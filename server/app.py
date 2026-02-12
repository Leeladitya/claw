"""
Claw v0.2.0 — Governance-First Browser Context API

6-Stage Pipeline:
  1. PII Scan          → Detect and classify sensitive data
  2. OPA Policy Gate   → Evaluate against active Rego policies
  3. Knowledge Lookup  → Retrieve contextual memory for domain
  4. Argumentation     → Resolve conflicts via Dung's semantics
  5. Context Assembly  → Build sanitized payload with knowledge context
  6. Model Inference   → Claude analysis with Risk Auditor prompt

New in v0.2.0:
  - Knowledge Hub (persistent contextual memory)
  - Argumentation Engine (ASPARTIX-inspired conflict resolution)
  - API key authentication (P0 audit fix)
  - Rate limiting (P0 audit fix)
  - CORS restriction (P0 audit fix)
  - Input size validation (P0 audit fix)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import anthropic
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .middleware.pii_scanner import scan_pii
from .middleware.opa_client import OPAClient
from .middleware.auth import APIKeyAuth
from .middleware.rate_limiter import RateLimiter
from .knowledge import KnowledgeHub, KnowledgeQuery, Disposition, EntryType
from .argumentation import (
    ArgumentationEngine, RegoBridge, Semantics,
)
from .utils.audit import AuditLogger

# ── Configuration ───────────────────────────────────────────────

LOG_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("claw")

MAX_INPUT_CHARS = int(os.environ.get("CLAW_MAX_INPUT_CHARS", "60000"))
CLAW_MODEL = os.environ.get("CLAW_MODEL", "claude-sonnet-4-5-20250514")
DEFAULT_POLICY_PACK = os.environ.get("CLAW_POLICY_PACK", "standard")
OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
KNOWLEDGE_PATH = os.environ.get("CLAW_KNOWLEDGE_PATH", "data/knowledge.jsonl")
AUDIT_PATH = os.environ.get("CLAW_AUDIT_PATH", "data/audit.jsonl")

# CORS — configurable, NOT wildcard (P0 audit fix)
ALLOWED_ORIGINS = os.environ.get(
    "CLAW_CORS_ORIGINS",
    "http://localhost:8787,moz-extension://*,chrome-extension://*"
).split(",")

# ── Global Instances ────────────────────────────────────────────

opa_client: OPAClient
knowledge_hub: KnowledgeHub
argumentation_engine: ArgumentationEngine
rego_bridge: RegoBridge
audit_logger: AuditLogger
claude_client: anthropic.Anthropic | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global opa_client, knowledge_hub, argumentation_engine
    global rego_bridge, audit_logger, claude_client

    opa_client = OPAClient(OPA_URL)
    knowledge_hub = KnowledgeHub(storage_path=KNOWLEDGE_PATH)
    argumentation_engine = ArgumentationEngine()
    rego_bridge = RegoBridge()
    audit_logger = AuditLogger(path=AUDIT_PATH)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        claude_client = anthropic.Anthropic(api_key=api_key)
        logger.info(f"Claude client initialized (model={CLAW_MODEL})")
    else:
        logger.warning("ANTHROPIC_API_KEY not set — model inference disabled")

    logger.info(
        f"Claw v0.2.0 started | OPA={OPA_URL} | "
        f"Knowledge={knowledge_hub.stats['total_entries']} entries | "
        f"Policy={DEFAULT_POLICY_PACK}"
    )

    yield

    await opa_client.close()
    logger.info("Claw shutdown complete")


# ── FastAPI App ─────────────────────────────────────────────────

app = FastAPI(
    title="Claw",
    version="0.2.0",
    description="Governance-First Browser Context API with Knowledge Hub & Argumentation Engine",
    lifespan=lifespan,
)

# Middleware stack (order matters: outermost first)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(RateLimiter, enabled=True)
app.add_middleware(APIKeyAuth)


# ── Request/Response Models ─────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str
    text: str
    title: str = ""
    policy_pack: str = DEFAULT_POLICY_PACK
    include_knowledge: bool = True
    argumentation_semantics: str = "grounded"

class AnalyzeResponse(BaseModel):
    request_id: str
    status: str
    policy: dict
    knowledge: dict = {}
    argumentation: dict = {}
    analysis: dict = {}
    audit: dict = {}

class PolicyDenialResponse(BaseModel):
    request_id: str
    status: str = "denied"
    policy: dict
    knowledge: dict = {}
    argumentation: dict = {}

class KnowledgeStoreRequest(BaseModel):
    domain: str
    entry_type: str = "user_annotation"
    disposition: str = "neutral"
    summary: str
    content: str = ""
    tags: list[str] = []

class KnowledgeQueryRequest(BaseModel):
    domain: str | None = None
    entry_type: str | None = None
    max_age_hours: float | None = None
    limit: int = 10


# ── Pipeline Functions ──────────────────────────────────────────

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return "unknown"


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


RISK_AUDITOR_PROMPT = """You are the Claw Risk Auditor. Analyze the provided web content
and return a JSON object with exactly these fields:
{
  "summary": ["bullet1", "bullet2", "bullet3"],
  "risk_score": <0-10 integer>,
  "risk_rationale": "<one sentence>",
  "safety_flags": [{"severity": "ok|warning|danger", "message": "..."}]
}

Context from Knowledge Hub (if available):
{knowledge_context}

Respond with ONLY the JSON object. No markdown, no explanation."""


async def run_pipeline(req: AnalyzeRequest) -> dict:
    """
    Execute the 6-stage governance pipeline.

    Returns a dict suitable for AnalyzeResponse or PolicyDenialResponse.
    """
    request_id = f"clw_{uuid.uuid4().hex[:10]}"
    domain = extract_domain(req.url)
    start_time = time.perf_counter()

    # ── Stage 1: PII Scan ────────────────────────────────────
    pii_result = scan_pii(req.text)
    logger.info(f"[{request_id}] Stage 1 PII: {pii_result.counts}")

    # ── Stage 2: OPA Policy Gate ─────────────────────────────
    opa_decision = await opa_client.evaluate(
        domain=domain,
        pii_counts=pii_result.counts,
        classification_signals=pii_result.classification_signals,
        policy_pack=req.policy_pack,
        content_features={
            "word_count": len(req.text.split()),
            "has_title": bool(req.title),
            "sensitive_keywords": pii_result.sensitive_keywords,
        },
    )
    logger.info(
        f"[{request_id}] Stage 2 OPA: decision={opa_decision.decision} "
        f"rules={opa_decision.matched_rules} ({opa_decision.evaluation_time_ms}ms)"
    )

    # ── Stage 3: Knowledge Hub Lookup ────────────────────────
    knowledge_context = {}
    knowledge_entries = []
    if req.include_knowledge:
        knowledge_entries = knowledge_hub.query(
            KnowledgeQuery(domain=domain, limit=5, policy_pack=req.policy_pack)
        )
        domain_rep = knowledge_hub.get_domain_reputation(domain)
        knowledge_context = {
            "domain_reputation": domain_rep,
            "relevant_entries": len(knowledge_entries),
            "entries": knowledge_entries[:3],  # Top 3 for response
        }
        logger.info(
            f"[{request_id}] Stage 3 Knowledge: "
            f"reputation={domain_rep['reputation']} entries={len(knowledge_entries)}"
        )

    # ── Stage 4: Argumentation Resolution ────────────────────
    af = rego_bridge.build_framework(
        opa_decision=opa_decision.to_dict(),
        knowledge_entries=knowledge_entries,
        pii_result=pii_result.to_dict(),
        request_context={"domain": domain, "policy_pack": req.policy_pack},
    )

    semantics_map = {
        "grounded": Semantics.GROUNDED,
        "preferred": Semantics.PREFERRED,
        "stable": Semantics.STABLE,
    }
    sem = semantics_map.get(req.argumentation_semantics, Semantics.GROUNDED)
    resolution = argumentation_engine.resolve(af, semantics=sem)

    logger.info(
        f"[{request_id}] Stage 4 Argumentation: "
        f"decision={resolution.decision} "
        f"winning={len(resolution.winning_arguments)} "
        f"defeated={len(resolution.defeated_arguments)} "
        f"({resolution.resolution_time_ms}ms)"
    )

    # Use argumentation result as final decision
    final_decision = resolution.decision

    policy_info = {
        "pack": req.policy_pack,
        "opa_decision": opa_decision.decision,
        "final_decision": final_decision,
        "deny_reasons": opa_decision.deny_reasons,
        "modifications_applied": opa_decision.modification_list,
        "matched_rules": opa_decision.matched_rules,
        "rules_evaluated": len(opa_decision.matched_rules),
        "evaluation_ms": opa_decision.evaluation_time_ms,
    }

    argumentation_info = {
        "semantics": resolution.semantics_used.value,
        "winning_arguments": resolution.winning_arguments,
        "defeated_arguments": resolution.defeated_arguments,
        "explanation": resolution.explanation,
        "resolution_ms": resolution.resolution_time_ms,
        "framework": {
            "num_arguments": len(af.arguments),
            "num_attacks": len(af.attacks),
        },
    }

    # ── Store decision as knowledge ──────────────────────────
    knowledge_hub.store_policy_decision(
        domain=domain,
        decision=final_decision,
        matched_rules=opa_decision.matched_rules,
        policy_pack=req.policy_pack,
        pii_counts=pii_result.counts,
    )

    # ── DENY path ────────────────────────────────────────────
    if final_decision == "deny":
        audit_logger.log(
            request_id=request_id, domain=domain, decision="deny",
            policy_pack=req.policy_pack,
            matched_rules=opa_decision.matched_rules,
            deny_reasons=opa_decision.deny_reasons,
            content_hash=content_hash(req.text),
            argumentation=argumentation_info,
        )
        return {
            "request_id": request_id, "status": "denied",
            "policy": policy_info,
            "knowledge": knowledge_context,
            "argumentation": argumentation_info,
        }

    # ── Stage 5: Context Assembly ────────────────────────────
    text_for_model = pii_result.masked_text if pii_result.has_any_pii else req.text
    if len(text_for_model) > MAX_INPUT_CHARS:
        text_for_model = text_for_model[:MAX_INPUT_CHARS] + "\n\n[TRUNCATED]"

    # Build knowledge context string for the prompt
    kh_context_str = "No prior knowledge for this domain."
    if knowledge_entries:
        kh_lines = [f"- {e['summary']} (relevance: {e['relevance_score']:.2f})"
                     for e in knowledge_entries[:3]]
        kh_context_str = "\n".join(kh_lines)

    c_hash = content_hash(text_for_model)

    # ── Stage 6: Model Inference ─────────────────────────────
    analysis = {}
    tokens_in = tokens_out = 0

    if claude_client:
        try:
            system_prompt = RISK_AUDITOR_PROMPT.replace(
                "{knowledge_context}", kh_context_str
            )
            user_content = f"URL: {req.url}\nTitle: {req.title}\n\n{text_for_model}"

            response = claude_client.messages.create(
                model=CLAW_MODEL,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
            )

            tokens_in = response.usage.input_tokens
            tokens_out = response.usage.output_tokens
            raw = response.content[0].text.strip()

            # Parse JSON response
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[-1] if "\n" in raw else raw[3:]
            if raw.endswith("```"):
                raw = raw[:-3]
            raw = raw.strip()

            analysis = json.loads(raw)

        except json.JSONDecodeError:
            logger.warning(f"[{request_id}] Claude returned non-JSON")
            analysis = {
                "summary": ["Analysis completed but response format was unexpected."],
                "risk_score": 5,
                "risk_rationale": "Unable to parse structured response",
                "safety_flags": [{"severity": "warning", "message": "Parse error"}],
            }
        except anthropic.APIError as e:
            logger.error(f"[{request_id}] Claude API error: {e}")
            raise HTTPException(status_code=502, detail=f"Model API error: {e.message}")
    else:
        analysis = {
            "summary": ["Model inference disabled (no API key configured)."],
            "risk_score": 0,
            "risk_rationale": "No model available",
            "safety_flags": [],
        }

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)

    audit_logger.log(
        request_id=request_id, domain=domain,
        decision=final_decision, policy_pack=req.policy_pack,
        matched_rules=opa_decision.matched_rules,
        modifications=opa_decision.modification_list,
        content_hash=c_hash, model=CLAW_MODEL,
        tokens_in=tokens_in, tokens_out=tokens_out,
        latency_ms=elapsed_ms,
        argumentation_semantics=resolution.semantics_used.value,
        knowledge_entries_used=len(knowledge_entries),
    )

    return {
        "request_id": request_id,
        "status": "analyzed",
        "policy": policy_info,
        "knowledge": knowledge_context,
        "argumentation": argumentation_info,
        "analysis": analysis,
        "audit": {
            "content_hash": c_hash,
            "model": CLAW_MODEL,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "latency_ms": elapsed_ms,
        },
    }


# ── API Endpoints ───────────────────────────────────────────────

@app.post("/v1/analyze")
async def analyze(req: AnalyzeRequest):
    """Submit browser content for 6-stage governance pipeline analysis."""
    if len(req.text) > MAX_INPUT_CHARS * 2:
        raise HTTPException(status_code=413, detail="Content too large")
    if not req.text.strip():
        raise HTTPException(status_code=422, detail="Empty content")

    result = await run_pipeline(req)

    if result["status"] == "denied":
        return JSONResponse(status_code=403, content=result)
    return result


@app.post("/v1/policy/evaluate")
async def policy_evaluate(req: AnalyzeRequest):
    """Dry-run: policy + knowledge + argumentation, no model call (zero cost)."""
    if not req.text.strip():
        raise HTTPException(status_code=422, detail="Empty content")

    domain = extract_domain(req.url)
    pii_result = scan_pii(req.text)

    opa_decision = await opa_client.evaluate(
        domain=domain, pii_counts=pii_result.counts,
        classification_signals=pii_result.classification_signals,
        policy_pack=req.policy_pack,
    )

    knowledge_entries = knowledge_hub.query(
        KnowledgeQuery(domain=domain, limit=5, policy_pack=req.policy_pack)
    ) if req.include_knowledge else []

    af = rego_bridge.build_framework(
        opa_decision=opa_decision.to_dict(),
        knowledge_entries=knowledge_entries,
        pii_result=pii_result.to_dict(),
    )
    resolution = argumentation_engine.resolve(af)

    return {
        "domain": domain,
        "pii": pii_result.to_dict(),
        "opa": opa_decision.to_dict(),
        "knowledge": {
            "domain_reputation": knowledge_hub.get_domain_reputation(domain),
            "entries_found": len(knowledge_entries),
        },
        "argumentation": {
            "final_decision": resolution.decision,
            "semantics": resolution.semantics_used.value,
            "winning": resolution.winning_arguments,
            "defeated": resolution.defeated_arguments,
            "explanation": resolution.explanation,
            "framework": af.to_dict(),
        },
    }


@app.get("/v1/policy/packs")
async def list_policy_packs():
    """List available policy packs."""
    return {
        "packs": [
            {"name": "standard", "description": "General browsing governance"},
            {"name": "finance", "description": "Financial services compliance"},
            {"name": "strict", "description": "Government/defense — explicit allowlist"},
            {"name": "research", "description": "Security research — log only, allow all"},
        ],
        "active": DEFAULT_POLICY_PACK,
    }


# ── Knowledge Hub Endpoints ─────────────────────────────────────

@app.post("/v1/knowledge/store")
async def knowledge_store(req: KnowledgeStoreRequest):
    """Store a knowledge entry manually."""
    from .knowledge.models import KnowledgeEntry as KE
    entry = KE(
        id="", domain=req.domain,
        entry_type=EntryType(req.entry_type),
        disposition=Disposition(req.disposition),
        summary=req.summary, content=req.content, tags=req.tags,
    )
    stored = knowledge_hub.store(entry)
    return {"stored": stored.to_dict()}


@app.post("/v1/knowledge/query")
async def knowledge_query(req: KnowledgeQueryRequest):
    """Query the Knowledge Hub."""
    q = KnowledgeQuery(
        domain=req.domain,
        entry_type=EntryType(req.entry_type) if req.entry_type else None,
        max_age_hours=req.max_age_hours,
        limit=req.limit,
    )
    entries = knowledge_hub.query(q)
    return {"entries": entries, "total": len(entries)}


@app.get("/v1/knowledge/reputation/{domain}")
async def knowledge_reputation(domain: str):
    """Get domain reputation from Knowledge Hub."""
    return knowledge_hub.get_domain_reputation(domain)


@app.get("/v1/knowledge/stats")
async def knowledge_stats():
    """Knowledge Hub statistics."""
    return knowledge_hub.stats


# ── Audit Endpoints ─────────────────────────────────────────────

@app.get("/v1/audit/decisions")
async def audit_decisions(limit: int = 50, decision: str | None = None):
    """Query the audit trail."""
    return {"decisions": audit_logger.query(limit=limit, decision=decision)}


# ── Health ──────────────────────────────────────────────────────

@app.get("/v1/health")
async def health():
    opa_status = await opa_client.health_check()
    return {
        "status": "healthy",
        "version": "0.2.0",
        "components": {
            "opa": opa_status,
            "claude": {"status": "configured" if claude_client else "not_configured"},
            "knowledge_hub": knowledge_hub.stats,
            "argumentation_engine": {"status": "active", "semantics": ["grounded", "preferred", "stable"]},
        },
    }
