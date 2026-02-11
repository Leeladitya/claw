"""
server.py — Claw: Governance-First Browser Context API

The 4-Stage Pipeline:
  Stage 1: Pre-Processing  — PII scan & content feature extraction
  Stage 2: Policy Gate     — OPA evaluation against active Rego policies
  Stage 3: Context Assembly — Apply modifications, hash, build MCP payload
  Stage 4: Model Inference  — Claude risk-aware analysis

Architecture:
  Firefox Extension ──POST──▶ Claw Gateway ──▶ OPA Sidecar (:8181)
                                    │
                                    ├── if ALLOW ──▶ Claude API ──▶ Response
                                    └── if DENY  ──▶ 403 + Reason

Usage:
  export ANTHROPIC_API_KEY="sk-ant-..."
  docker compose up          # starts OPA + Claw
  # or: python -m server.app  (if OPA is already running)
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager

import anthropic
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from server.middleware.opa_client import OPAClient
from server.middleware.pii_scanner import scan_pii, mask_text
from server.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    AuditMetadata,
    HealthComponent,
    HealthResponse,
    PIIScanResult,
    PolicyDecision,
    PolicyDenialResponse,
    PolicyEvaluationResponse,
    PolicyPackInfo,
    PolicyPackName,
    PolicyResult,
    RiskAnalysis,
    SafetyFlag,
    Severity,
    compute_content_hash,
)
from server.utils.audit import log_decision, get_recent_decisions

# ── Logging ──────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-14s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("claw.server")

# ── Configuration ────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = os.environ.get("CLAW_MODEL", "claude-sonnet-4-5-20250514")
OPA_URL = os.environ.get("CLAW_OPA_URL", "http://localhost:8181")
ACTIVE_POLICY_PACK = os.environ.get("CLAW_POLICY_PACK", "standard")
MAX_INPUT_CHARS = 60_000
SERVER_START_TIME = time.time()

# ── Clients ──────────────────────────────────────────────────────

opa_client = OPAClient(base_url=OPA_URL)
claude_client: anthropic.Anthropic | None = None

if ANTHROPIC_API_KEY:
    claude_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
else:
    log.warning("ANTHROPIC_API_KEY not set — Claude analysis will be unavailable")


# ── Claude System Prompt ─────────────────────────────────────────

RISK_AUDITOR_PROMPT = """\
You are a Risk-Aware Content Auditor. You receive webpage content that has
already passed through a security policy gate. PII has been redacted.
Produce a structured analysis. Return ONLY valid JSON — no markdown fences.

Output schema:
{
  "summary": ["Bullet 1", "Bullet 2", "Bullet 3"],
  "risk_score": <integer 0-10>,
  "risk_rationale": "<1-2 sentence explanation>",
  "safety_flags": [
    {"severity": "ok"|"warning"|"danger", "message": "<finding>"}
  ]
}

Scoring rubric:
  0-2: Factual, well-sourced, neutral.
  3-4: Minor editorialization, largely balanced.
  5-6: Notable bias, emotional language, or missing context.
  7-8: Significant sensationalism or misleading framing.
  9-10: Extreme propaganda or disinformation.

Always include at least one safety flag. Be calibrated.
"""


# ── Policy Pack Registry ─────────────────────────────────────────

POLICY_PACKS: dict[str, PolicyPackInfo] = {
    "standard": PolicyPackInfo(
        name="standard",
        version="1.0.0",
        description="Public domains only. Masks emails and phones. No content gate. For personal browsing and general research.",
    ),
    "finance": PolicyPackInfo(
        name="finance",
        version="1.0.0",
        description="Allowlisted + internal domains. Full PII redaction, blocks SSN/CC. Blocks confidential-tagged content. For financial services compliance.",
    ),
    "strict": PolicyPackInfo(
        name="strict",
        version="1.0.0",
        description="Explicit allowlist only. Blocks all PII categories. Requires classification below secret. For defense, government, and healthcare.",
    ),
    "research": PolicyPackInfo(
        name="research",
        version="1.0.0",
        description="All domains with logging. Detects PII but passes through. Warns but allows. For security research and testing.",
    ),
}


# ── App Lifecycle ────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    log.info("=" * 60)
    log.info("  🦞 Claw — Governance-First Browser Context API")
    log.info(f"  Model:       {MODEL}")
    log.info(f"  OPA:         {OPA_URL}")
    log.info(f"  Policy Pack: {ACTIVE_POLICY_PACK}")
    log.info(f"  API Key:     {'configured' if ANTHROPIC_API_KEY else 'NOT SET'}")
    log.info("=" * 60)

    opa_healthy = await opa_client.is_healthy()
    if opa_healthy:
        log.info("OPA sidecar: connected")
    else:
        log.warning("OPA sidecar: NOT REACHABLE — run 'docker compose up opa'")

    yield

    # Shutdown
    await opa_client.close()
    log.info("Claw server stopped.")


# ── FastAPI App ──────────────────────────────────────────────────

app = FastAPI(
    title="Claw API",
    description="Governance-first browser context API. Policy-gated, risk-scored, audit-trailed.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ═════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ═════════════════════════════════════════════════════════════════


# ── Health ───────────────────────────────────────────────────────

@app.get("/v1/health", response_model=HealthResponse, tags=["System"])
async def health():
    opa_healthy = await opa_client.is_healthy()
    claude_ok = claude_client is not None

    components = {
        "opa": HealthComponent(
            status="ok" if opa_healthy else "error",
            detail=f"connected at {OPA_URL}" if opa_healthy else "unreachable",
        ),
        "claude": HealthComponent(
            status="ok" if claude_ok else "error",
            detail=f"model: {MODEL}" if claude_ok else "ANTHROPIC_API_KEY not set",
        ),
        "audit": HealthComponent(status="ok", detail="logging to audit.jsonl"),
    }

    overall = "ok" if (opa_healthy and claude_ok) else "degraded"

    return HealthResponse(
        status=overall,
        version="1.0.0",
        uptime_seconds=int(time.time() - SERVER_START_TIME),
        components=components,
    )


# ── Analyze (The Main Pipeline) ─────────────────────────────────

@app.post("/v1/analyze", tags=["Context"])
async def analyze(req: AnalyzeRequest):
    """
    The 4-Stage Pipeline:
      1. Pre-process: PII scan + feature extraction
      2. Policy gate: OPA evaluation
      3. Context assembly: Apply modifications, hash
      4. Model inference: Claude risk analysis
    """
    request_start = time.monotonic()
    pack_name = req.options.policy_pack.value if req.options and req.options.policy_pack else ACTIVE_POLICY_PACK

    # ── Stage 1: Pre-Processing ──────────────────────────────
    log.info(f"Stage 1 | PII scan for {req.domain} ({len(req.text)} chars)")
    pii_result = scan_pii(req.text)

    content_features = {
        "word_count": len(req.text.split()),
        "char_count": len(req.text),
        "sensitive_keywords": pii_result.sensitive_keywords,
        "classification_signals": pii_result.classification_signals,
    }

    # ── Stage 2: OPA Policy Evaluation ───────────────────────
    log.info(f"Stage 2 | OPA evaluation (pack: {pack_name})")
    opa_decision = await opa_client.evaluate(
        url=req.url,
        domain=req.domain,
        title=req.title or "",
        pii_scan=pii_result.pii,
        content_features=content_features,
        policy_pack=pack_name,
    )

    policy_result = opa_client.decision_to_policy_result(opa_decision, pack_name)
    response_base = AnalyzeResponse(policy=policy_result, pii_scan=pii_result.pii)

    # ── DENY: Block and return ───────────────────────────────
    if opa_decision.decision == PolicyDecision.DENY:
        log.warning(f"Stage 2 | DENIED: {opa_decision.reason}")

        log_decision(
            request_id=response_base.request_id,
            domain=req.domain,
            decision="deny",
            policy_pack=pack_name,
            rules_evaluated=opa_decision.rules_evaluated,
            matched_rules=opa_decision.matched_rules,
            reason=opa_decision.reason,
        )

        return JSONResponse(
            status_code=403,
            content=PolicyDenialResponse(
                request_id=response_base.request_id,
                policy=policy_result,
                reason=opa_decision.reason,
                matched_rules=opa_decision.matched_rules,
            ).model_dump(),
        )

    # ── Stage 3: Context Assembly ────────────────────────────
    log.info(f"Stage 3 | Context assembly (decision: {opa_decision.decision.value})")

    # Apply PII masking if policy requires modifications
    if opa_decision.decision == PolicyDecision.ALLOW_WITH_MODIFICATIONS:
        analysis_text, mods = mask_text(req.text, list(opa_decision.modifications))
        policy_result.modifications_applied = mods
    else:
        analysis_text = req.text

    # Truncate for model
    words = analysis_text.split()
    if len(words) > 12000:
        analysis_text = " ".join(words[:12000]) + "\n\n[... content truncated]"

    content_hash = compute_content_hash(analysis_text)

    # ── Stage 4: Model Inference ─────────────────────────────
    if not claude_client:
        log.warning("Stage 4 | Skipped — no API key configured")
        analysis = RiskAnalysis(
            summary=["Claude API key not configured. Set ANTHROPIC_API_KEY to enable analysis."],
            risk_score=0,
            risk_rationale="Analysis unavailable — API key not set.",
            safety_flags=[SafetyFlag(severity=Severity.WARNING, message="Model inference skipped.")],
        )
        audit = AuditMetadata(content_hash=content_hash, model="none")
    else:
        log.info(f"Stage 4 | Claude inference ({MODEL})")
        inference_start = time.monotonic()

        try:
            user_prompt = (
                f"Analyze the following webpage content.\n\n"
                f"URL: {req.url}\n"
                f"Title: {req.title or 'Unknown'}\n\n"
                f"--- BEGIN CONTENT ---\n"
                f"{analysis_text[:MAX_INPUT_CHARS]}\n"
                f"--- END CONTENT ---"
            )

            response = claude_client.messages.create(
                model=MODEL,
                max_tokens=1024,
                system=RISK_AUDITOR_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            inference_ms = int((time.monotonic() - inference_start) * 1000)

            raw = response.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()

            parsed = json.loads(raw)
            analysis = RiskAnalysis(
                summary=parsed.get("summary", []),
                risk_score=parsed.get("risk_score", 0),
                risk_rationale=parsed.get("risk_rationale", ""),
                safety_flags=[
                    SafetyFlag(**f) for f in parsed.get("safety_flags", [])
                ],
            )

            audit = AuditMetadata(
                content_hash=content_hash,
                model=MODEL,
                tokens_in=response.usage.input_tokens,
                tokens_out=response.usage.output_tokens,
                latency_ms=inference_ms,
            )

        except json.JSONDecodeError:
            log.error("Claude returned invalid JSON")
            analysis = RiskAnalysis(
                summary=["Analysis completed but response parsing failed."],
                risk_score=-1,
                risk_rationale="Model output was not valid JSON.",
                safety_flags=[SafetyFlag(severity=Severity.WARNING, message="Output parse error.")],
            )
            audit = AuditMetadata(content_hash=content_hash, model=MODEL)

        except anthropic.APIError as e:
            log.error(f"Claude API error: {e}")
            raise HTTPException(status_code=502, detail=f"Claude API error: {e.message}")

    # ── Audit Log ────────────────────────────────────────────
    total_ms = int((time.monotonic() - request_start) * 1000)
    log.info(f"Complete | {req.domain} | {opa_decision.decision.value} | {total_ms}ms total")

    log_decision(
        request_id=response_base.request_id,
        domain=req.domain,
        decision=opa_decision.decision.value,
        policy_pack=pack_name,
        rules_evaluated=opa_decision.rules_evaluated,
        matched_rules=opa_decision.matched_rules,
        modifications=policy_result.modifications_applied,
        content_hash=content_hash,
        model=MODEL,
    )

    # ── Response ─────────────────────────────────────────────
    response_base.status = "analyzed"
    response_base.analysis = analysis
    response_base.audit = audit

    return response_base


# ── Policy Dry Run ───────────────────────────────────────────────

@app.post("/v1/policy/evaluate", response_model=PolicyEvaluationResponse, tags=["Policy"])
async def evaluate_policy(req: AnalyzeRequest):
    """
    Dry-run policy evaluation — no model inference, no API cost.
    Test content against the active policy without calling Claude.
    """
    pack_name = req.options.policy_pack.value if req.options and req.options.policy_pack else ACTIVE_POLICY_PACK

    pii_result = scan_pii(req.text)
    content_features = {
        "word_count": len(req.text.split()),
        "char_count": len(req.text),
        "sensitive_keywords": pii_result.sensitive_keywords,
        "classification_signals": pii_result.classification_signals,
    }

    opa_decision = await opa_client.evaluate(
        url=req.url,
        domain=req.domain,
        title=req.title or "",
        pii_scan=pii_result.pii,
        content_features=content_features,
        policy_pack=pack_name,
    )

    return PolicyEvaluationResponse(
        decision=opa_decision.decision,
        rules_matched=[
            {"rule": r, "module": "claw.main", "result": "matched"}
            for r in opa_decision.matched_rules
        ],
        modifications=opa_decision.modifications,
        pii_scan=pii_result.pii,
        evaluation_ms=opa_decision.evaluation_ms,
    )


# ── Policy Pack Management ───────────────────────────────────────

@app.get("/v1/policy/packs", tags=["Policy"])
async def list_packs():
    packs = []
    for name, info in POLICY_PACKS.items():
        pack = info.model_copy()
        pack.is_active = (name == ACTIVE_POLICY_PACK)
        packs.append(pack)
    return {"packs": packs}


@app.get("/v1/policy/active", tags=["Policy"])
async def get_active_pack():
    info = POLICY_PACKS.get(ACTIVE_POLICY_PACK)
    if info:
        pack = info.model_copy()
        pack.is_active = True
        return pack
    raise HTTPException(status_code=404, detail="Active pack not found")


# ── Audit Log ────────────────────────────────────────────────────

@app.get("/v1/audit/decisions", tags=["Audit"])
async def list_audit_decisions(limit: int = 50):
    decisions = get_recent_decisions(limit=min(limit, 200))
    return {"decisions": decisions, "total": len(decisions)}


# ── Entrypoint ───────────────────────────────────────────────────

def main():
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=8787,
        log_level="info",
        reload=False,
    )


if __name__ == "__main__":
    main()
