"""OPA Client — Async HTTP client for Open Policy Agent."""
from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
import httpx

logger = logging.getLogger("claw.opa")

@dataclass
class OPADecision:
    decision: str = "allow"
    deny_reasons: list[str] = field(default_factory=list)
    modification_list: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    evaluation_time_ms: float = 0.0
    raw_result: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision, "deny_reasons": self.deny_reasons,
            "modification_list": self.modification_list,
            "matched_rules": self.matched_rules,
            "evaluation_time_ms": self.evaluation_time_ms,
        }

class OPAClient:
    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=5.0)

    async def evaluate(self, domain: str, pii_counts: dict,
                       classification_signals: list[str],
                       policy_pack: str = "standard",
                       content_features: dict | None = None) -> OPADecision:
        start = time.perf_counter()
        opa_input = {"input": {
            "domain": domain, "policy_pack": policy_pack,
            "pii_detected": pii_counts,
            "classification_signals": classification_signals,
            "content_features": content_features or {},
        }}
        try:
            resp = await self._client.post(
                f"{self.opa_url}/v1/data/claw/main", json=opa_input)
            elapsed = (time.perf_counter() - start) * 1000
            if resp.status_code != 200:
                logger.error(f"OPA returned {resp.status_code}")
                return OPADecision(decision="allow",
                    matched_rules=["opa_unavailable_fallback"],
                    evaluation_time_ms=elapsed)
            result = resp.json().get("result", {})
            decision = result.get("decision", "allow")
            deny_reasons = result.get("deny_reasons", [])
            modification_list = result.get("modification_list", [])
            matched_rules = result.get("matched_rules", [])
            if deny_reasons and decision != "deny":
                decision = "deny"
            elif modification_list and decision == "allow":
                decision = "allow_with_modifications"
            return OPADecision(decision=decision, deny_reasons=deny_reasons,
                modification_list=modification_list, matched_rules=matched_rules,
                evaluation_time_ms=round(elapsed, 3), raw_result=result)
        except httpx.ConnectError:
            elapsed = (time.perf_counter() - start) * 1000
            logger.warning("OPA unreachable — fallback to allow")
            return OPADecision(decision="allow",
                matched_rules=["opa_unreachable_fallback"],
                evaluation_time_ms=elapsed)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"OPA error: {e}")
            return OPADecision(decision="allow",
                matched_rules=["opa_error_fallback"], evaluation_time_ms=elapsed)

    async def health_check(self) -> dict:
        try:
            resp = await self._client.get(f"{self.opa_url}/health")
            return {"status": "healthy" if resp.status_code == 200 else "unhealthy"}
        except Exception:
            return {"status": "unreachable"}

    async def close(self):
        await self._client.aclose()
