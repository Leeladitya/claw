"""
middleware/opa_client.py — Stage 2: OPA Policy Evaluation Client

Communicates with the OPA REST API (sidecar) to evaluate browser
content against active Rego policies. The client constructs the
OPA input document from request metadata and PII scan results,
then interprets the policy decision.

OPA runs as a sidecar (Docker container or local binary) on port 8181.
Policies are loaded from the opa/policies/ directory via volume mount.

Decision flow:
  1. Build input document (metadata + PII scan + content features)
  2. POST to OPA's Data API: /v1/data/claw/main
  3. Parse response: allow/deny/allow_with_modifications
  4. Return structured decision for the pipeline
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from server.models import (
    PIIScanResult,
    PolicyDecision,
    PolicyResult,
)

log = logging.getLogger("claw.opa")

# ── Configuration ────────────────────────────────────────────────

DEFAULT_OPA_URL = "http://localhost:8181"
POLICY_PATH = "/v1/data/claw/main"
HEALTH_PATH = "/health"
TIMEOUT = 5.0  # seconds


# ── OPA Decision ─────────────────────────────────────────────────

@dataclass
class OPADecision:
    """Parsed result from an OPA policy evaluation."""
    decision: PolicyDecision = PolicyDecision.DENY
    matched_rules: list[str] = field(default_factory=list)
    modifications: list[str] = field(default_factory=list)
    reason: str = ""
    evaluation_ms: int = 0
    rules_evaluated: int = 0
    raw_response: dict = field(default_factory=dict)


# ── OPA Client ───────────────────────────────────────────────────

class OPAClient:
    """
    Async HTTP client for the OPA REST API.

    Usage:
        client = OPAClient()
        decision = await client.evaluate(input_doc)
    """

    def __init__(self, base_url: str = DEFAULT_OPA_URL):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=TIMEOUT,
        )

    async def close(self):
        await self._client.aclose()

    async def is_healthy(self) -> bool:
        """Check if OPA sidecar is reachable."""
        try:
            resp = await self._client.get(HEALTH_PATH)
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    async def evaluate(
        self,
        url: str,
        domain: str,
        title: str,
        pii_scan: PIIScanResult,
        content_features: dict,
        policy_pack: str = "standard",
    ) -> OPADecision:
        """
        Evaluate browser content against OPA policies.

        Constructs the input document and queries OPA's Data API.
        Returns a structured OPADecision.
        """
        # Build the OPA input document
        input_doc = {
            "input": {
                "url": url,
                "domain": domain,
                "title": title or "",
                "policy_pack": policy_pack,
                "pii_detected": {
                    "ssn": pii_scan.ssn,
                    "credit_card": pii_scan.credit_card,
                    "email": pii_scan.email,
                    "phone": pii_scan.phone,
                    "ip_address": pii_scan.ip_address,
                    "total": pii_scan.total,
                },
                "content_features": content_features,
            }
        }

        start = time.monotonic()

        try:
            resp = await self._client.post(POLICY_PATH, json=input_doc)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code != 200:
                log.error(f"OPA returned {resp.status_code}: {resp.text}")
                return OPADecision(
                    decision=PolicyDecision.DENY,
                    reason=f"OPA evaluation failed (HTTP {resp.status_code})",
                    evaluation_ms=elapsed_ms,
                )

            body = resp.json()
            result = body.get("result", {})

            return self._parse_decision(result, elapsed_ms)

        except httpx.ConnectError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            log.error("Cannot connect to OPA sidecar — is it running?")
            return OPADecision(
                decision=PolicyDecision.DENY,
                reason="OPA sidecar unreachable. Start it with: docker compose up opa",
                evaluation_ms=elapsed_ms,
            )
        except httpx.TimeoutException:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            log.error("OPA evaluation timed out")
            return OPADecision(
                decision=PolicyDecision.DENY,
                reason="OPA evaluation timed out",
                evaluation_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            log.error(f"OPA evaluation error: {e}")
            return OPADecision(
                decision=PolicyDecision.DENY,
                reason=f"OPA evaluation error: {str(e)}",
                evaluation_ms=elapsed_ms,
            )

    def _parse_decision(self, result: dict, elapsed_ms: int) -> OPADecision:
        """
        Parse the OPA result object into an OPADecision.

        Expected OPA result structure from our Rego policy:
        {
          "decision": "allow" | "allow_with_modifications" | "deny",
          "matched_rules": ["rule_name", ...],
          "modifications": ["description", ...],
          "reason": "human-readable explanation",
          "rules_evaluated": 12
        }
        """
        decision_str = result.get("decision", "deny")
        try:
            decision = PolicyDecision(decision_str)
        except ValueError:
            decision = PolicyDecision.DENY

        return OPADecision(
            decision=decision,
            matched_rules=result.get("matched_rules", []),
            modifications=result.get("modifications", []),
            reason=result.get("reason", ""),
            rules_evaluated=result.get("rules_evaluated", 0),
            evaluation_ms=elapsed_ms,
            raw_response=result,
        )

    def decision_to_policy_result(
        self,
        opa_decision: OPADecision,
        pack_name: str,
    ) -> PolicyResult:
        """Convert an OPADecision into the API's PolicyResult schema."""
        return PolicyResult(
            pack=pack_name,
            version="1.0.0",
            decision=opa_decision.decision,
            modifications_applied=opa_decision.modifications,
            rules_evaluated=opa_decision.rules_evaluated,
            matched_rules=opa_decision.matched_rules,
            evaluation_ms=opa_decision.evaluation_ms,
            reason=opa_decision.reason,
        )
