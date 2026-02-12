"""
Rego-to-Argumentation Bridge

Converts OPA policy evaluation results and Knowledge Hub context
into Dung's Abstract Argumentation Framework for conflict resolution.

This is the key integration point between:
- OPA's declarative ABAC decisions (Rego)
- Knowledge Hub's contextual memory
- ASPARTIX-inspired argumentation semantics

The bridge creates arguments from:
1. OPA deny rules → "deny" arguments
2. OPA modification rules → "modify" arguments
3. Knowledge Hub entries → "contextual" arguments
4. Default allow → "baseline" argument

Attack relations are derived from:
- Contradictory decisions (deny attacks allow)
- Specificity (domain-specific attacks general)
- Recency (newer knowledge attacks older)
- Strength (higher-confidence attacks lower)
"""

from __future__ import annotations

import logging

from .models import (
    Argument,
    ArgumentSource,
    ArgumentationFramework,
    AttackType,
)

logger = logging.getLogger("claw.argumentation.bridge")


class RegoBridge:
    """
    Constructs argumentation frameworks from OPA decisions
    and Knowledge Hub context.
    """

    def build_framework(
        self,
        opa_decision: dict,
        knowledge_entries: list[dict] | None = None,
        pii_result: dict | None = None,
        request_context: dict | None = None,
    ) -> ArgumentationFramework:
        """
        Build a complete AF from all pipeline inputs.

        Args:
            opa_decision: Raw OPA result with deny_reasons, modifications, etc.
            knowledge_entries: Relevant entries from Knowledge Hub
            pii_result: PII scan results
            request_context: URL, domain, policy_pack, etc.

        Returns:
            ArgumentationFramework ready for extension computation
        """
        af = ArgumentationFramework()

        # ── Baseline: default allow ──────────────────────────────
        baseline = Argument(
            id="baseline_allow",
            claim="Content should be allowed for analysis",
            source=ArgumentSource.OPA_POLICY,
            strength=0.3,
            metadata={"decision": "allow"},
        )
        af.add_argument(baseline)

        # ── OPA deny arguments ───────────────────────────────────
        deny_reasons = opa_decision.get("deny_reasons", [])
        for i, reason in enumerate(deny_reasons):
            arg = Argument(
                id=f"opa_deny_{i}",
                claim=reason,
                source=ArgumentSource.OPA_POLICY,
                strength=0.9,
                metadata={"decision": "deny", "rule": reason},
            )
            af.add_argument(arg)
            # Deny attacks baseline allow
            af.add_attack(
                arg.id, "baseline_allow",
                AttackType.REBUT,
                f"Policy denies: {reason}",
            )

        # ── OPA modification arguments ───────────────────────────
        modifications = opa_decision.get("modification_list", [])
        for i, mod in enumerate(modifications):
            mod_type = mod if isinstance(mod, str) else mod.get("type", str(mod))
            arg = Argument(
                id=f"opa_modify_{i}",
                claim=f"Content requires modification: {mod_type}",
                source=ArgumentSource.OPA_POLICY,
                strength=0.7,
                metadata={
                    "decision": "allow_with_modifications",
                    "modification": mod_type,
                },
            )
            af.add_argument(arg)
            # Modifications attack baseline (replace with modified allow)
            af.add_attack(
                arg.id, "baseline_allow",
                AttackType.UNDERCUT,
                f"Modification required: {mod_type}",
            )

        # ── PII-derived arguments ────────────────────────────────
        if pii_result:
            total_pii = sum(
                pii_result.get("counts", {}).get(t, 0)
                for t in ["ssn", "credit_card", "email", "phone", "ip_address"]
            )
            if total_pii > 0:
                has_critical = (
                    pii_result.get("counts", {}).get("ssn", 0) > 0 or
                    pii_result.get("counts", {}).get("credit_card", 0) > 0
                )
                if has_critical:
                    arg = Argument(
                        id="pii_critical",
                        claim="Critical PII detected (SSN/CC) — deny or heavy redaction required",
                        source=ArgumentSource.PII_SCANNER,
                        strength=0.95,
                        metadata={"decision": "deny"},
                    )
                    af.add_argument(arg)
                    af.add_attack(
                        arg.id, "baseline_allow",
                        AttackType.REBUT,
                        "Critical PII must not reach model",
                    )
                else:
                    arg = Argument(
                        id="pii_moderate",
                        claim=f"Non-critical PII detected ({total_pii} items) — masking required",
                        source=ArgumentSource.PII_SCANNER,
                        strength=0.6,
                        metadata={"decision": "allow_with_modifications"},
                    )
                    af.add_argument(arg)
                    af.add_attack(
                        arg.id, "baseline_allow",
                        AttackType.UNDERCUT,
                        "PII masking needed",
                    )

        # ── Knowledge Hub arguments ──────────────────────────────
        if knowledge_entries:
            for i, entry in enumerate(knowledge_entries):
                relevance = entry.get("relevance_score", 0.5)
                disposition = entry.get("disposition", "neutral")

                if disposition == "trusted":
                    arg = Argument(
                        id=f"knowledge_trust_{i}",
                        claim=f"Domain previously marked trusted: {entry.get('domain', 'unknown')}",
                        source=ArgumentSource.KNOWLEDGE_HUB,
                        strength=min(0.8, relevance),
                        metadata={
                            "decision": "allow",
                            "knowledge_id": entry.get("id", ""),
                        },
                    )
                    af.add_argument(arg)
                    # Trust arguments attack deny arguments (can override blocks)
                    for deny_id in [a.id for a in af.arguments.values()
                                    if a.metadata.get("decision") == "deny"
                                    and a.source == ArgumentSource.DOMAIN_RULE]:
                        af.add_attack(
                            arg.id, deny_id,
                            AttackType.UNDERMINE,
                            "Historical trust overrides domain block",
                        )

                elif disposition == "suspicious":
                    arg = Argument(
                        id=f"knowledge_suspect_{i}",
                        claim=f"Domain previously flagged suspicious: {entry.get('domain', 'unknown')}",
                        source=ArgumentSource.KNOWLEDGE_HUB,
                        strength=min(0.85, relevance),
                        metadata={"decision": "deny"},
                    )
                    af.add_argument(arg)
                    af.add_attack(
                        arg.id, "baseline_allow",
                        AttackType.REBUT,
                        "Historical suspicion record",
                    )

                elif disposition == "contextual":
                    arg = Argument(
                        id=f"knowledge_ctx_{i}",
                        claim=entry.get("summary", "Relevant context found"),
                        source=ArgumentSource.KNOWLEDGE_HUB,
                        strength=min(0.5, relevance),
                        metadata={
                            "decision": "allow",
                            "context": entry.get("content", ""),
                        },
                    )
                    af.add_argument(arg)

        # ── Cross-attack resolution ──────────────────────────────
        self._add_strength_attacks(af)

        return af

    def _add_strength_attacks(self, af: ArgumentationFramework) -> None:
        """
        Add attacks based on argument strength.

        When two arguments with contradictory decisions exist,
        the stronger one attacks the weaker (preference-based
        argumentation following Amgoud & Cayrol).
        """
        args = list(af.arguments.values())
        for i, a1 in enumerate(args):
            for a2 in args[i + 1:]:
                d1 = a1.metadata.get("decision", "")
                d2 = a2.metadata.get("decision", "")

                # Only add strength-based attacks between contradictory decisions
                if not self._decisions_conflict(d1, d2):
                    continue

                if a1.strength > a2.strength + 0.1:
                    af.add_attack(
                        a1.id, a2.id,
                        AttackType.REBUT,
                        f"Strength override ({a1.strength:.2f} > {a2.strength:.2f})",
                    )
                elif a2.strength > a1.strength + 0.1:
                    af.add_attack(
                        a2.id, a1.id,
                        AttackType.REBUT,
                        f"Strength override ({a2.strength:.2f} > {a1.strength:.2f})",
                    )

    @staticmethod
    def _decisions_conflict(d1: str, d2: str) -> bool:
        """Check if two decisions are contradictory."""
        if d1 == d2:
            return False
        conflict_pairs = {
            ("allow", "deny"),
            ("deny", "allow"),
            ("allow", "allow_with_modifications"),
        }
        return (d1, d2) in conflict_pairs or (d2, d1) in conflict_pairs
