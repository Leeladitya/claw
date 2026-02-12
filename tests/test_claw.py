"""
Claw v0.2.0 Test Suite

Tests covering:
- PII Scanner: detection accuracy and masking
- Argumentation Engine: grounded/preferred/stable extensions
- Knowledge Hub: store, query, reputation
- Rego Bridge: framework construction from OPA decisions
"""
import os
import sys
import tempfile


# Add server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── PII Scanner Tests ──────────────────────────────────────────

class TestPIIScanner:
    def test_ssn_detection(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("My SSN is 123-45-6789 and hers is 234-56-7890")
        assert result.counts["ssn"] == 2
        assert result.has_critical_pii is True
        assert "[SSN_REDACTED]" in result.masked_text

    def test_credit_card_detection(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("Card: 4111-1111-1111-1111")
        assert result.counts["credit_card"] == 1
        assert result.has_critical_pii is True
        assert "[CC_REDACTED]" in result.masked_text

    def test_email_detection(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("Contact john@example.com or jane@corp.org")
        assert result.counts["email"] == 2
        assert "[EMAIL_REDACTED]" in result.masked_text

    def test_phone_detection(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("Call 555-123-4567")
        assert result.counts["phone"] == 1

    def test_ip_detection(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("Server at 192.168.1.100")
        assert result.counts["ip_address"] == 1

    def test_no_pii(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("This is a clean document about weather.")
        assert result.has_any_pii is False
        assert result.total_pii_count == 0

    def test_sensitive_keywords(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("This document is CONFIDENTIAL and contains api_key data")
        assert "confidential" in result.sensitive_keywords
        assert "api_key" in result.sensitive_keywords

    def test_classification_signals(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("Q3 financial earnings report — confidential")
        assert "financial" in result.classification_signals
        assert "confidential" in result.classification_signals

    def test_localhost_ip_excluded(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("Connect to 127.0.0.1")
        assert result.counts["ip_address"] == 0

    def test_invalid_ssn_excluded(self):
        from server.middleware.pii_scanner import scan_pii
        result = scan_pii("The code is 000-12-3456")
        assert result.counts["ssn"] == 0


# ── Argumentation Engine Tests ─────────────────────────────────

class TestArgumentationEngine:
    def _make_engine(self):
        from server.argumentation import ArgumentationEngine
        return ArgumentationEngine()

    def _make_framework(self):
        from server.argumentation import (
            ArgumentationFramework, Argument, ArgumentSource, AttackType
        )
        af = ArgumentationFramework()
        return af, Argument, ArgumentSource, AttackType

    def test_grounded_empty_framework(self):
        engine = self._make_engine()
        af, Argument, ArgumentSource, _ = self._make_framework()
        # No arguments → empty grounded extension
        ext = engine.grounded_extension(af)
        assert ext.is_empty

    def test_grounded_unattacked_arguments(self):
        engine = self._make_engine()
        af, Argument, ArgumentSource, _ = self._make_framework()

        af.add_argument(Argument(id="a", claim="Allow", source=ArgumentSource.OPA_POLICY))
        af.add_argument(Argument(id="b", claim="Modify", source=ArgumentSource.PII_SCANNER))

        ext = engine.grounded_extension(af)
        assert "a" in ext.arguments
        assert "b" in ext.arguments

    def test_grounded_simple_attack(self):
        """a attacks b → grounded = {a}"""
        engine = self._make_engine()
        af, Argument, ArgumentSource, AttackType = self._make_framework()

        af.add_argument(Argument(id="a", claim="Deny", source=ArgumentSource.OPA_POLICY))
        af.add_argument(Argument(id="b", claim="Allow", source=ArgumentSource.OPA_POLICY))
        af.add_attack("a", "b", AttackType.REBUT)

        ext = engine.grounded_extension(af)
        assert "a" in ext.arguments
        assert "b" not in ext.arguments

    def test_grounded_mutual_attack(self):
        """a ↔ b → grounded = ∅ (neither is defended)"""
        engine = self._make_engine()
        af, Argument, ArgumentSource, AttackType = self._make_framework()

        af.add_argument(Argument(id="a", claim="Deny", source=ArgumentSource.OPA_POLICY))
        af.add_argument(Argument(id="b", claim="Allow", source=ArgumentSource.KNOWLEDGE_HUB))
        af.add_attack("a", "b", AttackType.REBUT)
        af.add_attack("b", "a", AttackType.REBUT)

        ext = engine.grounded_extension(af)
        assert ext.is_empty

    def test_grounded_reinstatement(self):
        """a → b → c: a defends c, grounded = {a, c}"""
        engine = self._make_engine()
        af, Argument, ArgumentSource, AttackType = self._make_framework()

        af.add_argument(Argument(id="a", claim="Trust override", source=ArgumentSource.KNOWLEDGE_HUB))
        af.add_argument(Argument(id="b", claim="Deny", source=ArgumentSource.OPA_POLICY))
        af.add_argument(Argument(id="c", claim="Allow", source=ArgumentSource.OPA_POLICY))
        af.add_attack("a", "b", AttackType.UNDERMINE)
        af.add_attack("b", "c", AttackType.REBUT)

        ext = engine.grounded_extension(af)
        assert "a" in ext.arguments
        assert "c" in ext.arguments
        assert "b" not in ext.arguments

    def test_preferred_mutual_attack(self):
        """a ↔ b → preferred = [{a}, {b}]"""
        engine = self._make_engine()
        af, Argument, ArgumentSource, AttackType = self._make_framework()

        af.add_argument(Argument(id="a", claim="Deny", source=ArgumentSource.OPA_POLICY))
        af.add_argument(Argument(id="b", claim="Allow", source=ArgumentSource.KNOWLEDGE_HUB))
        af.add_attack("a", "b", AttackType.REBUT)
        af.add_attack("b", "a", AttackType.REBUT)

        preferred = engine.preferred_extensions(af)
        arg_sets = [ext.arguments for ext in preferred]
        assert {"a"} in arg_sets or {"b"} in arg_sets

    def test_stable_extension(self):
        """a → b: stable = [{a}] (a attacks everything outside)"""
        engine = self._make_engine()
        af, Argument, ArgumentSource, AttackType = self._make_framework()

        af.add_argument(Argument(id="a", claim="Deny", source=ArgumentSource.OPA_POLICY))
        af.add_argument(Argument(id="b", claim="Allow", source=ArgumentSource.OPA_POLICY))
        af.add_attack("a", "b", AttackType.REBUT)

        stable = engine.stable_extensions(af)
        assert len(stable) >= 1
        assert "a" in stable[0].arguments

    def test_resolve_produces_result(self):
        engine = self._make_engine()
        af, Argument, ArgumentSource, AttackType = self._make_framework()
        from server.argumentation import Semantics

        af.add_argument(Argument(
            id="deny_1", claim="Block domain",
            source=ArgumentSource.OPA_POLICY, strength=0.9,
            metadata={"decision": "deny"},
        ))
        af.add_argument(Argument(
            id="allow_1", claim="Baseline allow",
            source=ArgumentSource.OPA_POLICY, strength=0.3,
            metadata={"decision": "allow"},
        ))
        af.add_attack("deny_1", "allow_1", AttackType.REBUT)

        result = engine.resolve(af, Semantics.GROUNDED)
        assert result.decision == "deny"
        assert "deny_1" in result.winning_arguments

    def test_conflict_free_check(self):
        engine = self._make_engine()
        af, Argument, ArgumentSource, AttackType = self._make_framework()

        af.add_argument(Argument(id="a", claim="X", source=ArgumentSource.OPA_POLICY))
        af.add_argument(Argument(id="b", claim="Y", source=ArgumentSource.OPA_POLICY))
        af.add_attack("a", "b", AttackType.REBUT)

        assert engine.is_conflict_free(af, {"a"}) is True
        assert engine.is_conflict_free(af, {"a", "b"}) is False


# ── Rego Bridge Tests ──────────────────────────────────────────

class TestRegoBridge:
    def test_build_framework_from_deny(self):
        from server.argumentation import RegoBridge
        bridge = RegoBridge()
        af = bridge.build_framework(
            opa_decision={
                "deny_reasons": ["domain_blocked: evil.com"],
                "modification_list": [],
                "matched_rules": ["domain_blocked"],
            },
        )
        assert len(af.arguments) >= 2  # baseline + deny
        assert len(af.attacks) >= 1    # deny attacks baseline

    def test_build_framework_with_pii(self):
        from server.argumentation import RegoBridge
        bridge = RegoBridge()
        af = bridge.build_framework(
            opa_decision={"deny_reasons": [], "modification_list": [], "matched_rules": []},
            pii_result={"counts": {"ssn": 1, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0}},
        )
        assert any("pii" in a.id for a in af.arguments.values())

    def test_build_framework_with_knowledge(self):
        from server.argumentation import RegoBridge
        bridge = RegoBridge()
        af = bridge.build_framework(
            opa_decision={"deny_reasons": [], "modification_list": [], "matched_rules": []},
            knowledge_entries=[{
                "domain": "example.com",
                "disposition": "trusted",
                "relevance_score": 0.8,
                "summary": "Previously trusted",
            }],
        )
        assert any("knowledge" in a.id for a in af.arguments.values())


# ── Knowledge Hub Tests ────────────────────────────────────────

class TestKnowledgeHub:
    def _make_hub(self):
        from server.knowledge import KnowledgeHub
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        return KnowledgeHub(storage_path=path, max_entries=100)

    def test_store_and_query(self):
        from server.knowledge import KnowledgeEntry, KnowledgeQuery, Disposition, EntryType
        hub = self._make_hub()

        entry = KnowledgeEntry(
            id="test_1", domain="example.com",
            entry_type=EntryType.DOMAIN_REPUTATION,
            disposition=Disposition.TRUSTED,
            summary="Test domain",
        )
        stored = hub.store(entry)
        assert stored.id == "test_1"

        results = hub.query(KnowledgeQuery(domain="example.com"))
        assert len(results) == 1
        assert results[0]["domain"] == "example.com"

    def test_domain_reputation(self):
        from server.knowledge import KnowledgeEntry, Disposition, EntryType
        hub = self._make_hub()

        for i in range(5):
            hub.store(KnowledgeEntry(
                id=f"t_{i}", domain="good.com",
                entry_type=EntryType.POLICY_DECISION,
                disposition=Disposition.TRUSTED,
                summary=f"Allowed {i}",
                content=f"unique_content_{i}",
            ))

        rep = hub.get_domain_reputation("good.com")
        assert rep["reputation"] == "trusted"
        assert rep["allow_count"] == 5

    def test_suspicious_reputation(self):
        from server.knowledge import KnowledgeEntry, Disposition, EntryType
        hub = self._make_hub()

        for i in range(5):
            hub.store(KnowledgeEntry(
                id=f"s_{i}", domain="bad.com",
                entry_type=EntryType.POLICY_DECISION,
                disposition=Disposition.SUSPICIOUS,
                summary=f"Denied {i}",
            ))

        rep = hub.get_domain_reputation("bad.com")
        assert rep["reputation"] == "suspicious"

    def test_unknown_domain(self):
        hub = self._make_hub()
        rep = hub.get_domain_reputation("never-seen.com")
        assert rep["reputation"] == "unknown"

    def test_store_policy_decision(self):
        hub = self._make_hub()
        entry = hub.store_policy_decision(
            domain="test.com", decision="allow",
            matched_rules=["baseline_allow"],
            policy_pack="standard",
        )
        assert entry.domain == "test.com"
        assert "policy_decision" in entry.tags

    def test_stats(self):
        hub = self._make_hub()
        stats = hub.stats
        assert "total_entries" in stats
        assert stats["total_entries"] == 0
