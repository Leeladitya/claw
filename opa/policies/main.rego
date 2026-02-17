# Claw v0.2.0 — Main Policy Bundle
# ═══════════════════════════════════════════════════════════════
#
# WHAT THIS IS (for everyone):
#   These are the rules that Claw uses to decide what happens to
#   content before it reaches the AI. Think of them like a building's
#   security system — some doors are always open, some require a badge,
#   some are locked unless there's an emergency.
#
#   Every rule here can be read as an English sentence:
#   "IF [condition], THEN [action]"
#
# HOW IT WORKS (for developers):
#   Rego is a declarative policy language from Open Policy Agent (OPA).
#   It evaluates attribute-based access control (ABAC) — decisions based
#   on attributes of the content, domain, user context, and PII signals.
#   Each rule produces a reason string that feeds into the Argumentation
#   Engine as an argument with a strength score.
#
# HOW IT CONNECTS TO ARGUMENTATION:
#   The rego_bridge.py module converts every deny_reason and modification
#   into a formal argument in Dung's framework. When rules conflict,
#   the Argumentation Engine computes which survive — not arbitrary
#   priority numbers.
#
# POLICY PACKS:
#   - "standard"  : balanced protection, good for general use
#   - "strict"    : allowlist-only, for high-security environments
#   - "research"  : relaxed PII rules for academic/research contexts
#   - "finance"   : financial-sector controls (confidential blocking)
#   - "healthcare": medical data protection (HIPAA-aligned)
#   - "community" : governance scenario contributions (Arena data)
#
# ═══════════════════════════════════════════════════════════════

package claw.main

import rego.v1

# ── Decision Assembly ──────────────────────────────────────────

default decision := "allow"

decision := "deny" if {
    count(deny_reasons) > 0
}

decision := "allow_with_modifications" if {
    count(deny_reasons) == 0
    count(modification_list) > 0
}

# ── Risk Score (feeds into Argumentation Engine) ──────────────

default risk_score := 0

risk_score := score if {
    pii_risk := (input.pii_detected.ssn * 30) + (input.pii_detected.credit_card * 25) + ((input.pii_detected.email + input.pii_detected.phone) * 5)
    domain_risk := count([x | some x in deny_reasons; startswith(x, "domain_blocked")]) * 40
    credential_risk := count([x | some x in deny_reasons; startswith(x, "credential_detected")]) * 35
    raw := pii_risk + domain_risk + credential_risk
    score := min([raw, 100])
}

# ══════════════════════════════════════════════════════════════
# DENY RULES
# ══════════════════════════════════════════════════════════════

# Rule 1: Blocklisted domains
deny_reasons contains reason if {
    some blocked in data.domain_blocklist
    endswith(input.domain, blocked)
    reason := sprintf("domain_blocked: %s matches blocklist entry %s", [input.domain, blocked])
}

# Rule 2: Critical PII — Social Security Numbers
deny_reasons contains reason if {
    input.policy_pack != "research"
    input.pii_detected.ssn > 0
    reason := sprintf("critical_pii: %d SSN(s) detected", [input.pii_detected.ssn])
}

# Rule 3: Critical PII — Credit Cards
deny_reasons contains reason if {
    input.policy_pack != "research"
    input.pii_detected.credit_card > 0
    reason := sprintf("critical_pii: %d credit card(s) detected", [input.pii_detected.credit_card])
}

# Rule 4: Classified content under finance/strict/healthcare packs
deny_reasons contains reason if {
    input.policy_pack in {"finance", "strict", "healthcare"}
    some signal in input.classification_signals
    signal in {"confidential", "classified", "restricted", "internal_only"}
    reason := sprintf("classified_content: signal '%s' blocked under %s pack", [signal, input.policy_pack])
}

# Rule 5: Internal domains
deny_reasons contains reason if {
    some pattern in data.internal_domain_patterns
    endswith(input.domain, pattern)
    reason := sprintf("internal_domain: %s matches internal pattern %s", [input.domain, pattern])
}

# Rule 6: Credential detection
deny_reasons contains reason if {
    some keyword in input.content_features.sensitive_keywords
    keyword in {"password", "api_key", "api-key", "secret_key", "secret-key", "private_key", "private-key", "bearer_token", "access_token", "refresh_token"}
    reason := sprintf("credential_detected: '%s' found in content", [keyword])
}

# Rule 7: Strict mode — allowlist only
deny_reasons contains reason if {
    input.policy_pack == "strict"
    not domain_in_strict_allowlist
    reason := sprintf("strict_mode: %s not in explicit allowlist", [input.domain])
}

# Rule 8: Healthcare — Protected Health Information keywords
deny_reasons contains reason if {
    input.policy_pack == "healthcare"
    some keyword in input.content_features.sensitive_keywords
    keyword in {"mrn", "medical_record", "diagnosis", "patient_id", "insurance_id", "prescription"}
    reason := sprintf("phi_detected: '%s' found — healthcare pack blocks protected health information", [keyword])
}

# Rule 9: Healthcare — Aggregate PII signals suggest patient records
deny_reasons contains reason if {
    input.policy_pack == "healthcare"
    pii_total := input.pii_detected.email + input.pii_detected.phone + input.pii_detected.ssn
    pii_total >= 3
    reason := sprintf("phi_aggregate: %d PII signals detected — likely patient record under healthcare pack", [pii_total])
}

# Rule 10: Content volume threshold
deny_reasons contains reason if {
    input.content_features.word_count > 50000
    reason := sprintf("volume_exceeded: %d words exceeds maximum threshold (50000)", [input.content_features.word_count])
}

# Rule 11: Finance domain enforcement
deny_reasons contains reason if {
    input.policy_pack == "finance"
    not domain_in_finance_allowlist
    not domain_in_strict_allowlist
    reason := sprintf("finance_domain: %s not in approved financial sources", [input.domain])
}

# Rule 12: Community scenario schema validation
deny_reasons contains reason if {
    input.policy_pack == "community"
    input.content_features.content_type == "scenario_submission"
    not input.content_features.has_valid_schema
    reason := "invalid_scenario: submission does not match Arena scenario schema"
}

# ══════════════════════════════════════════════════════════════
# MODIFICATION RULES
# ══════════════════════════════════════════════════════════════

# Rule M1: Non-critical PII masking
modification_list contains mod if {
    pii_total := input.pii_detected.email + input.pii_detected.phone + input.pii_detected.ip_address
    pii_total > 0
    mod := sprintf("pii_redaction: %d item(s) require masking", [pii_total])
}

# Rule M2: Sensitive keyword flagging
modification_list contains mod if {
    count(input.content_features.sensitive_keywords) > 0
    mod := sprintf("keyword_flag: %d sensitive keyword(s) flagged", [count(input.content_features.sensitive_keywords)])
}

# Rule M3: URL density warning
modification_list contains mod if {
    input.content_features.url_count > 10
    mod := sprintf("url_density: %d URLs detected — recommend summarization", [input.content_features.url_count])
}

# Rule M4: Code/system content annotation
modification_list contains mod if {
    some keyword in input.content_features.sensitive_keywords
    keyword in {"localhost", "127.0.0.1", "root", "admin", "sudo"}
    mod := sprintf("code_annotation: '%s' suggests system content — review for hardcoded values", [keyword])
}

# Rule M5: Healthcare de-identification reminder
modification_list contains mod if {
    input.policy_pack == "healthcare"
    some keyword in input.content_features.sensitive_keywords
    keyword in {"clinical", "treatment", "therapy", "symptom", "prognosis"}
    mod := sprintf("deidentification_reminder: healthcare term '%s' — verify de-identification", [keyword])
}

# ══════════════════════════════════════════════════════════════
# MATCHED RULES — Audit trail
# ══════════════════════════════════════════════════════════════

matched_rules contains rule if {
    count(deny_reasons) > 0
    some reason in deny_reasons
    rule := reason
}

matched_rules contains rule if {
    count(modification_list) > 0
    some mod in modification_list
    rule := mod
}

matched_rules contains "baseline_allow" if {
    count(deny_reasons) == 0
    count(modification_list) == 0
}

# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

domain_in_strict_allowlist if {
    some allowed in data.strict_domain_allowlist
    endswith(input.domain, allowed)
}

domain_in_finance_allowlist if {
    some allowed in data.finance_domain_allowlist
    endswith(input.domain, allowed)
}

# ══════════════════════════════════════════════════════════════
# POLICY METADATA — For argumentation bridge
# ══════════════════════════════════════════════════════════════

policy_metadata := {
    "pack": input.policy_pack,
    "deny_count": count(deny_reasons),
    "modification_count": count(modification_list),
    "risk_score": risk_score,
    "matched_rule_count": count(matched_rules),
}
