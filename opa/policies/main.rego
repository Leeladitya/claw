# Claw v0.2.0 — Main Policy Bundle
# Declarative ABAC controls inspired by logic programming principles.
# Rego's close connection to Datalog makes it natural for expressing
# attribute-based access control — the same declarative foundation
# that underpins formal argumentation frameworks.

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

# ── Deny Rules ─────────────────────────────────────────────────

deny_reasons contains reason if {
    some blocked in data.domain_blocklist
    endswith(input.domain, blocked)
    reason := sprintf("domain_blocked: %s matches blocklist entry %s", [input.domain, blocked])
}

deny_reasons contains reason if {
    input.policy_pack != "research"
    input.pii_detected.ssn > 0
    reason := sprintf("critical_pii: %d SSN(s) detected", [input.pii_detected.ssn])
}

deny_reasons contains reason if {
    input.policy_pack != "research"
    input.pii_detected.credit_card > 0
    reason := sprintf("critical_pii: %d credit card(s) detected", [input.pii_detected.credit_card])
}

deny_reasons contains reason if {
    input.policy_pack in {"finance", "strict"}
    some signal in input.classification_signals
    signal in {"confidential", "classified"}
    reason := sprintf("classified_content: signal '%s' blocked under %s pack", [signal, input.policy_pack])
}

deny_reasons contains reason if {
    some pattern in data.internal_domain_patterns
    endswith(input.domain, pattern)
    reason := sprintf("internal_domain: %s matches internal pattern %s", [input.domain, pattern])
}

deny_reasons contains reason if {
    some keyword in input.content_features.sensitive_keywords
    keyword in {"password", "api_key", "api-key", "secret_key", "secret-key", "private_key", "private-key"}
    reason := sprintf("credential_detected: '%s' found in content", [keyword])
}

deny_reasons contains reason if {
    input.policy_pack == "strict"
    not domain_in_strict_allowlist
    reason := sprintf("strict_mode: %s not in explicit allowlist", [input.domain])
}

# ── Modification Rules ─────────────────────────────────────────

modification_list contains mod if {
    pii_total := input.pii_detected.email + input.pii_detected.phone + input.pii_detected.ip_address
    pii_total > 0
    mod := sprintf("pii_redaction: %d item(s) require masking", [pii_total])
}

modification_list contains mod if {
    count(input.content_features.sensitive_keywords) > 0
    mod := sprintf("keyword_flag: %d sensitive keyword(s) flagged", [count(input.content_features.sensitive_keywords)])
}

# ── Matched Rules ──────────────────────────────────────────────

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

# ── Helpers ────────────────────────────────────────────────────

domain_in_strict_allowlist if {
    some allowed in data.strict_domain_allowlist
    endswith(input.domain, allowed)
}
