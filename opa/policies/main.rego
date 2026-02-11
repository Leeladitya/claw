# ─────────────────────────────────────────────────────────────────
#  Claw Main Policy — claw/main
#
#  Evaluates browser content requests against security policies.
#  Returns a structured decision: allow, allow_with_modifications, or deny.
#
#  This file is loaded by OPA at startup and queried by the Claw
#  server at: POST /v1/data/claw/main
# ─────────────────────────────────────────────────────────────────

package claw.main

import rego.v1

# ─── Default Decision ───────────────────────────────────────────
# Start with allow, then layer on deny rules and modification rules.
# If ANY deny rule fires, the final decision is deny.
# If modification rules fire but no deny rules, decision is allow_with_modifications.
# Otherwise, decision is allow.

default _base_allow := true

# ─────────────────────────────────────────────────────────────────
#  DENY RULES
#  Any of these firing produces a hard deny.
# ─────────────────────────────────────────────────────────────────

# Rule: Block blacklisted domains
deny_domain if {
	some blocked in data.domain_blocklist
	endswith(input.domain, blocked)
}

# Rule: Block if SSN or credit card data detected (except research pack)
deny_critical_pii if {
	input.policy_pack != "research"
	input.pii_detected.ssn > 0
}

deny_critical_pii if {
	input.policy_pack != "research"
	input.pii_detected.credit_card > 0
}

# Rule: Block content with top-secret/classified signals (strict + finance packs)
deny_classified if {
	input.policy_pack in {"strict", "finance"}
	some signal in input.content_features.classification_signals
	signal in {"confidential", "legal_privileged"}
}

# Rule: Block internal corporate domains unless on research pack
deny_internal_domain if {
	input.policy_pack != "research"
	some pattern in data.internal_domain_patterns
	endswith(input.domain, pattern)
}

# Rule: Block if credential patterns found in content
deny_credentials if {
	input.policy_pack != "research"
	some signal in input.content_features.classification_signals
	signal == "credentials"
}

# Rule: Strict pack requires explicit domain allowlist
deny_strict_unlisted if {
	input.policy_pack == "strict"
	not domain_in_strict_allowlist
}

domain_in_strict_allowlist if {
	some allowed in data.strict_domain_allowlist
	endswith(input.domain, allowed)
}

# ─────────────────────────────────────────────────────────────────
#  MODIFICATION RULES
#  These fire when content is allowed but requires transformation.
# ─────────────────────────────────────────────────────────────────

# Modification: Mask PII (emails, phones) when detected
modify_mask_pii if {
	input.pii_detected.total > 0
	input.policy_pack != "research"
}

# Modification: Flag sensitive keywords for awareness
modify_flag_keywords if {
	count(input.content_features.sensitive_keywords) > 0
}

# ─────────────────────────────────────────────────────────────────
#  DECISION ASSEMBLY
#  Collects all fired rules and produces the final structured result.
# ─────────────────────────────────────────────────────────────────

# Collect all deny reasons
deny_reasons["domain_blocklist: domain is blacklisted"] if { deny_domain }
deny_reasons["critical_pii: SSN or credit card data detected"] if { deny_critical_pii }
deny_reasons["classified_content: confidential or privileged content detected"] if { deny_classified }
deny_reasons["internal_domain: corporate internal domain blocked"] if { deny_internal_domain }
deny_reasons["credentials_detected: passwords or API keys found in content"] if { deny_credentials }
deny_reasons["strict_unlisted: domain not on strict allowlist"] if { deny_strict_unlisted }

# Collect all modification descriptions
modification_list["pii_masking: redact detected PII before model submission"] if { modify_mask_pii }
modification_list["keyword_flagging: sensitive keywords detected in content"] if { modify_flag_keywords }

# Collect matched rule names for audit
matched_rules[rule] if { some rule in deny_reasons }
matched_rules[rule] if { some rule in modification_list }

# Count total rules evaluated
rules_evaluated := 8

# ─── Final Decision ─────────────────────────────────────────────

decision := "deny" if {
	count(deny_reasons) > 0
}

decision := "allow_with_modifications" if {
	count(deny_reasons) == 0
	count(modification_list) > 0
}

decision := "allow" if {
	count(deny_reasons) == 0
	count(modification_list) == 0
}

# First deny reason as the human-readable explanation
reason := concat("; ", sort(deny_reasons)) if {
	count(deny_reasons) > 0
}

reason := concat("; ", sort(modification_list)) if {
	count(deny_reasons) == 0
	count(modification_list) > 0
}

reason := "all checks passed" if {
	count(deny_reasons) == 0
	count(modification_list) == 0
}

# Collected modifications array
modifications := sort(modification_list)
