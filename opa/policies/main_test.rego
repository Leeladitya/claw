# ─────────────────────────────────────────────────────────────────
#  Claw Policy Tests
#
#  Run with: opa test opa/policies/ opa/data/ -v
# ─────────────────────────────────────────────────────────────────

package claw.main_test

import rego.v1

import data.claw.main

# ─── Helper: minimal valid input ────────────────────────────────

clean_input := {
	"url": "https://example.com/article",
	"domain": "example.com",
	"title": "Test Article",
	"policy_pack": "standard",
	"pii_detected": {
		"ssn": 0, "credit_card": 0,
		"email": 0, "phone": 0,
		"ip_address": 0, "total": 0,
	},
	"content_features": {
		"word_count": 500,
		"char_count": 3000,
		"sensitive_keywords": [],
		"classification_signals": [],
	},
}

# ─── Test: Clean content should be allowed ──────────────────────

test_clean_content_allowed if {
	main.decision == "allow" with input as clean_input
		with data.domain_blocklist as [".malware.com"]
		with data.internal_domain_patterns as [".corp.local"]
		with data.strict_domain_allowlist as []
}

# ─── Test: Blacklisted domain should be denied ──────────────────

test_blocked_domain_denied if {
	blocked_input := object.union(clean_input, {"domain": "evil.bank.com"})
	main.decision == "deny" with input as blocked_input
		with data.domain_blocklist as [".bank.com"]
		with data.internal_domain_patterns as []
		with data.strict_domain_allowlist as []
}

# ─── Test: SSN detection triggers deny ──────────────────────────

test_ssn_denied if {
	ssn_input := object.union(clean_input, {
		"pii_detected": {
			"ssn": 2, "credit_card": 0,
			"email": 0, "phone": 0,
			"ip_address": 0, "total": 2,
		},
	})
	main.decision == "deny" with input as ssn_input
		with data.domain_blocklist as []
		with data.internal_domain_patterns as []
		with data.strict_domain_allowlist as []
}

# ─── Test: Email PII triggers modifications ─────────────────────

test_email_pii_modifies if {
	pii_input := object.union(clean_input, {
		"pii_detected": {
			"ssn": 0, "credit_card": 0,
			"email": 3, "phone": 0,
			"ip_address": 0, "total": 3,
		},
	})
	main.decision == "allow_with_modifications" with input as pii_input
		with data.domain_blocklist as []
		with data.internal_domain_patterns as []
		with data.strict_domain_allowlist as []
}

# ─── Test: Research pack allows SSN through ─────────────────────

test_research_allows_ssn if {
	research_input := object.union(clean_input, {
		"policy_pack": "research",
		"pii_detected": {
			"ssn": 1, "credit_card": 0,
			"email": 0, "phone": 0,
			"ip_address": 0, "total": 1,
		},
	})
	# Research pack should NOT deny on SSN
	not main.deny_critical_pii with input as research_input
		with data.domain_blocklist as []
		with data.internal_domain_patterns as []
		with data.strict_domain_allowlist as []
}

# ─── Test: Internal domain blocked for standard pack ────────────

test_internal_domain_blocked if {
	internal_input := object.union(clean_input, {
		"domain": "secrets.corp.local",
	})
	main.decision == "deny" with input as internal_input
		with data.domain_blocklist as []
		with data.internal_domain_patterns as [".corp.local"]
		with data.strict_domain_allowlist as []
}

# ─── Test: Classified content denied for finance pack ───────────

test_classified_denied_finance if {
	classified_input := object.union(clean_input, {
		"policy_pack": "finance",
		"content_features": {
			"word_count": 500,
			"char_count": 3000,
			"sensitive_keywords": ["confidential"],
			"classification_signals": ["confidential"],
		},
	})
	main.decision == "deny" with input as classified_input
		with data.domain_blocklist as []
		with data.internal_domain_patterns as []
		with data.strict_domain_allowlist as []
}

# ─── Test: Strict pack denies unlisted domains ──────────────────

test_strict_unlisted_denied if {
	strict_input := object.union(clean_input, {
		"policy_pack": "strict",
		"domain": "random-blog.com",
	})
	main.decision == "deny" with input as strict_input
		with data.domain_blocklist as []
		with data.internal_domain_patterns as []
		with data.strict_domain_allowlist as [".gov", ".edu"]
}

# ─── Test: Strict pack allows .gov domains ──────────────────────

test_strict_allows_gov if {
	gov_input := object.union(clean_input, {
		"policy_pack": "strict",
		"domain": "nist.gov",
	})
	main.domain_in_strict_allowlist with input as gov_input
		with data.strict_domain_allowlist as [".gov"]
}
