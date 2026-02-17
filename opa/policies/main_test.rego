package claw.main_test

import rego.v1

# ═══════════════════════════════════════════════════════════════
# TEST SUITE for Claw v0.2.0 Policy Bundle
#
# WHAT THESE DO (for everyone):
#   Each test simulates a specific situation and checks that the
#   policy engine makes the RIGHT decision. If any test fails,
#   we know a policy change broke something.
#
# HOW TO RUN:
#   opa test opa/policies/ opa/data/ -v
# ═══════════════════════════════════════════════════════════════

# ── CORE TESTS (original 10) ─────────────────────────────────

# Test 1: Clean content → allow
test_clean_content_allowed if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 100, "url_count": 0},
    }
    result.decision == "allow"
}

# Test 2: Blocked domain → deny
test_blocked_domain if {
    result := data.claw.main with input as {
        "domain": "evil.bank.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 3: SSN triggers deny
test_ssn_deny if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 2, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 4: Email triggers modification
test_email_modification if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 3, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "allow_with_modifications"
}

# Test 5: Research pack allows SSN
test_research_allows_ssn if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "research",
        "pii_detected": {"ssn": 1, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "allow"
}

# Test 6: Internal domain blocked
test_internal_domain if {
    result := data.claw.main with input as {
        "domain": "secret.corp.local",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 7: Strict pack denies unlisted domain
test_strict_unlisted if {
    result := data.claw.main with input as {
        "domain": "random-site.com",
        "policy_pack": "strict",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 8: Strict pack allows .gov
test_strict_allows_gov if {
    result := data.claw.main with input as {
        "domain": "data.census.gov",
        "policy_pack": "strict",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "allow"
}

# Test 9: Credential keyword denied
test_credential_keyword if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": ["password", "api_key"], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 10: Finance pack blocks confidential
test_finance_confidential if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "finance",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": ["confidential"],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# ── NEW TESTS (expanded policies) ────────────────────────────

# Test 11: Healthcare — PHI keyword blocked
test_healthcare_phi_keyword if {
    result := data.claw.main with input as {
        "domain": "hospital.org",
        "policy_pack": "healthcare",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": ["diagnosis", "prescription"], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 12: Healthcare — aggregate PII triggers deny
test_healthcare_aggregate_pii if {
    result := data.claw.main with input as {
        "domain": "clinic.com",
        "policy_pack": "healthcare",
        "pii_detected": {"ssn": 1, "credit_card": 0, "email": 1, "phone": 1, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 13: Volume threshold exceeded
test_volume_threshold if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 60000, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 14: Finance domain enforcement
test_finance_domain_enforcement if {
    result := data.claw.main with input as {
        "domain": "random-blog.com",
        "policy_pack": "finance",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 15: Healthcare allows clean clinical discussion with modification
test_healthcare_clinical_modification if {
    result := data.claw.main with input as {
        "domain": "pubmed.gov",
        "policy_pack": "healthcare",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": ["clinical"], "word_count": 50, "url_count": 0},
    }
    result.decision == "allow_with_modifications"
}

# Test 16: Bearer token triggers deny
test_bearer_token_deny if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": ["bearer_token"], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}

# Test 17: URL density triggers modification
test_url_density_modification if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 100, "url_count": 15},
    }
    result.decision == "allow_with_modifications"
}

# Test 18: Risk score computation
test_risk_score_with_ssn if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 2, "credit_card": 1, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.risk_score > 0
}

# Test 19: Community pack rejects invalid scenario
test_community_invalid_scenario if {
    result := data.claw.main with input as {
        "domain": "github.com",
        "policy_pack": "community",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0, "content_type": "scenario_submission", "has_valid_schema": false},
    }
    result.decision == "deny"
}

# Test 20: Healthcare — restricted classification
test_healthcare_restricted if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "healthcare",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": ["restricted"],
        "content_features": {"sensitive_keywords": [], "word_count": 50, "url_count": 0},
    }
    result.decision == "deny"
}
