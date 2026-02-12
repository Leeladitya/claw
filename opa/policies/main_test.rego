package claw.main_test

import rego.v1

# Test 1: Clean content allowed
test_clean_content_allowed if {
    result := data.claw.main with input as {
        "domain": "example.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": [], "word_count": 100},
    }
    result.decision == "allow"
}

# Test 2: Blocked domain denied
test_blocked_domain if {
    result := data.claw.main with input as {
        "domain": "evil.bank.com",
        "policy_pack": "standard",
        "pii_detected": {"ssn": 0, "credit_card": 0, "email": 0, "phone": 0, "ip_address": 0},
        "classification_signals": [],
        "content_features": {"sensitive_keywords": []},
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
        "content_features": {"sensitive_keywords": []},
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
        "content_features": {"sensitive_keywords": []},
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
        "content_features": {"sensitive_keywords": []},
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
        "content_features": {"sensitive_keywords": []},
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
        "content_features": {"sensitive_keywords": []},
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
        "content_features": {"sensitive_keywords": []},
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
        "content_features": {"sensitive_keywords": ["password", "api_key"]},
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
        "content_features": {"sensitive_keywords": []},
    }
    result.decision == "deny"
}
