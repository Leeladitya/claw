# tests/ — Test Suite

## What This Is (for everyone)

These tests verify that every part of Claw works correctly. There are 28 tests covering PII detection, policy evaluation, knowledge storage, argumentation logic, and the full pipeline. If any test fails, something is broken.

Think of them as a checklist that runs automatically every time someone changes the code. No change ships without all 28 checks passing.

## What This Is (for developers)

**test_claw.py** — 28 pytest test cases:
- PII Scanner: SSN, credit card, email, phone, IP detection + masking
- OPA integration: mock policy evaluation
- Knowledge Hub: store, query, reputation, temporal decay, domain reputation
- Argumentation Engine: grounded, preferred, stable extensions + rego bridge
- Pipeline integration: full 6-stage flow

Run: `pytest tests/ -v`

CI/CD runs these automatically on every push via GitHub Actions.
