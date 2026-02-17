# server/ — The Governance Engine

## What This Is (for everyone)

This folder contains the brain of Claw — the 6-stage pipeline that decides what happens to content before it reaches the AI. Think of it like a courthouse: content enters, gets examined by different specialists (PII scanner, policy evaluator, knowledge expert, argumentation judge), and exits with a verdict and a full audit trail.

The key innovation here is the **argumentation engine**. Most security systems use simple rules: "if bad, block." But what happens when rules contradict each other? Domain is trusted, but content has an SSN. Policy says deny, but knowledge says this domain has been clean 50 times. Claw doesn't pick the loudest rule — it constructs a formal debate where each signal becomes an argument, and mathematical logic determines which arguments survive scrutiny.

## What This Is (for developers)

FastAPI application implementing a 6-stage governance pipeline:

1. **PII Scanner** (`middleware/pii_scanner.py`) — Regex-based PII detection for SSN, credit card, email, phone, IP
2. **OPA Client** (`middleware/opa_client.py`) — HTTP client to Open Policy Agent for Rego policy evaluation
3. **Knowledge Hub** (`knowledge/hub.py`) — JSONL-backed domain memory with temporal decay scoring
4. **Argumentation Engine** (`argumentation/engine.py`) — Dung's AAF with grounded/preferred/stable extensions
5. **Context Assembly** — Combines all signals into enriched prompt
6. **Model Inference** — Sends to Claude with full governance context

**SDAM Model** (`sdam_model.py`) — Powell's Sequential Decision Analytics framework applied to governance. Maps the 5 elements (state, decision, exogenous info, transition, objective) to CISO decision scenarios. Implements PFA and CFA policy classes with Monte Carlo simulation.

Key entry point: `app.py` — all routes defined here.
