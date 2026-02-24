# 🦞 Claw

### What if AI had to justify every decision it makes — before it makes it?

---

## The Story

Every time you paste content into an AI, something invisible happens. Your text — with all its personal details, sensitive context, and organizational secrets — gets sent to a model that has no rules about what it should or shouldn't process.

No one checks if that email contains your social security number. No one asks whether the content from that website should even reach the model. No policy gate. No audit trail. No memory of what happened last time.

**Claw changes that.**

Claw is a governance layer that sits between you and your AI. Before any content reaches the model, it passes through a 6-stage pipeline that scans for personal information, evaluates access policies, checks domain reputation from memory, and — when rules conflict — uses formal argumentation logic to decide what should happen.

Every decision is logged. Every argument is traceable. Every override is justified.

Think of it as a security-conscious colleague who reads everything before the AI does, flags what matters, and keeps receipts.

---

## Why This Matters

**If you're a regular user:** Your personal data — emails, phone numbers, financial details — gets automatically detected and masked before it ever reaches the AI. Claw protects you without you having to think about it.

**If you're a developer:** Claw gives you a programmable policy engine (OPA/Rego) that enforces attribute-based access control on AI inputs. Write rules once, enforce them everywhere.

**If you're a CISO or security professional:** This is a formal governance pipeline with an argumentation engine that resolves policy conflicts through Dung's Abstract Argumentation Frameworks — not arbitrary priority numbers. Every decision produces an auditable trail. The Knowledge Hub builds domain reputations over time, so the system gets smarter with use.

**If you're a researcher:** The argumentation engine implements grounded, preferred, and stable extension semantics. The Rego-to-AAF bridge demonstrates that declarative policy languages can be combined with formal argumentation theory for principled conflict resolution. The Knowledge Hub uses temporal decay scoring for contextual memory.

One system. Multiple levels of understanding. Real protection at every level.

---

## How It Works

```
 Your Browser
      │
      ▼
┌──────────────────────────────────────────────────┐
│                                                  │
│   1. PII Scan ──────── detect & mask             │
│      Found SSN? Credit card? Email?              │
│      Masked before anything else sees it.        │
│                                                  │
│   2. Policy Gate ────── OPA/Rego evaluation       │
│      Should this content be allowed at all?      │
│      Domain blocklists, content classification.  │
│                                                  │
│   3. Knowledge Hub ──── domain memory            │
│      Have we seen this domain before?            │
│      What happened last time? Trusted? Suspect?  │
│                                                  │
│   4. Argumentation ──── conflict resolution      │
│      Policy says deny. Knowledge says trusted.   │
│      Who wins? Formal logic decides.             │
│                                                  │
│   5. Context Assembly ─ prompt enrichment        │
│      Build the safest, richest prompt possible.  │
│                                                  │
│   6. Model Inference ── risk analysis            │
│      Claude analyzes — with full governance      │
│      context and a complete audit trail.         │
│                                                  │
└──────────────────────────────────────────────────┘
```

### What makes this different from a simple filter?

Most content filters are binary — block or allow. Claw **argues**.

When the PII scanner detects an email address (modify the content), but the Knowledge Hub shows this domain has been trusted 50 times (allow), and the policy says financial content requires strict review (deny) — these three signals conflict.

Claw doesn't pick the loudest one. It constructs a formal argumentation framework where each signal becomes an argument with a strength score. Arguments attack each other based on evidence. The engine computes which positions survive formal scrutiny — using the same mathematical framework that logicians have used since Dung formalized it in 1995.

The result: a principled decision, not an arbitrary one. And every step is logged.

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/Leeladitya/claw.git
cd claw
cp .env.example .env          # add your ANTHROPIC_API_KEY
docker compose up              # starts OPA + Claw server
```

That's it. Claw is running on `http://localhost:8787`.

### Browser Extension

The extension works across all major Chromium browsers and Firefox from a single codebase.

**Chrome / Edge / Brave:**
1. Navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle top-right)
3. Click **Load unpacked** → select `extension/`
4. The Claw shield icon appears in the toolbar

**Firefox:**
1. Go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on** → select `extension/manifest.json`
3. The Claw shield icon appears in the toolbar

Visit any page → click the 🦞 icon → **Scan & Analyze**

You'll see the full pipeline result: PII detection grid, policy decision, domain reputation from Knowledge Hub, argumentation breakdown (which arguments won, which lost, and why), risk analysis, and audit trail.

### API — Zero-Cost Policy Dry Run

Want to test policies without burning API credits? The dry-run endpoint runs stages 1-4 (PII → Policy → Knowledge → Argumentation) without calling Claude:

```bash
curl -X POST http://localhost:8787/v1/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://test.com",
    "text": "Contact john@example.com or call 555-123-4567. SSN: 123-45-6789"
  }'
```

Response shows: PII detected (1 email, 1 phone, 1 SSN), policy decision (deny — critical PII), argumentation result (deny argument at strength 0.95 defeats baseline allow at 0.3), and the full argument map.

---

## The Argumentation Engine

This is the part that makes Claw genuinely different.

**In plain language:** When different parts of the system disagree about what to do, the argumentation engine runs a formal debate. Each position becomes an argument with a strength score. Arguments can attack other arguments. The engine figures out which set of arguments can stand together without contradicting each other — that's the winning position.

**Technically:** The engine implements Dung's (1995) Abstract Argumentation Frameworks. The Rego-to-AAF Bridge converts OPA policy decisions, Knowledge Hub entries, and PII scan results into arguments:

| Signal | Argument Type | Strength |
|--------|--------------|----------|
| OPA deny rule | Deny argument | 0.9 |
| Critical PII (SSN/CC) | Deny argument | 0.95 |
| OPA modification rule | Modify argument | 0.7 |
| Knowledge Hub "trusted" entry | Trust argument (attacks deny) | varies |
| Knowledge Hub "suspicious" entry | Suspicion argument (attacks allow) | varies |
| Baseline | Allow argument | 0.3 |

The engine computes three types of solutions:

- **Grounded extension** (default) — the most cautious position. Only arguments that survive complete skeptical scrutiny. Polynomial time. This is what Claw uses for security decisions.
- **Preferred extensions** — all maximally defensible positions. Useful when multiple valid approaches exist.
- **Stable extensions** — positions that address every argument, leaving nothing unresolved.

---

## Knowledge Hub

Claw learns. Not through opaque neural networks, but through an auditable, domain-scoped memory system.

Every time Claw processes content from a domain, it records the decision: allowed, modified, or denied — along with what rules matched and what PII was found. Next time content arrives from the same domain, that history is retrieved and fed into the argumentation engine as contextual evidence.

Over time, domain reputations emerge:
- **Trusted** — consistent history of clean, allowed content
- **Suspicious** — pattern of denied or flagged content
- **Mixed** — some good, some bad
- **Unknown** — first encounter

Recent knowledge weighs more than old knowledge (exponential decay with 1-week halflife). This ensures the system adapts to changing domain behavior while maintaining institutional memory.

---

## Sequential Decision Modeling (v0.3.0)

Real governance decisions don't happen in isolation. A CISO's first call at T+0 reshapes the landscape for every call that follows. Claw v0.3.0 adds a **Sequential Decision Analytics and Modeling** (SDAM) layer — built on Powell's framework from Princeton — that models how governance decisions chain together over time.

The 6-stage pipeline handles one decision. The SDAM model handles the *sequence*.

**How it maps to governance:**

The PII scan results, OPA evaluation, and Knowledge Hub context become the **state** (S_t). The CISO's choice becomes the **decision** (x_t). Incoming forensics, satellite data, AI confidence changes become new **exogenous information** (W_{t+1}). The argumentation framework shifting — arguments created, defeated, strengthened — is the **transition function**. And the multi-dimensional governance score (consistency, proportionality, reversibility, auditability, epistemic rigor) is the **objective**.

**Two policy classes are implemented:**

**PFA (Policy Function Approximation)** — threshold rules. If confidence exceeds θ and sensor integrity is above threshold, escalate. Fast, interpretable, tunable via grid search.

**CFA (Cost Function Approximation)** — parameterized scoring. Each action scored via weighted features (evidence-seeking, caution, duty, speed) with context-dependent adjustments. Adapts to varying state conditions.

Monte Carlo simulation across 200 scenarios: CFA outperforms PFA consistently (avg 52.86 vs 48.37). This result is validated by a dedicated test (`test_cfa_outperforms_pfa`).

See `server/sdam_model.py` (556 lines) for the full implementation.

---

## Policy Packs (v0.3.0 Expansion)

Claw ships with **6 policy packs** — each a different enforcement posture:

| Pack | Rules | Focus |
|------|-------|-------|
| `standard` | Baseline protection | Domain blocklists, basic PII, credentials |
| `strict` | Zero-trust | Unlisted domains denied, aggregate PII |
| `research` | Academic | SSN/CC allowed for research classification |
| `finance` | Financial services | Domain allowlist-only, confidential keywords |
| `healthcare` | HIPAA-aligned | PHI keyword blocking, aggregate PII for patient records |
| `community` | Arena validation | Scenario schema enforcement |

v0.3.0 expanded from 7 to **12 deny rules** and from 2 to **5 modification rules**, with risk score computation that feeds directly into the argumentation bridge. Healthcare pack detects aggregate patient data (≥3 PII signals), finance pack enforces domain allowlists, and all packs now detect bearer/access/refresh tokens.

**20 OPA test cases** cover every rule.

---

## Browser Compatibility

The extension ships as a single codebase that works across browsers using a cross-browser compatibility shim (`const B = typeof browser !== "undefined" ? browser : chrome`). Firefox exposes `browser.*` (Promise-native), Chrome 116+ MV3 exposes `chrome.*` with Promise support — both work identically after the alias.

| Browser | Status | Notes |
|---------|--------|-------|
| Chrome 116+ | ✅ | Load unpacked from `extension/` |
| Edge (Chromium) | ✅ | Same as Chrome |
| Brave | ✅ | Same as Chrome |
| Firefox 109+ | ✅ | Load temporary add-on |
| Safari | ❌ | Different extension model |

---

## Security

Claw was built to pass a security audit. Every finding from the v0.1.0 quality assessment has been addressed:

| Concern | Solution |
|---------|----------|
| No authentication | Bearer token with constant-time comparison |
| No rate limiting | Per-IP token bucket (30-60 req/min) |
| CORS wildcard | Configurable allowlist, no wildcards |
| No input validation | Max content size enforcement |
| Container runs as root | Non-root user in Docker |
| Unpinned dependencies | All versions pinned |
| No tests | 65 Python tests + 20 OPA policy tests |
| No CI/CD | GitHub Actions: OPA tests → Python tests → integration |

Full details in [SECURITY.md](SECURITY.md).

---

## API Reference

| Method | Path | What it does |
|--------|------|-------------|
| `POST` | `/v1/analyze` | Full 6-stage pipeline — PII, policy, knowledge, argumentation, assembly, Claude |
| `POST` | `/v1/policy/evaluate` | Dry-run stages 1-4 only — no model call, zero cost |
| `GET` | `/v1/policy/packs` | List available policy packs |
| `POST` | `/v1/knowledge/store` | Manually add a knowledge entry |
| `POST` | `/v1/knowledge/query` | Search the Knowledge Hub |
| `GET` | `/v1/knowledge/reputation/{domain}` | Get a domain's reputation |
| `GET` | `/v1/knowledge/stats` | Knowledge Hub statistics |
| `GET` | `/v1/audit/decisions` | Query the audit trail |
| `GET` | `/v1/health` | Check all component health |

---

## Configuration

| Variable | Default | What it controls |
|----------|---------|-----------------|
| `ANTHROPIC_API_KEY` | *(required)* | Your Claude API key |
| `CLAW_MODEL` | `claude-sonnet-4-5-20250514` | Which model to use |
| `CLAW_POLICY_PACK` | `standard` | Active policy ruleset |
| `CLAW_API_KEYS` | *(empty = auth off)* | API keys for authentication |
| `CLAW_CORS_ORIGINS` | localhost + extensions | Allowed origins |
| `CLAW_MAX_INPUT_CHARS` | `60000` | Max input length |

---

## Project Structure

```
claw/
├── server/
│   ├── app.py                    # FastAPI — the 6-stage pipeline
│   ├── sdam_model.py             # Powell's SDAM framework (v0.3.0)
│   ├── middleware/
│   │   ├── auth.py               # API key authentication
│   │   ├── rate_limiter.py       # Per-IP rate limiting
│   │   ├── pii_scanner.py        # PII detection & masking
│   │   └── opa_client.py         # OPA policy evaluation
│   ├── knowledge/
│   │   ├── hub.py                # Knowledge Hub — domain memory
│   │   └── models.py             # Knowledge data models
│   ├── argumentation/
│   │   ├── engine.py             # Dung's AAF — extension computation
│   │   ├── models.py             # Argumentation data models
│   │   └── rego_bridge.py        # OPA decisions → formal arguments
│   └── utils/
│       └── audit.py              # Audit trail logger
├── opa/
│   ├── policies/main.rego        # 12 deny + 5 modify rules (v0.3.0)
│   ├── policies/main_test.rego   # 20 OPA tests
│   └── data/data.json            # Domain lists, configuration
├── extension/                    # Cross-browser extension (Chrome/Edge/Brave/Firefox)
├── tests/
│   ├── test_claw.py              # 28 pipeline tests
│   └── test_sdam.py              # 37 SDAM tests (v0.3.0)
├── .github/workflows/ci.yml     # CI/CD pipeline
├── Dockerfile                    # Non-root container
├── docker-compose.yml            # OPA + Claw orchestration
└── requirements.txt              # Pinned dependencies
```

---

## Development

```bash
pip install -r requirements.txt

pytest tests/ -v                    # 65 Python tests (28 pipeline + 37 SDAM)
opa test opa/policies/ opa/data/ -v # 20 OPA policy tests
ruff check server/ tests/           # Lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development guide.

---

## What's Next

Claw v0.3.0 added a temporal dimension. The engine now models not just single decisions, but the *sequence* of decisions a CISO navigates under uncertainty — and compares policy strategies via Monte Carlo simulation.

The next steps:

**VFA and DLA policy classes** — two more of Powell's four universal policy types. Value Function Approximation learns which states are worth reaching. Direct Lookahead simulates forward before deciding. Both require community data to train.

**AGORA integration** — Claw's engine powers **[AGORA](https://github.com/Leeladitya/agora)**, an open Decision Arena where CISOs, researchers, and ethicists contribute scenarios and reason together about the governance decisions that affect everyone. Arena playthroughs feed directly into the SDAM model.

**Constitutional framework loader** — load Vedic dharmic, Kantian, Confucian, or Islamic jurisprudential frameworks into the argumentation engine and let them argue. The JSON format is defined; the engine integration is next.

Because governance decisions that affect everyone should be reasoned about by everyone.

---

**License:** MIT

**Built for:** [saatvix.com](https://saatvix.com)
