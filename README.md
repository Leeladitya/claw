# 🦞 Claw v0.2.0

**Policy-gated, knowledge-enriched, argumentation-resolved browser content analysis.**

Claw is an AI governance pipeline that sits between your browser and Claude, enforcing access control policies, detecting PII, building domain knowledge, and resolving policy conflicts through formal argumentation — before any content reaches the model.

## Architecture

```
Browser Extension
       │
       ▼
┌──────────────────────────────────────────────────┐
│  6-Stage Governance Pipeline                     │
│                                                  │
│  1. PII Scan ──► regex detection & masking       │
│  2. OPA Gate ──► Rego policy evaluation          │
│  3. Knowledge Hub ──► domain memory lookup       │
│  4. Argumentation ──► Dung's AAF resolution      │
│  5. Context Assembly ──► prompt enrichment       │
│  6. Model Inference ──► Claude risk analysis     │
│                                                  │
│  Audit Trail ──► every decision logged (JSONL)   │
└──────────────────────────────────────────────────┘
```

### What's New in v0.2.0

- **Knowledge Hub** — persistent domain memory with temporal decay scoring. Claw learns domain reputations over time and feeds contextual arguments into policy decisions.
- **Argumentation Engine** — implements Dung's (1995) Abstract Argumentation Frameworks with grounded, preferred, and stable extension semantics. When OPA policies conflict or knowledge contradicts policy, formal argumentation provides principled resolution.
- **Rego-to-AAF Bridge** — converts OPA decisions, Knowledge Hub entries, and PII scan results into a formal argumentation framework with strength-based preference attacks.
- **Security Hardening** — API key authentication, per-IP rate limiting, restrictive CORS, input validation, non-root Docker container, pinned dependencies.
- **Test Suite** — 29 test cases covering PII scanning, argumentation engine, Rego bridge, and Knowledge Hub. Plus 10 OPA policy tests.
- **CI/CD** — GitHub Actions pipeline: OPA tests → Python tests + lint → integration tests.

## Quick Start

```bash
git clone https://github.com/Leeladitya/claw.git
cd claw
cp .env.example .env          # add your ANTHROPIC_API_KEY
docker compose up              # starts OPA + Claw server
```

**Install Firefox Extension:**
1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `extension/manifest.json`
4. Click the 🦞 icon on any page → **Scan & Analyze**

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/analyze` | Full 6-stage pipeline (PII → OPA → Knowledge → Argumentation → Assembly → Claude) |
| POST | `/v1/policy/evaluate` | Dry-run stages 1-4 only (no model call, zero cost) |
| GET | `/v1/policy/packs` | List available policy packs |
| POST | `/v1/knowledge/store` | Manually store a knowledge entry |
| POST | `/v1/knowledge/query` | Query Knowledge Hub |
| GET | `/v1/knowledge/reputation/{domain}` | Get domain reputation |
| GET | `/v1/knowledge/stats` | Knowledge Hub statistics |
| GET | `/v1/audit/decisions` | Query audit trail |
| GET | `/v1/health` | Component health check |

### Example: Analyze Content

```bash
curl -X POST http://localhost:8787/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/article",
    "text": "Article content to analyze..."
  }'
```

### Example: Policy Dry-Run with Argumentation

```bash
curl -X POST http://localhost:8787/v1/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://test.com",
    "text": "Content with email@example.com and SSN 123-45-6789"
  }' | jq '.argumentation'
```

### Example: Query Domain Knowledge

```bash
curl http://localhost:8787/v1/knowledge/reputation/example.com
```

## Argumentation Engine

When the OPA policy gate and Knowledge Hub produce conflicting signals, the Argumentation Engine resolves them using Dung's Abstract Argumentation Frameworks (AAF).

**How it works:**

The Rego Bridge converts pipeline outputs into arguments with strength scores:
- OPA deny rules → deny arguments (strength 0.9)
- Critical PII (SSN/CC) → deny arguments (strength 0.95)
- OPA modifications → modify arguments (strength 0.7)
- Knowledge "trusted" entries → trust arguments that attack deny rules
- Knowledge "suspicious" entries → suspicion arguments that attack allow
- Baseline allow → allow argument (strength 0.3)

Stronger arguments attack weaker ones when their decisions conflict. The engine then computes:

- **Grounded extension** (default): unique, polynomial-time, most skeptical — appropriate for security decisions
- **Preferred extensions**: maximal admissible sets for tie-breaking
- **Stable extensions**: complete coverage guarantee

## Knowledge Hub

Claw builds persistent domain memory through a JSONL-backed Knowledge Hub:

- Every policy decision is stored with domain, outcome, and matched rules
- Subsequent requests for the same domain retrieve historical context
- Temporal decay (1-week halflife) ensures recent knowledge weighs more
- Domain reputation aggregated as: trusted, suspicious, mixed, or unknown
- Knowledge entries feed into the Argumentation Engine as contextual arguments

## Security

See [SECURITY.md](SECURITY.md) for the full security architecture.

| Layer | Mechanism |
|-------|-----------|
| Authentication | Bearer token (constant-time comparison) |
| Rate Limiting | Per-IP token bucket (30-60 req/min by endpoint) |
| CORS | Configurable allowlist (no wildcard) |
| Input Validation | Max content size enforcement |
| PII Masking | SSN, credit card, email, phone, IP detection |
| Policy Gate | OPA/Rego attribute-based access control |
| Argumentation | Formal conflict resolution |
| Audit Trail | Immutable JSONL decision log |

## Configuration

See `.env.example` for all environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (required) | Claude API key |
| `CLAW_MODEL` | `claude-sonnet-4-5-20250514` | Model for analysis |
| `CLAW_POLICY_PACK` | `standard` | Active policy pack |
| `CLAW_API_KEYS` | (empty = auth disabled) | Comma-separated API keys |
| `CLAW_CORS_ORIGINS` | localhost + extensions | Allowed CORS origins |
| `CLAW_MAX_INPUT_CHARS` | `60000` | Max input content length |

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run Python tests
pytest tests/ -v

# Run OPA policy tests
opa test opa/policies/ opa/data/ -v

# Lint
ruff check server/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development guide.

## Project Structure

```
claw/
├── server/
│   ├── app.py                    # FastAPI app, 6-stage pipeline
│   ├── middleware/
│   │   ├── auth.py               # API key authentication
│   │   ├── rate_limiter.py       # Per-IP token bucket
│   │   ├── pii_scanner.py        # Regex PII detection
│   │   └── opa_client.py         # OPA sidecar client
│   ├── knowledge/
│   │   ├── hub.py                # JSONL-backed Knowledge Hub
│   │   └── models.py             # Knowledge data models
│   ├── argumentation/
│   │   ├── engine.py             # Dung's AAF engine
│   │   ├── models.py             # Argumentation data models
│   │   └── rego_bridge.py        # OPA → AAF converter
│   └── utils/
│       └── audit.py              # JSONL audit logger
├── opa/
│   ├── policies/
│   │   ├── main.rego             # Access control policies
│   │   └── main_test.rego        # OPA policy tests
│   └── data/
│       └── data.json             # Domain lists, config
├── extension/
│   ├── manifest.json             # Firefox extension manifest
│   ├── content/extractor.js      # DOM content extraction
│   ├── popup/
│   │   ├── popup.html            # Extension UI
│   │   ├── popup.css             # Dark industrial theme
│   │   └── popup.js              # Popup controller
│   └── icons/                    # Extension icons
├── tests/
│   └── test_claw.py              # 29 test cases
├── .github/workflows/ci.yml      # CI/CD pipeline
├── Dockerfile                    # Non-root container
├── docker-compose.yml            # OPA + Claw orchestration
├── requirements.txt              # Pinned Python deps
├── SECURITY.md                   # Security architecture
├── CONTRIBUTING.md               # Development guide
└── CHANGELOG.md                  # Version history
```

## Theoretical Foundation

Claw's argumentation engine is inspired by research on integrating formal argumentation theory with AI governance. The Rego-to-AAF bridge demonstrates that declarative policy languages (Rego/OPA) can be combined with argumentation-based conflict resolution (Dung, 1995) for principled policy decision-making under conflicting evidence.

**Key references:**
- Dung, P.M. (1995). "On the acceptability of arguments and its fundamental role in nonmonotonic reasoning, logic programming and n-person games." *Artificial Intelligence*, 77(2), 321-357.
- Open Policy Agent (OPA) — https://www.openpolicyagent.org/

## License

MIT

---

Built with the conviction that AI governance should be formal, auditable, and principled.
