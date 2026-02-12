# Security Policy

## Supported Versions

|Version|Supported|
|-|-|
|0.2.x|✅ Active|
|0.1.x|❌ EOL|

## Reporting Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Email: security@saatvix.com

Include:

* Description of the vulnerability
* Steps to reproduce
* Impact assessment
* Suggested fix (if any)

Response timeline:

* Acknowledgment: 48 hours
* Initial assessment: 5 business days
* Fix timeline: depends on severity

## Security Architecture

Claw treats the browser extension as an **untrusted input source**. All security enforcement is server-side:

1. **API Key Authentication** — Bearer token with constant-time comparison
2. **Rate Limiting** — Per-IP token bucket (30 req/min for /analyze)
3. **CORS Restriction** — Configurable origin allowlist (not wildcard)
4. **Input Validation** — Content size limits enforced before processing
5. **PII Masking** — Sensitive data redacted before model inference
6. **OPA Policy Gate** — Declarative ABAC controls via Rego
7. **Argumentation Resolution** — Formal conflict resolution for ambiguous decisions
8. **Audit Logging** — Append-only JSONL with SHA-256 hash chaining

## Known Limitations

* PII scanner uses regex patterns (no ML-based NER yet)
* OPA runs as sidecar (not embedded — Go rewrite planned)
* Knowledge Hub stores data locally (no encryption at rest yet)
* No TLS configured by default (use reverse proxy for production)
