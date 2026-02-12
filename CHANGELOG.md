# Changelog

## [0.2.0] - 2026-02-12

### Added
- **Knowledge Hub**: Persistent contextual memory with domain-scoped retrieval, temporal decay, and reputation scoring
- **Argumentation Engine**: ASPARTIX-inspired implementation of Dung's Abstract Argumentation Framework with grounded, preferred, and stable extension computation
- **Rego Bridge**: Converts OPA policy conflicts into formal argumentation frameworks for principled conflict resolution
- **API Key Authentication**: Bearer token auth with constant-time comparison (CLAW_API_KEYS)
- **Rate Limiting**: Per-IP token bucket rate limiter (30 req/min for /analyze)
- **Python Test Suite**: pytest coverage for PII scanner, argumentation engine, knowledge hub, and rego bridge
- **SECURITY.md**: Security policy and vulnerability disclosure process
- **CONTRIBUTING.md**: Contribution guidelines
- Knowledge Hub API endpoints: `/v1/knowledge/store`, `/v1/knowledge/query`, `/v1/knowledge/reputation/{domain}`, `/v1/knowledge/stats`
- Argumentation info in all pipeline responses
- CI/CD with GitHub Actions (OPA tests + Python tests + integration)

### Changed
- Pipeline upgraded from 4 stages to **6 stages** (added Knowledge Lookup and Argumentation Resolution)
- CORS restricted from wildcard to configurable allowlist (CLAW_CORS_ORIGINS)
- Dependencies pinned to exact versions
- Docker container runs as non-root user
- Docker Compose includes resource limits (memory/CPU)
- OPA image pinned to v0.70.0 (was :latest)
- Input validation enforced before processing

### Fixed
- CORS wildcard vulnerability (audit P0)
- Missing authentication (audit P0)
- Missing rate limiting (audit P0)
- Container running as root (audit warning)
- No CI/CD pipeline (audit P0)

## [0.1.0] - 2026-02-11

### Added
- Initial 4-stage pipeline (PII → OPA → Assembly → Inference)
- OPA integration with Rego policy packs (standard/finance/strict/research)
- PII scanner (SSN, CC, email, phone, IP)
- Firefox extension with governance UI
- Audit logging with hash chaining
- Docker Compose setup
