# Changelog

## [0.3.0] - 2026-02-14

### Added
- **SDAM Model**: Powell's Sequential Decision Analytics framework applied to governance scenarios
  - GovernanceState mapping Powell's S_t = (R_t, I_t, B_t) to CISO decision state
  - PFA Policy (threshold rules) and CFA Policy (parameterized optimization) implementations
  - Monte Carlo simulation engine with configurable seeds
  - Policy search via grid optimization over θ parameters
  - Community data integration: load_arena_export() and batch_analyze_exports()
  - CFA outperforms PFA in 200/200 Monte Carlo simulations (52.86 vs 48.37 avg score)
- **Expanded OPA Policies**: 12 deny rules (was 7), 5 modification rules (was 2)
  - Healthcare policy pack with PHI keyword blocking and aggregate PII detection
  - Finance domain enforcement (allowlist-only for financial pack)
  - Content volume threshold (50K word max)
  - Bearer/access/refresh token credential detection
  - Community scenario schema validation
  - Risk score computation for argumentation bridge
  - Policy metadata output for argumentation engine
- **20 OPA test cases** (was 10)
- **Folder README files**: dual-audience documentation (everyone + developers) for server/, argumentation/, knowledge/, opa/, extension/, tests/
- **community_data/ directory**: Arena game export collection with analysis instructions

### Changed
- Version bump from 0.2.0 to 0.3.0
- data.json expanded with healthcare domain allowlist

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
