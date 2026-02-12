# Contributing to Claw

## Development Setup

```bash
git clone https://github.com/Leeladitya/claw.git
cd claw
pip install -r requirements.txt
```

## Running Tests

```bash
# Python tests
pytest tests/ -v

# OPA policy tests (requires opa binary)
opa test opa/policies/ opa/data/ -v

# Lint
ruff check server/ tests/
```

## Architecture

Claw uses a 6-stage pipeline:

1. **PII Scan** → `server/middleware/pii_scanner.py`
2. **OPA Policy Gate** → `server/middleware/opa_client.py` + `opa/policies/main.rego`
3. **Knowledge Hub Lookup** → `server/knowledge/hub.py`
4. **Argumentation Resolution** → `server/argumentation/engine.py`
5. **Context Assembly** → `server/app.py`
6. **Model Inference** → `server/app.py`

## Adding New Features

- **New PII pattern**: Add regex to `server/middleware/pii_scanner.py`, add test
- **New policy rule**: Add Rego rule to `opa/policies/main.rego`, add test to `main_test.rego`
- **New knowledge entry type**: Add to `server/knowledge/models.py`
- **New argumentation logic**: Extend `server/argumentation/engine.py`

## Pull Request Process

1. Fork and create a feature branch
2. Add tests for new functionality
3. Ensure `pytest` and `opa test` pass
4. Ensure `ruff check` passes
5. Submit PR with clear description

## Code Style

- Python: Follow ruff defaults, type hints required
- Rego: Use `import rego.v1`, descriptive rule names
- JS: No framework dependencies in extension
