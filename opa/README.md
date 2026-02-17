# opa/ — Policy Rules

## What This Is (for everyone)

This folder contains the rules that Claw follows. They're written in a language called Rego (by Open Policy Agent) that reads almost like English:

- "If the domain is on the blocklist, deny."
- "If a Social Security Number is detected, deny."
- "If emails are found, allow but redact them first."

There are 6 policy packs for different situations:
- **standard** — balanced protection, good default
- **strict** — only approved websites allowed
- **research** — relaxed rules for academic work
- **finance** — financial-sector controls
- **healthcare** — medical data protection (HIPAA-aligned)
- **community** — Arena scenario contribution validation

You can read every rule in `policies/main.rego` — there are no hidden rules.

## What This Is (for developers)

**policies/main.rego** — 12 deny rules, 5 modification rules, risk scoring, policy metadata output. All rules produce reason strings consumed by rego_bridge.py.

**policies/main_test.rego** — 20 test cases. Run: `opa test opa/policies/ opa/data/ -v`

**data/data.json** — Domain blocklists, allowlists, internal patterns. Editable configuration.

### Adding New Rules

1. Add a new `deny_reasons contains reason if { ... }` or `modification_list contains mod if { ... }` block
2. Add a corresponding test in `main_test.rego`
3. Run tests: `opa test opa/policies/ opa/data/ -v`
4. The rego_bridge.py will automatically convert your new rule's output into an argumentation argument
