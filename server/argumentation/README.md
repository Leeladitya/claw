# argumentation/ — The Debate Engine

## What This Is (for everyone)

When different parts of Claw disagree about what to do with content, this engine runs a formal debate. Each signal (PII found, domain trusted, policy says deny) becomes an **argument** with a strength score. Arguments can attack each other. The engine computes which set of arguments can stand together without contradicting each other — that's the winning position.

This is based on work by Phan Minh Dung (1995), who proved that formal argumentation can resolve conflicts in ways that are mathematically guaranteed to be consistent. Claw is one of the first systems to apply this to AI governance.

## What This Is (for developers)

**engine.py** — Implements Dung's characteristic function F(S) = {a ∈ Args | S defends a}. Computes grounded extension (polynomial, always used), preferred extensions (exponential worst-case, for tie-breaking), and stable extensions (completeness check).

**rego_bridge.py** — Converts OPA policy decisions, Knowledge Hub entries, and PII scan results into formal argumentation framework. Each Rego deny/modify/allow becomes an Argument with strength and attack relations.

**models.py** — Data classes: Argument, Attack, ArgumentationFramework, Extension, ResolutionResult.
