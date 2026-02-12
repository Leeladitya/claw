"""Argumentation engine — Dung's AAF for policy conflict resolution."""
from .engine import ArgumentationEngine
from .rego_bridge import RegoBridge
from .models import (
    Argument,
    ArgumentSource,
    Attack,
    AttackType,
    ArgumentationFramework,
    Extension,
    ResolutionResult,
    Semantics,
)

__all__ = [
    "ArgumentationEngine",
    "RegoBridge",
    "Argument",
    "ArgumentSource",
    "Attack",
    "AttackType",
    "ArgumentationFramework",
    "Extension",
    "ResolutionResult",
    "Semantics",
]
