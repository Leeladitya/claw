"""
Argumentation Framework Models — Dung's Abstract Argumentation

Implements the formal structures from:
- Dung (1995): On the acceptability of arguments
- Bondarenko, Dung, Kowalski, Toni (1997): ABA framework
- Vedic-ABA integration for multi-constitutional reasoning

These models bridge formal argumentation theory with practical
policy conflict resolution in the Claw governance pipeline.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Semantics(str, Enum):
    """Argumentation semantics for extension computation."""
    GROUNDED = "grounded"
    PREFERRED = "preferred"
    STABLE = "stable"
    COMPLETE = "complete"


class ArgumentSource(str, Enum):
    """Origin of an argument in the resolution framework."""
    OPA_POLICY = "opa_policy"
    KNOWLEDGE_HUB = "knowledge_hub"
    PII_SCANNER = "pii_scanner"
    VEDIC_PRINCIPLE = "vedic_principle"
    DOMAIN_RULE = "domain_rule"
    TEMPORAL_CONTEXT = "temporal_context"


class AttackType(str, Enum):
    """Classification of attack relations between arguments."""
    REBUT = "rebut"          # Contradictory conclusions
    UNDERCUT = "undercut"    # Challenges inference rule
    UNDERMINE = "undermine"  # Challenges premise/assumption


@dataclass
class Argument:
    """
    An argument in Dung's abstract argumentation framework.

    In Claw's context, arguments represent policy decisions,
    knowledge-derived insights, or ethical principles that may
    conflict with each other during content evaluation.
    """
    id: str
    claim: str
    source: ArgumentSource
    strength: float = 1.0       # [0, 1] — weight for preference
    support: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        raw = f"{self.id}:{self.claim}:{self.source.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, Argument):
            return self.id == other.id
        return False

    def __repr__(self):
        return f"Arg({self.id}: {self.claim[:40]}...)"


@dataclass
class Attack:
    """
    An attack relation between two arguments.

    Following Dung (1995), if (a, b) is an attack, then argument 'a'
    attacks argument 'b'. The attack type classifies the nature of
    the conflict for audit and explanation purposes.
    """
    attacker: str   # argument id
    target: str     # argument id
    attack_type: AttackType = AttackType.REBUT
    reason: str = ""

    def __hash__(self):
        return hash((self.attacker, self.target))

    def __eq__(self, other):
        if isinstance(other, Attack):
            return (self.attacker == self.target and
                    self.target == other.target)
        return False


@dataclass
class Extension:
    """
    A set of arguments that are collectively acceptable under
    a given semantics.

    The grounded extension is unique and represents the most
    cautious/skeptical position. Preferred extensions maximize
    defended arguments. Stable extensions ensure every non-member
    is attacked.
    """
    arguments: set[str] = field(default_factory=set)
    semantics: Semantics = Semantics.GROUNDED
    is_empty: bool = False

    @property
    def size(self) -> int:
        return len(self.arguments)


@dataclass
class ArgumentationFramework:
    """
    Dung's Abstract Argumentation Framework (AAF).

    AF = (Args, Attacks) where:
    - Args is a finite set of arguments
    - Attacks ⊆ Args × Args is a binary attack relation

    This is the core data structure that the engine operates on.
    """
    arguments: dict[str, Argument] = field(default_factory=dict)
    attacks: list[Attack] = field(default_factory=list)

    def add_argument(self, arg: Argument) -> None:
        self.arguments[arg.id] = arg

    def add_attack(self, attacker_id: str, target_id: str,
                   attack_type: AttackType = AttackType.REBUT,
                   reason: str = "") -> None:
        if attacker_id in self.arguments and target_id in self.arguments:
            self.attacks.append(Attack(
                attacker=attacker_id,
                target=target_id,
                attack_type=attack_type,
                reason=reason,
            ))

    def get_attackers(self, arg_id: str) -> set[str]:
        """Get all arguments that attack the given argument."""
        return {a.attacker for a in self.attacks if a.target == arg_id}

    def get_attacked(self, arg_id: str) -> set[str]:
        """Get all arguments attacked by the given argument."""
        return {a.target for a in self.attacks if a.attacker == arg_id}

    def is_attacked_by(self, arg_id: str, candidate: set[str]) -> bool:
        """Check if arg_id is attacked by any member of candidate set."""
        attackers = self.get_attackers(arg_id)
        return bool(attackers & candidate)

    def is_defended_by(self, arg_id: str, candidate: set[str]) -> bool:
        """
        Check if candidate defends arg_id.
        arg_id is defended by S if for every attacker of arg_id,
        there exists a member of S that attacks the attacker.
        """
        attackers = self.get_attackers(arg_id)
        for attacker in attackers:
            attacker_attackers = self.get_attackers(attacker)
            if not (attacker_attackers & candidate):
                return False
        return True

    @property
    def arg_ids(self) -> set[str]:
        return set(self.arguments.keys())

    def to_dict(self) -> dict:
        return {
            "arguments": [
                {
                    "id": a.id,
                    "claim": a.claim,
                    "source": a.source.value,
                    "strength": a.strength,
                }
                for a in self.arguments.values()
            ],
            "attacks": [
                {
                    "attacker": a.attacker,
                    "target": a.target,
                    "type": a.attack_type.value,
                    "reason": a.reason,
                }
                for a in self.attacks
            ],
            "stats": {
                "num_arguments": len(self.arguments),
                "num_attacks": len(self.attacks),
            },
        }


@dataclass
class ResolutionResult:
    """
    The output of argumentation resolution applied to a
    Claw policy evaluation context.
    """
    decision: str                   # allow | allow_with_modifications | deny
    winning_arguments: list[str]    # ids of arguments in the extension
    defeated_arguments: list[str]   # ids of arguments not in extension
    semantics_used: Semantics
    framework_summary: dict         # compact AF representation
    resolution_time_ms: float = 0.0
    explanation: str = ""           # human-readable reasoning chain
