"""
Argumentation Engine — Dung's Extension Computation

Implements the core algorithms from Dung (1995) for computing:
- Grounded extension (unique, most skeptical)
- Preferred extensions (maximal complete)
- Stable extensions (complete + attacks all outsiders)

Applied in Claw to resolve policy conflicts when:
- Multiple OPA rules produce contradictory decisions
- Knowledge Hub context conflicts with policy decisions
- Temporal/contextual factors create ambiguity

Computational complexity:
- Grounded: O(|Args|³) — polynomial, always used first
- Preferred: O(2^|Args|) worst case — used only for tie-breaking
- Stable: O(2^|Args|) worst case — used for completeness verification

In practice, Claw's argumentation frameworks are small (5-20 args),
so all semantics compute in <1ms.
"""

from __future__ import annotations

import time
import logging
from itertools import combinations

from .models import (
    ArgumentationFramework,
    Extension,
    ResolutionResult,
    Semantics,
)

logger = logging.getLogger("claw.argumentation")


class ArgumentationEngine:
    """
    Core engine for computing argumentation extensions.

    Follows Dung's characteristic function F:
        F(S) = { a ∈ Args | S defends a }

    The grounded extension is the least fixpoint of F.
    """

    def __init__(self):
        self._cache: dict[str, Extension] = {}

    # ── Grounded Extension ──────────────────────────────────────

    def grounded_extension(self, af: ArgumentationFramework) -> Extension:
        """
        Compute the grounded extension via iterative fixpoint.

        Algorithm:
            S₀ = ∅
            Sₙ₊₁ = F(Sₙ) = { a | af defends a w.r.t. Sₙ }
            Stop when Sₙ₊₁ = Sₙ

        Returns the unique grounded extension.
        """
        current: set[str] = set()

        for _ in range(len(af.arguments) + 1):
            next_set: set[str] = set()
            for arg_id in af.arg_ids:
                if af.is_defended_by(arg_id, current):
                    # Also check arg is not attacked by current set member
                    if not af.is_attacked_by(arg_id, current):
                        next_set.add(arg_id)
                    elif af.is_defended_by(arg_id, current):
                        next_set.add(arg_id)

            # Include unattacked arguments (always in grounded)
            for arg_id in af.arg_ids:
                if not af.get_attackers(arg_id):
                    next_set.add(arg_id)

            if next_set == current:
                break
            current = next_set

        return Extension(
            arguments=current,
            semantics=Semantics.GROUNDED,
            is_empty=len(current) == 0,
        )

    # ── Admissible Sets ─────────────────────────────────────────

    def is_conflict_free(self, af: ArgumentationFramework,
                         candidate: set[str]) -> bool:
        """Check if no argument in candidate attacks another in candidate."""
        for attack in af.attacks:
            if attack.attacker in candidate and attack.target in candidate:
                return False
        return True

    def is_admissible(self, af: ArgumentationFramework,
                      candidate: set[str]) -> bool:
        """
        S is admissible iff:
        1. S is conflict-free
        2. S defends all its members
        """
        if not self.is_conflict_free(af, candidate):
            return False
        for arg_id in candidate:
            if not af.is_defended_by(arg_id, candidate):
                return False
        return True

    # ── Complete Extensions ─────────────────────────────────────

    def is_complete(self, af: ArgumentationFramework,
                    candidate: set[str]) -> bool:
        """
        S is complete iff S is admissible and contains every
        argument it defends.
        """
        if not self.is_admissible(af, candidate):
            return False
        for arg_id in af.arg_ids - candidate:
            if af.is_defended_by(arg_id, candidate):
                if not af.is_attacked_by(arg_id, candidate):
                    return False
        return True

    # ── Preferred Extensions ────────────────────────────────────

    def preferred_extensions(self, af: ArgumentationFramework) -> list[Extension]:
        """
        Compute all preferred (maximal admissible) extensions.

        Uses a top-down approach: start from full set, remove
        arguments until admissible, keep maximal ones.

        For small frameworks (<20 args), this is efficient.
        """
        all_args = af.arg_ids
        admissible_sets: list[set[str]] = []

        # Check all subsets — feasible for small frameworks
        # For larger ones, we'd use labelling algorithms
        n = len(all_args)
        if n > 20:
            logger.warning(
                f"Large framework ({n} args), falling back to grounded"
            )
            g = self.grounded_extension(af)
            return [g]

        arg_list = list(all_args)

        for size in range(n, -1, -1):
            for combo in combinations(arg_list, size):
                candidate = set(combo)
                if self.is_admissible(af, candidate):
                    admissible_sets.append(candidate)

        # Filter to maximal
        preferred: list[set[str]] = []
        for s in admissible_sets:
            is_maximal = True
            for other in admissible_sets:
                if s < other:  # strict subset
                    is_maximal = False
                    break
            if is_maximal and s not in preferred:
                preferred.append(s)

        if not preferred:
            preferred = [set()]

        return [
            Extension(
                arguments=p,
                semantics=Semantics.PREFERRED,
                is_empty=len(p) == 0,
            )
            for p in preferred
        ]

    # ── Stable Extensions ───────────────────────────────────────

    def stable_extensions(self, af: ArgumentationFramework) -> list[Extension]:
        """
        Compute all stable extensions.

        S is stable iff S is conflict-free and S attacks every
        argument not in S.
        """
        all_args = af.arg_ids
        stable: list[set[str]] = []

        n = len(all_args)
        if n > 20:
            logger.warning(
                f"Large framework ({n} args), falling back to grounded"
            )
            g = self.grounded_extension(af)
            return [g]

        arg_list = list(all_args)

        for size in range(n, -1, -1):
            for combo in combinations(arg_list, size):
                candidate = set(combo)
                if not self.is_conflict_free(af, candidate):
                    continue

                # Check: every arg NOT in candidate is attacked by candidate
                outsiders = all_args - candidate
                all_attacked = True
                for outsider in outsiders:
                    if not af.is_attacked_by(outsider, candidate):
                        all_attacked = False
                        break

                if all_attacked:
                    stable.append(candidate)

        return [
            Extension(
                arguments=s,
                semantics=Semantics.STABLE,
                is_empty=len(s) == 0,
            )
            for s in stable
        ]

    # ── Resolution for Claw Pipeline ────────────────────────────

    def resolve(
        self,
        af: ArgumentationFramework,
        semantics: Semantics = Semantics.GROUNDED,
    ) -> ResolutionResult:
        """
        Resolve a policy conflict using argumentation.

        Strategy:
        1. Always compute grounded first (polynomial, unique)
        2. If grounded is empty/insufficient, try preferred
        3. Use argument strength for tie-breaking

        Returns a ResolutionResult with the winning decision.
        """
        start = time.perf_counter()

        # Step 1: Grounded extension (always)
        grounded = self.grounded_extension(af)

        if semantics == Semantics.GROUNDED or grounded.size > 0:
            ext = grounded
        elif semantics == Semantics.PREFERRED:
            preferred = self.preferred_extensions(af)
            # Pick the preferred extension with highest aggregate strength
            ext = max(
                preferred,
                key=lambda e: sum(
                    af.arguments[a].strength
                    for a in e.arguments
                    if a in af.arguments
                ),
            )
        elif semantics == Semantics.STABLE:
            stable = self.stable_extensions(af)
            if stable:
                ext = max(
                    stable,
                    key=lambda e: sum(
                        af.arguments[a].strength
                        for a in e.arguments
                        if a in af.arguments
                    ),
                )
            else:
                ext = grounded
        else:
            ext = grounded

        elapsed = (time.perf_counter() - start) * 1000

        # Determine decision from winning arguments
        decision = self._extract_decision(af, ext)
        explanation = self._build_explanation(af, ext)

        winning = list(ext.arguments)
        defeated = list(af.arg_ids - ext.arguments)

        return ResolutionResult(
            decision=decision,
            winning_arguments=winning,
            defeated_arguments=defeated,
            semantics_used=ext.semantics,
            framework_summary=af.to_dict(),
            resolution_time_ms=round(elapsed, 3),
            explanation=explanation,
        )

    def _extract_decision(self, af: ArgumentationFramework,
                          ext: Extension) -> str:
        """
        Extract a Claw decision from the winning extension.

        Priority: deny > allow_with_modifications > allow
        If any winning argument says 'deny', we deny.
        """
        if ext.is_empty:
            return "allow"  # No conflicts, default allow

        decisions = []
        for arg_id in ext.arguments:
            arg = af.arguments.get(arg_id)
            if arg and "decision" in arg.metadata:
                decisions.append(arg.metadata["decision"])

        if "deny" in decisions:
            return "deny"
        if "allow_with_modifications" in decisions:
            return "allow_with_modifications"
        return "allow"

    def _build_explanation(self, af: ArgumentationFramework,
                           ext: Extension) -> str:
        """Build a human-readable explanation of the resolution."""
        if ext.is_empty:
            return "No conflicts detected; all arguments are mutually acceptable."

        parts = []
        for arg_id in ext.arguments:
            arg = af.arguments.get(arg_id)
            if arg:
                defeated_by_this = af.get_attacked(arg_id) - ext.arguments
                if defeated_by_this:
                    targets = ", ".join(defeated_by_this)
                    parts.append(
                        f"[{arg.source.value}] '{arg.claim}' "
                        f"prevails over: {targets}"
                    )
                else:
                    parts.append(
                        f"[{arg.source.value}] '{arg.claim}' accepted (uncontested)"
                    )

        return " | ".join(parts) if parts else "Resolution computed."
