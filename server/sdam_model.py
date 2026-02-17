"""
Claw Sequential Decision Model for AI Governance
==================================================

Built on Powell's Sequential Decision Analytics and Modeling (SDAM) framework
from Princeton University (Powell, 2022).

WHAT THIS DOES (for everyone):
    Imagine a security chief facing a crisis. Every few minutes, new
    information arrives and they must decide: escalate? investigate?
    wait? Each choice changes what happens next. This model captures
    that entire decision chain mathematically — so we can study which
    decision *strategies* (called "policies") lead to the best outcomes
    across thousands of simulated crises.

    Think of it like a flight simulator for governance decisions.

HOW IT CONNECTS TO POWELL'S FRAMEWORK:
    Powell identifies 5 elements in ANY sequential decision problem:
    1. State variables (S_t) — everything you know right now
    2. Decision variables (x_t) — what you choose to do
    3. Exogenous information (W_t+1) — new info that arrives after you decide
    4. Transition function S^M — how your state changes based on decisions + info
    5. Objective function — what you're trying to maximize/minimize

    And 4 universal classes of policies (strategies for deciding):
    - PFA: Policy Function Approximation — simple rules (if X > threshold, do Y)
    - CFA: Cost Function Approximation — optimize a parameterized formula
    - VFA: Value Function Approximation — estimate future value of each state
    - DLA: Direct Lookahead Approximation — simulate the future before deciding

    This model implements all 5 elements and demonstrates PFA and CFA policies
    applied to the CISO governance domain.

WHY THIS MATTERS FOR AGORA:
    Every time someone plays the Decision Arena game, their choices become
    data. This model can ingest that data, simulate thousands of variations,
    and identify which governance strategies perform best under uncertainty.
    The community doesn't just play — they contribute to a formal study of
    sequential governance under pressure.

References:
    Powell, W.B. (2022). Sequential Decision Analytics and Modeling:
    Modeling with Python. Foundations and Trends in Technology,
    Information and Operations Management.

    Dung, P.M. (1995). On the acceptability of arguments and its
    fundamental role in nonmonotonic reasoning, logic programming
    and n-person games. Artificial Intelligence, 77(2), 321-357.
"""

from __future__ import annotations

import json
import math
import random
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from pathlib import Path

logger = logging.getLogger("agora.sdam")


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ELEMENT 1: STATE VARIABLES (S_t)                              ║
# ║                                                                ║
# ║  "Everything you know at time t."                              ║
# ║                                                                ║
# ║  Powell divides state into three types:                        ║
# ║  - R_t (Physical/Resource state): tangible things you have     ║
# ║  - I_t (Informational state): facts you've observed            ║
# ║  - B_t (Belief state): your current estimates of unknowns      ║
# ╚══════════════════════════════════════════════════════════════════╝

@dataclass
class GovernanceState:
    """
    The complete state of a governance decision at time t.

    FOR EVERYONE:
        This is everything the decision-maker knows at one moment in time.
        Threat level, sensor status, how much time is left, what arguments
        are currently winning — all of it captured in one snapshot.

    FOR RESEARCHERS:
        Maps to Powell's S_t = (R_t, I_t, B_t) where:
        - R_t (resource): time_remaining, escalation_level, staff_available
        - I_t (informational): threat_confidence, cyber_detected, sensor_integrity,
                               forensic_status, secondary_data
        - B_t (belief): estimated_threat_probability, arg_strengths
    """

    # ── R_t: Resource state ──
    time_remaining: float        # seconds left in decision window
    escalation_level: int        # 0=normal, 1=elevated, 2=crisis, 3=full escalation
    staff_available: int         # how many people can work on this right now

    # ── I_t: Informational state ──
    threat_confidence: float     # AI system's reported confidence (0-1)
    cyber_detected: bool         # has a cyber intrusion been detected?
    sensor_integrity: float      # how much we trust the sensors (0=compromised, 1=clean)
    forensic_status: str         # "none", "in_progress", "confirmed_attack", "confirmed_clean"
    secondary_data: Optional[str]  # "corroborates", "contradicts", "partial", None

    # ── B_t: Belief state ──
    estimated_threat_prob: float  # our *actual* estimate of real threat (may differ from AI)
    arg_strengths: dict = field(default_factory=dict)  # argument_id -> current strength

    # ── Derived (for policy computation) ──
    stage: int = 0               # which decision point we're at
    decision_history: list = field(default_factory=list)  # past decisions for consistency

    def to_vector(self) -> list[float]:
        """
        Flatten state into a numerical vector for policy computation.

        WHY: Policies like VFA need numerical features. This converts
        our rich state into numbers that mathematical formulas can use.
        """
        return [
            self.time_remaining / 720,     # normalize to [0,1] over 12 min
            self.escalation_level / 3,
            self.staff_available / 20,
            self.threat_confidence,
            float(self.cyber_detected),
            self.sensor_integrity,
            {"none": 0, "in_progress": 0.3, "confirmed_attack": 0.8, "confirmed_clean": 1.0}
                .get(self.forensic_status, 0),
            0.0 if self.secondary_data is None else
                {"corroborates": 1.0, "contradicts": -1.0, "partial": 0.3}
                .get(self.secondary_data, 0),
            self.estimated_threat_prob,
            float(self.stage) / 3,
        ]


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ELEMENT 2: DECISION VARIABLES (x_t)                           ║
# ║                                                                ║
# ║  "What you choose to do."                                      ║
# ║                                                                ║
# ║  At each stage, the CISO picks one action from a finite set.   ║
# ║  Decisions must satisfy constraints: x_t ∈ X(S_t)              ║
# ║  (you can only choose actions that are feasible given state)   ║
# ╚══════════════════════════════════════════════════════════════════╝

class Decision(Enum):
    """
    Possible actions at any decision point.

    FOR EVERYONE:
        These are the buttons the decision-maker can press.
        Not every button is available at every stage —
        that depends on the current state.
    """
    ESCALATE = "escalate"
    INVESTIGATE = "investigate"
    PARALLEL = "parallel"
    ISOLATE = "isolate"
    DOWNGRADE = "downgrade"
    MAINTAIN = "maintain"
    PETROV_CALL = "petrov_call"
    STAND_DOWN = "stand_down"
    ESCALATE_BOTH = "escalate_both"
    CALL_ALLIED = "call_allied"
    TIMEOUT = "timeout"


# Which decisions are available at each stage
STAGE_ACTIONS: dict[int, list[Decision]] = {
    0: [Decision.ESCALATE, Decision.INVESTIGATE, Decision.PARALLEL, Decision.ISOLATE],
    1: [Decision.DOWNGRADE, Decision.MAINTAIN, Decision.PETROV_CALL],
    2: [Decision.STAND_DOWN, Decision.ESCALATE_BOTH, Decision.CALL_ALLIED],
}


def feasible_actions(state: GovernanceState) -> list[Decision]:
    """
    X(S_t): The set of feasible actions given current state.

    FOR EVERYONE:
        If time has run out, you can only do "timeout" (forced default).
        Otherwise, you pick from the actions available at your stage.
    """
    if state.time_remaining <= 0:
        return [Decision.TIMEOUT]
    return STAGE_ACTIONS.get(state.stage, [])


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ELEMENT 3: EXOGENOUS INFORMATION (W_t+1)                      ║
# ║                                                                ║
# ║  "New info that arrives AFTER you decide, BEFORE next stage."  ║
# ║                                                                ║
# ║  This is the uncertainty. You can't control it. It's what      ║
# ║  makes governance hard: reality keeps changing on you.          ║
# ╚══════════════════════════════════════════════════════════════════╝

@dataclass
class ExogenousInfo:
    """
    Random information that arrives between decisions.

    FOR EVERYONE:
        After you make a choice, the world responds. A satellite sends
        new data. Forensics come back. The AI updates its confidence.
        None of this was known when you decided. That's what makes
        sequential decisions under uncertainty so challenging.

    FOR RESEARCHERS:
        W_t+1 is drawn from a probability distribution that may depend
        on the current state S_t and the decision x_t. This is the
        stochastic element that makes governance a sequential decision
        problem rather than a static optimization.
    """
    ai_confidence_update: float          # new AI confidence level
    secondary_satellite: Optional[str]   # "corroborates", "contradicts", "partial", None
    forensic_result: Optional[str]       # "confirmed_attack", "confirmed_clean", None
    sensor_integrity_change: float       # delta to sensor integrity
    time_consumed: float                 # how much time the previous decision burned


def generate_exogenous(state: GovernanceState, decision: Decision, rng: random.Random) -> ExogenousInfo:
    """
    Generate random information based on current state and decision.

    FOR EVERYONE:
        This is the "world responding" to your choice. If you chose
        to investigate, forensic results are more likely to arrive.
        If you escalated, the AI confidence might not change much
        because you didn't look deeper.

    FOR RESEARCHERS:
        W_t+1 ~ P(· | S_t, x_t). The distribution of exogenous info
        depends on both state and action — investigating speeds up
        forensic results, escalating consumes more time, etc.
    """

    # AI confidence drifts upward (the system is designed to escalate)
    ai_delta = rng.gauss(0.02, 0.03)
    new_confidence = min(0.99, max(0.5, state.threat_confidence + ai_delta))

    # Time consumed depends on action
    time_map = {
        Decision.ESCALATE: 240,
        Decision.INVESTIGATE: 300,
        Decision.PARALLEL: 240,
        Decision.ISOLATE: 180,
        Decision.DOWNGRADE: 120,
        Decision.MAINTAIN: 180,
        Decision.PETROV_CALL: 120,
        Decision.STAND_DOWN: 0,
        Decision.ESCALATE_BOTH: 0,
        Decision.CALL_ALLIED: 0,
        Decision.TIMEOUT: 180,
    }
    time_consumed = time_map.get(decision, 180)

    # Secondary satellite data — more likely to arrive at stage 1+
    secondary = None
    if state.stage >= 1 and rng.random() < 0.7:
        # In the actual scenario, the real threat is FALSE (it's a cyber attack)
        # So secondary satellite is more likely to contradict
        secondary = rng.choices(
            ["contradicts", "partial", "corroborates"],
            weights=[0.6, 0.25, 0.15]
        )[0]

    # Forensic results — more likely if we investigated
    forensic = None
    if decision in (Decision.INVESTIGATE, Decision.ISOLATE, Decision.PARALLEL):
        if rng.random() < 0.6:  # investigation yields results
            forensic = rng.choices(
                ["confirmed_attack", "confirmed_clean"],
                weights=[0.85, 0.15]  # it IS a cyber attack in the base scenario
            )[0]

    # Sensor integrity degrades if compromised and not isolated
    integrity_delta = 0.0
    if state.cyber_detected and decision != Decision.ISOLATE:
        integrity_delta = -rng.uniform(0.05, 0.15)

    return ExogenousInfo(
        ai_confidence_update=new_confidence,
        secondary_satellite=secondary,
        forensic_result=forensic,
        sensor_integrity_change=integrity_delta,
        time_consumed=time_consumed,
    )


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ELEMENT 4: TRANSITION FUNCTION S^M(S_t, x_t, W_t+1)          ║
# ║                                                                ║
# ║  "How the world changes based on your decision + new info."    ║
# ║                                                                ║
# ║  This is the core dynamics. Given where you are, what you did, ║
# ║  and what new info arrived, this computes where you end up.    ║
# ╚══════════════════════════════════════════════════════════════════╝

def transition(state: GovernanceState, decision: Decision, info: ExogenousInfo) -> GovernanceState:
    """
    S_{t+1} = S^M(S_t, x_t, W_{t+1})

    FOR EVERYONE:
        You were in one situation, you made a choice, new info arrived,
        and now you're in a NEW situation. This function computes that
        new situation precisely. Every element of the state gets updated.

    FOR RESEARCHERS:
        The transition function updates all three state components:
        - R_t → R_{t+1}: time decreases, escalation may change
        - I_t → I_{t+1}: threat confidence updates, forensics arrive
        - B_t → B_{t+1}: beliefs about true threat probability update
    """

    # ── Update resource state (R_t) ──
    new_time = max(0, state.time_remaining - info.time_consumed)

    # Escalation level changes based on decision
    esc_map = {
        Decision.ESCALATE: min(3, state.escalation_level + 2),
        Decision.PARALLEL: min(3, state.escalation_level + 1),
        Decision.ESCALATE_BOTH: 3,
        Decision.DOWNGRADE: max(0, state.escalation_level - 1),
        Decision.STAND_DOWN: 0,
        Decision.PETROV_CALL: 0,
    }
    new_esc = esc_map.get(decision, state.escalation_level)

    # ── Update informational state (I_t) ──
    new_integrity = max(0.0, min(1.0, state.sensor_integrity + info.sensor_integrity_change))

    new_forensic = state.forensic_status
    if info.forensic_result is not None:
        new_forensic = info.forensic_result
    elif decision in (Decision.INVESTIGATE, Decision.PARALLEL) and state.forensic_status == "none":
        new_forensic = "in_progress"

    new_secondary = info.secondary_satellite if info.secondary_satellite else state.secondary_data

    # ── Update belief state (B_t) ──
    # Bayesian-inspired update of our TRUE estimate of threat probability
    # Based on: what does the evidence actually suggest?
    new_prob = state.estimated_threat_prob

    # If forensics confirmed cyber attack → threat prob drops sharply
    if new_forensic == "confirmed_attack":
        new_prob *= 0.15  # strong evidence it's fake

    # If secondary satellite contradicts → threat prob drops
    if new_secondary == "contradicts":
        new_prob *= 0.4

    # If secondary corroborates → threat prob rises
    if new_secondary == "corroborates":
        new_prob = min(0.99, new_prob * 1.5)

    # AI confidence rising WITHOUT supporting evidence → suspicious
    if info.ai_confidence_update > state.threat_confidence and new_integrity < 0.5:
        new_prob *= 0.8  # compromised sensor + rising confidence = manipulation

    # Clamp
    new_prob = max(0.01, min(0.99, new_prob))

    # ── Update argumentation strengths ──
    new_args = dict(state.arg_strengths)

    # Decision-specific argument impacts
    if decision == Decision.INVESTIGATE:
        new_args["evidence_based"] = new_args.get("evidence_based", 0.5) + 0.2
        new_args["ai_confidence"] = new_args.get("ai_confidence", 0.7) - 0.1
    elif decision == Decision.ESCALATE:
        new_args["duty_to_report"] = new_args.get("duty_to_report", 0.5) + 0.3
        new_args["proportionality"] = new_args.get("proportionality", 0.5) - 0.2
    elif decision == Decision.ISOLATE:
        new_args["clean_data"] = new_args.get("clean_data", 0.5) + 0.3
        new_args["ai_confidence"] = new_args.get("ai_confidence", 0.7) - 0.3
    elif decision == Decision.STAND_DOWN:
        new_args["forensic_evidence"] = new_args.get("forensic_evidence", 0.5) + 0.4

    return GovernanceState(
        time_remaining=new_time,
        escalation_level=new_esc,
        staff_available=state.staff_available,
        threat_confidence=info.ai_confidence_update,
        cyber_detected=state.cyber_detected,
        sensor_integrity=new_integrity,
        forensic_status=new_forensic,
        secondary_data=new_secondary,
        estimated_threat_prob=new_prob,
        arg_strengths=new_args,
        stage=state.stage + 1,
        decision_history=state.decision_history + [decision.value],
    )


# ╔══════════════════════════════════════════════════════════════════╗
# ║  ELEMENT 5: OBJECTIVE FUNCTION                                 ║
# ║                                                                ║
# ║  "What are you trying to achieve?"                             ║
# ║                                                                ║
# ║  Powell writes: max_π E{ Σ C(S_t, X^π(S_t)) | S_0 }          ║
# ║  We maximize total governance quality across all stages.       ║
# ╚══════════════════════════════════════════════════════════════════╝

def contribution(state: GovernanceState, decision: Decision) -> dict[str, float]:
    """
    C(S_t, x_t): The contribution (reward) of taking decision x_t in state S_t.

    FOR EVERYONE:
        Each decision earns or loses points across 5 governance dimensions.
        A good decision in a crisis scores high. A panicked overreaction
        or a dangerous delay scores low. The total across all stages is
        your governance performance.

    FOR RESEARCHERS:
        Multi-dimensional contribution function. In Powell's framework,
        this is typically scalar, but governance requires multi-criteria
        evaluation. We compute a weighted sum for the scalar objective
        but preserve the breakdown for interpretability.
    """
    scores = {
        "consistency": 0.0,
        "proportionality": 0.0,
        "reversibility": 0.0,
        "auditability": 0.0,
        "epistemic_rigor": 0.0,
    }

    # ── Proportionality: is your response proportional to the actual threat? ──
    # High threat + escalate = proportional. Low threat + escalate = overreaction.
    if decision in (Decision.ESCALATE, Decision.ESCALATE_BOTH):
        scores["proportionality"] = state.estimated_threat_prob * 30
    elif decision in (Decision.INVESTIGATE, Decision.PARALLEL):
        scores["proportionality"] = 20  # always somewhat proportional
    elif decision in (Decision.STAND_DOWN, Decision.DOWNGRADE, Decision.PETROV_CALL):
        scores["proportionality"] = (1.0 - state.estimated_threat_prob) * 30

    # ── Reversibility: can you undo this? ──
    reversibility_map = {
        Decision.ESCALATE: 5, Decision.INVESTIGATE: 25, Decision.PARALLEL: 25,
        Decision.ISOLATE: 15, Decision.DOWNGRADE: 20, Decision.MAINTAIN: 20,
        Decision.PETROV_CALL: 5, Decision.STAND_DOWN: 10,
        Decision.ESCALATE_BOTH: 8, Decision.CALL_ALLIED: 20, Decision.TIMEOUT: 0,
    }
    scores["reversibility"] = reversibility_map.get(decision, 10)

    # ── Auditability: did you gather evidence before deciding? ──
    evidence_actions = {Decision.INVESTIGATE, Decision.PARALLEL, Decision.CALL_ALLIED}
    if decision in evidence_actions:
        scores["auditability"] = 25
    elif state.forensic_status in ("confirmed_attack", "confirmed_clean"):
        scores["auditability"] = 20  # acting on evidence
    else:
        scores["auditability"] = 8

    # ── Epistemic rigor: did you prioritize verified knowledge? ──
    if decision == Decision.INVESTIGATE:
        scores["epistemic_rigor"] = 28
    elif decision == Decision.ISOLATE:
        scores["epistemic_rigor"] = 22
    elif decision == Decision.CALL_ALLIED:
        scores["epistemic_rigor"] = 25
    elif decision == Decision.PETROV_CALL:
        scores["epistemic_rigor"] = 15  # human judgment, less formal
    else:
        scores["epistemic_rigor"] = 10

    # ── Consistency: does this follow from your previous decisions? ──
    if len(state.decision_history) > 0:
        prev = state.decision_history[-1]
        # Coherent pairs get bonuses
        coherent = {
            "investigate": {"downgrade", "stand_down", "call_allied", "petrov_call"},
            "parallel": {"maintain", "escalate_both", "downgrade"},
            "escalate": {"maintain", "escalate_both"},
            "isolate": {"downgrade", "stand_down"},
        }
        if prev in coherent and decision.value in coherent[prev]:
            scores["consistency"] = 25
        else:
            scores["consistency"] = 10
    else:
        scores["consistency"] = 15  # first decision, neutral

    return scores


def scalar_contribution(state: GovernanceState, decision: Decision) -> float:
    """
    Weighted scalar version of the contribution function.
    Used by policies that need a single number to optimize.
    """
    s = contribution(state, decision)
    weights = {
        "consistency": 0.15,
        "proportionality": 0.25,
        "reversibility": 0.20,
        "auditability": 0.20,
        "epistemic_rigor": 0.20,
    }
    return sum(s[k] * weights[k] for k in s)


# ╔══════════════════════════════════════════════════════════════════╗
# ║  POLICIES: How to make decisions                               ║
# ║                                                                ║
# ║  Powell's 4 universal classes:                                 ║
# ║  - PFA: Policy Function Approximation (rule-based)             ║
# ║  - CFA: Cost Function Approximation (optimize formula)         ║
# ║  - VFA: Value Function Approximation (estimate future value)   ║
# ║  - DLA: Direct Lookahead (simulate ahead)                      ║
# ║                                                                ║
# ║  We implement PFA and CFA here. VFA and DLA are natural        ║
# ║  extensions once community data provides training signal.      ║
# ╚══════════════════════════════════════════════════════════════════╝

class PFAPolicy:
    """
    Policy Function Approximation: simple threshold rules.

    FOR EVERYONE:
        This is the "gut feeling" approach — a set of if/then rules.
        "If AI confidence > 90% AND no independent confirmation, investigate."
        Simple, fast, easy to explain. The thresholds can be tuned.

    FOR RESEARCHERS:
        PFA: X^π(S_t | θ) is an analytical function mapping state to action.
        No embedded optimization. Parameters θ are tuned via policy search.
        See Powell Ch. 7, Eq. (7.7)-(7.8).
    """

    def __init__(self, theta: dict = None):
        """
        theta: tunable parameters for the policy rules.
            - confidence_threshold: above this, lean toward escalation
            - integrity_threshold: below this, don't trust sensors
            - time_urgency: below this time fraction, act fast
        """
        self.theta = theta or {
            "confidence_threshold": 0.90,
            "integrity_threshold": 0.5,
            "time_urgency": 0.25,
        }

    def decide(self, state: GovernanceState) -> Decision:
        """X^π(S_t | θ) — map state to action using threshold rules."""
        actions = feasible_actions(state)
        if len(actions) == 1:
            return actions[0]

        stage = state.stage
        conf = state.threat_confidence
        integrity = state.sensor_integrity
        time_frac = state.time_remaining / 720  # fraction of 12 min left

        if stage == 0:
            # Stage 1: Initial response
            if conf > self.theta["confidence_threshold"] and integrity > self.theta["integrity_threshold"]:
                return Decision.ESCALATE  # high confidence + clean sensors → escalate
            elif state.cyber_detected and integrity < self.theta["integrity_threshold"]:
                return Decision.INVESTIGATE  # compromised sensors → check first
            elif time_frac < self.theta["time_urgency"]:
                return Decision.ESCALATE  # running out of time
            else:
                return Decision.PARALLEL  # hedge

        elif stage == 1:
            # Stage 2: After initial info
            if state.secondary_data == "contradicts":
                return Decision.DOWNGRADE
            elif conf > self.theta["confidence_threshold"]:
                return Decision.MAINTAIN
            else:
                return Decision.PETROV_CALL

        elif stage == 2:
            # Stage 3: Final decision
            if state.forensic_status == "confirmed_attack":
                return Decision.STAND_DOWN
            elif state.forensic_status == "confirmed_clean":
                return Decision.ESCALATE_BOTH
            else:
                return Decision.CALL_ALLIED

        return actions[0]


class CFAPolicy:
    """
    Cost Function Approximation: optimize a parameterized score.

    FOR EVERYONE:
        Instead of simple rules, this approach scores every possible
        action using a formula, then picks the highest-scoring one.
        The formula has tunable weights — how much do you value
        caution vs. speed? Evidence vs. duty?

    FOR RESEARCHERS:
        CFA: X^π(S_t | θ) = argmax_x { Σ θ_f · φ_f(S_t, x) }
        where φ_f are features and θ are tunable weights.
        See Powell Ch. 7, Eq. (7.1), Section 7.1 on CFAs.
    """

    def __init__(self, theta: dict = None):
        """
        theta: weights for different scoring features.
            - w_evidence: weight for evidence-seeking actions
            - w_caution: weight for reversible actions
            - w_duty: weight for escalation/reporting duty
            - w_speed: weight for actions that preserve time
        """
        self.theta = theta or {
            "w_evidence": 0.35,
            "w_caution": 0.25,
            "w_duty": 0.20,
            "w_speed": 0.20,
        }

    def _score_action(self, state: GovernanceState, action: Decision) -> float:
        """
        Compute parameterized score: Σ θ_f · φ_f(S_t, x)

        Features φ_f capture different governance values.
        Weights θ_f determine how much each value matters.
        """
        features = {}

        # φ_evidence: does this action seek/use evidence?
        evidence_map = {
            Decision.INVESTIGATE: 1.0, Decision.PARALLEL: 0.7, Decision.CALL_ALLIED: 0.9,
            Decision.ISOLATE: 0.6, Decision.DOWNGRADE: 0.5, Decision.STAND_DOWN: 0.8,
            Decision.ESCALATE: 0.1, Decision.MAINTAIN: 0.2, Decision.PETROV_CALL: 0.3,
            Decision.ESCALATE_BOTH: 0.4, Decision.TIMEOUT: 0.0,
        }
        features["evidence"] = evidence_map.get(action, 0.3)

        # φ_caution: is this action reversible?
        caution_map = {
            Decision.PARALLEL: 1.0, Decision.INVESTIGATE: 0.9, Decision.MAINTAIN: 0.8,
            Decision.CALL_ALLIED: 0.7, Decision.ISOLATE: 0.5, Decision.DOWNGRADE: 0.6,
            Decision.STAND_DOWN: 0.4, Decision.ESCALATE: 0.1, Decision.ESCALATE_BOTH: 0.1,
            Decision.PETROV_CALL: 0.2, Decision.TIMEOUT: 0.0,
        }
        features["caution"] = caution_map.get(action, 0.3)

        # φ_duty: does this fulfill reporting obligations?
        duty_map = {
            Decision.ESCALATE: 1.0, Decision.ESCALATE_BOTH: 0.9, Decision.PARALLEL: 0.7,
            Decision.MAINTAIN: 0.5, Decision.INVESTIGATE: 0.3, Decision.CALL_ALLIED: 0.6,
            Decision.STAND_DOWN: 0.4, Decision.DOWNGRADE: 0.3, Decision.ISOLATE: 0.2,
            Decision.PETROV_CALL: 0.1, Decision.TIMEOUT: 0.0,
        }
        features["duty"] = duty_map.get(action, 0.3)

        # φ_speed: does this preserve decision time?
        time_cost = {
            Decision.INVESTIGATE: 300, Decision.PARALLEL: 240, Decision.ESCALATE: 240,
            Decision.ISOLATE: 180, Decision.MAINTAIN: 180, Decision.DOWNGRADE: 120,
            Decision.PETROV_CALL: 120, Decision.STAND_DOWN: 0, Decision.ESCALATE_BOTH: 0,
            Decision.CALL_ALLIED: 0, Decision.TIMEOUT: 180,
        }
        features["speed"] = 1.0 - (time_cost.get(action, 180) / 300)

        # Context-dependent adjustments
        if state.sensor_integrity < 0.5:
            features["evidence"] *= 1.3  # evidence MORE valuable when sensors compromised

        if state.estimated_threat_prob < 0.3:
            features["duty"] *= 0.5  # duty less pressing when threat is low

        # Weighted sum: Σ θ_f · φ_f
        score = sum(self.theta[f"w_{k}"] * features[k] for k in features)
        return score

    def decide(self, state: GovernanceState) -> Decision:
        """X^π(S_t | θ) = argmax_x { score(S_t, x | θ) }"""
        actions = feasible_actions(state)
        if len(actions) == 1:
            return actions[0]
        return max(actions, key=lambda a: self._score_action(state, a))


# ╔══════════════════════════════════════════════════════════════════╗
# ║  SIMULATOR: Run full sequential decision episodes              ║
# ║                                                                ║
# ║  This is where Powell's framework comes alive:                 ║
# ║  (S_0, x_0, W_1, S_1, x_1, W_2, ..., S_T)                   ║
# ║                                                                ║
# ║  Start in state S_0, use policy to pick x_0, observe W_1,     ║
# ║  transition to S_1, repeat until terminal.                     ║
# ╚══════════════════════════════════════════════════════════════════╝

@dataclass
class EpisodeResult:
    """
    The complete record of one sequential decision episode.

    FOR EVERYONE:
        One full playthrough of the scenario — every state, every
        decision, every piece of new information, every score.
        This is the data that feeds back into AGORA.
    """
    states: list[dict]
    decisions: list[str]
    contributions: list[dict]
    total_score: float
    dimension_scores: dict[str, float]
    policy_name: str
    seed: int


def simulate_episode(
    policy,
    initial_state: GovernanceState = None,
    seed: int = 42,
    num_stages: int = 3,
) -> EpisodeResult:
    """
    Run one complete episode: (S_0, x_0, W_1, S_1, x_1, W_2, ..., S_T)

    FOR EVERYONE:
        This plays through the entire scenario once — making decisions,
        receiving new information, updating the state — and records
        everything that happened.

    FOR RESEARCHERS:
        Single sample path simulation. The policy π determines x_t = X^π(S_t).
        Exogenous info W_{t+1} is sampled from P(· | S_t, x_t).
        Contributions C(S_t, x_t) are accumulated.
    """
    rng = random.Random(seed)

    if initial_state is None:
        initial_state = GovernanceState(
            time_remaining=720,       # 12 minutes
            escalation_level=0,
            staff_available=4,        # skeleton crew
            threat_confidence=0.87,
            cyber_detected=True,
            sensor_integrity=0.7,     # partially compromised
            forensic_status="none",
            secondary_data=None,
            estimated_threat_prob=0.45,  # we're uncertain
            arg_strengths={
                "baseline_allow": 0.3,
                "ai_confidence": 0.7,
                "sensor_reliability": 0.6,
                "measured_response": 0.65,
                "escalation_duty": 0.7,
                "time_pressure": 0.75,
            },
            stage=0,
            decision_history=[],
        )

    state = initial_state
    states = [asdict(state)]
    decisions = []
    contributions = []
    total = 0.0
    dim_totals = {k: 0.0 for k in ["consistency", "proportionality", "reversibility",
                                     "auditability", "epistemic_rigor"]}

    for t in range(num_stages):
        # ── Policy decides ──
        decision = policy.decide(state)
        decisions.append(decision.value)

        # ── Compute contribution ──
        c = contribution(state, decision)
        contributions.append(c)
        sc = scalar_contribution(state, decision)
        total += sc
        for k in dim_totals:
            dim_totals[k] += c[k]

        # ── Generate exogenous info ──
        info = generate_exogenous(state, decision, rng)

        # ── Transition ──
        state = transition(state, decision, info)
        states.append(asdict(state))

    # Normalize scores to 0-100
    max_possible = num_stages * 28  # rough max per dimension per stage
    for k in dim_totals:
        dim_totals[k] = min(100, (dim_totals[k] / max_possible) * 100)

    policy_name = type(policy).__name__
    return EpisodeResult(
        states=states,
        decisions=decisions,
        contributions=contributions,
        total_score=total,
        dimension_scores=dim_totals,
        policy_name=policy_name,
        seed=seed,
    )


# ╔══════════════════════════════════════════════════════════════════╗
# ║  POLICY SEARCH: Finding the best policy parameters             ║
# ║                                                                ║
# ║  Powell's key insight: the REAL problem is:                    ║
# ║    max_θ F^π(θ)                                                ║
# ║  Find the parameters that make the policy perform best         ║
# ║  IN EXPECTATION across many random scenarios.                  ║
# ╚══════════════════════════════════════════════════════════════════╝

def policy_search_grid(
    policy_class,
    param_grid: dict[str, list],
    n_simulations: int = 100,
    initial_state: GovernanceState = None,
) -> tuple[dict, float, list[dict]]:
    """
    Grid search over policy parameters.

    FOR EVERYONE:
        Try many different settings of the policy's knobs,
        run each setting through hundreds of simulated crises,
        and find which settings produce the best average score.
        This is how we learn which governance strategies work best.

    FOR RESEARCHERS:
        Solves max_θ F^π(θ) where F^π(θ) = (1/N) Σ_n C(S_t(ω_n), X^π(S_t(ω_n) | θ))
        via full grid enumeration. Feasible because θ is low-dimensional.
        See Powell Ch. 7, Section 7.4 and Eq. (8.12).
    """
    import itertools

    keys = list(param_grid.keys())
    values = list(param_grid.values())
    best_theta = None
    best_score = float("-inf")
    results = []

    for combo in itertools.product(*values):
        theta = dict(zip(keys, combo))
        policy = policy_class(theta=theta)

        # Evaluate over N simulations with different random seeds
        total = 0.0
        for seed in range(n_simulations):
            ep = simulate_episode(policy, initial_state=initial_state, seed=seed)
            total += ep.total_score

        avg_score = total / n_simulations
        results.append({"theta": theta, "avg_score": avg_score})

        if avg_score > best_score:
            best_score = avg_score
            best_theta = theta

    return best_theta, best_score, results


# ╔══════════════════════════════════════════════════════════════════╗
# ║  COMMUNITY DATA INTEGRATION                                    ║
# ║                                                                ║
# ║  Load game export JSON files and convert to SDAM format.       ║
# ║  This is how Arena playthrough data feeds into the model.      ║
# ╚══════════════════════════════════════════════════════════════════╝

def load_arena_export(filepath: str) -> dict:
    """
    Load a Decision Arena game export and convert to SDAM episode format.

    FOR EVERYONE:
        When you play the Arena game and click "Export to AGORA," it saves
        a JSON file. This function reads that file and converts your
        decisions into the formal SDAM format so the model can study them.

    FOR RESEARCHERS:
        Maps the client-side game data (stage choices, argumentation state)
        to the formal SDAM tuple (S_0, x_0, W_1, S_1, ...).
    """
    with open(filepath, "r") as f:
        data = json.load(f)

    # Map game decision IDs to our Decision enum
    id_map = {
        "d1_escalate": "escalate", "d1_investigate": "investigate",
        "d1_parallel": "parallel", "d1_isolate": "isolate",
        "d2_downgrade": "downgrade", "d2_maintain": "maintain",
        "d2_petrov": "petrov_call",
        "d3_stand_down": "stand_down", "d3_escalate_both": "escalate_both",
        "d3_allied": "call_allied",
    }

    episode = {
        "scenario_id": data.get("scenario_id", "unknown"),
        "decisions": [
            id_map.get(d["choice"], d["choice"])
            for d in data.get("decisions", [])
        ],
        "scores": data.get("scores", {}),
        "total_score": data.get("total_score", 0),
        "played_at": data.get("played_at", ""),
        "arguments_final": data.get("arguments_final", []),
    }

    return episode


def batch_analyze_exports(directory: str) -> dict:
    """
    Analyze all Arena exports in a directory.

    FOR EVERYONE:
        When the community has contributed many playthroughs, this
        function reads ALL of them and computes statistics:
        which decisions are most popular, which strategies score highest,
        where does the community disagree most.

    FOR RESEARCHERS:
        Empirical analysis of the policy distribution over the community.
        Each playthrough is a sample from an implicit policy.
    """
    path = Path(directory)
    episodes = []

    for f in path.glob("agora-arena-*.json"):
        try:
            episodes.append(load_arena_export(str(f)))
        except Exception as e:
            logger.warning(f"Skipping {f}: {e}")

    if not episodes:
        return {"error": "No valid exports found", "directory": directory}

    # Decision frequency at each stage
    stage_freq = {1: {}, 2: {}, 3: {}}
    for ep in episodes:
        for i, d in enumerate(ep["decisions"]):
            stage = i + 1
            stage_freq[stage][d] = stage_freq[stage].get(d, 0) + 1

    # Score distribution
    scores = [ep["total_score"] for ep in episodes]

    return {
        "total_playthroughs": len(episodes),
        "decision_frequency_by_stage": stage_freq,
        "score_stats": {
            "mean": sum(scores) / len(scores) if scores else 0,
            "min": min(scores) if scores else 0,
            "max": max(scores) if scores else 0,
        },
        "most_common_path": [
            max(stage_freq[s], key=stage_freq[s].get) if stage_freq[s] else "none"
            for s in [1, 2, 3]
        ],
    }


# ╔══════════════════════════════════════════════════════════════════╗
# ║  MAIN: Demonstration                                           ║
# ╚══════════════════════════════════════════════════════════════════╝

if __name__ == "__main__":
    print("=" * 65)
    print("  AGORA Sequential Decision Model")
    print("  Framework: Powell's SDAM (Princeton, 2022)")
    print("=" * 65)
    print()

    # ── Run PFA policy ──
    print("━━━ PFA Policy (threshold rules) ━━━")
    pfa = PFAPolicy()
    ep1 = simulate_episode(pfa, seed=42)
    print(f"  Decisions: {ep1.decisions}")
    print(f"  Total Score: {ep1.total_score:.2f}")
    print(f"  Dimensions: {', '.join(f'{k}={v:.0f}' for k, v in ep1.dimension_scores.items())}")
    print()

    # ── Run CFA policy ──
    print("━━━ CFA Policy (parameterized optimization) ━━━")
    cfa = CFAPolicy()
    ep2 = simulate_episode(cfa, seed=42)
    print(f"  Decisions: {ep2.decisions}")
    print(f"  Total Score: {ep2.total_score:.2f}")
    print(f"  Dimensions: {', '.join(f'{k}={v:.0f}' for k, v in ep2.dimension_scores.items())}")
    print()

    # ── Run PFA policy search ──
    print("━━━ PFA Policy Search (finding best thresholds) ━━━")
    best_theta, best_score, _ = policy_search_grid(
        PFAPolicy,
        param_grid={
            "confidence_threshold": [0.80, 0.85, 0.90, 0.95],
            "integrity_threshold": [0.3, 0.5, 0.7],
            "time_urgency": [0.15, 0.25, 0.35],
        },
        n_simulations=50,
    )
    print(f"  Best θ: {best_theta}")
    print(f"  Best avg score: {best_score:.2f}")
    print()

    # ── Compare across random scenarios ──
    print("━━━ Monte Carlo Comparison (200 scenarios) ━━━")
    pfa_scores, cfa_scores = [], []
    for seed in range(200):
        pfa_scores.append(simulate_episode(pfa, seed=seed).total_score)
        cfa_scores.append(simulate_episode(cfa, seed=seed).total_score)

    print(f"  PFA avg: {sum(pfa_scores)/len(pfa_scores):.2f}")
    print(f"  CFA avg: {sum(cfa_scores)/len(cfa_scores):.2f}")
    print(f"  CFA wins: {sum(1 for a, b in zip(pfa_scores, cfa_scores) if b > a)}/200")
    print()
    print("Done. Export Arena game data to feed community decisions into this model.")
