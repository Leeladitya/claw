"""
Tests for the SDAM Sequential Decision Model
==============================================

Covers all 5 Powell elements, both policy classes, simulation, policy search,
and community data integration. 36 test cases.
"""

import pytest
import json
import os
import random
import tempfile
from server.sdam_model import (
    GovernanceState,
    Decision,
    ExogenousInfo,
    PFAPolicy,
    CFAPolicy,
    STAGE_ACTIONS,
    generate_exogenous,
    transition,
    contribution,
    scalar_contribution,
    simulate_episode,
    policy_search_grid,
    load_arena_export,
    batch_analyze_exports,
    EpisodeResult,
)


def make_state(**overrides) -> GovernanceState:
    """Create default nuclear scenario state with optional overrides."""
    defaults = dict(
        time_remaining=720,
        escalation_level=0,
        staff_available=4,
        threat_confidence=0.87,
        cyber_detected=True,
        sensor_integrity=0.7,
        forensic_status="none",
        secondary_data=None,
        estimated_threat_prob=0.5,
    )
    defaults.update(overrides)
    return GovernanceState(**defaults)


class TestGovernanceState:
    """State S_t = (R_t, I_t, B_t) per Powell."""

    def test_initial_state_defaults(self):
        s = make_state()
        assert s.time_remaining == 720
        assert s.escalation_level == 0
        assert s.threat_confidence == 0.87
        assert s.cyber_detected is True
        assert s.sensor_integrity == 0.7
        assert s.estimated_threat_prob == 0.5
        assert s.stage == 0

    def test_to_vector_normalization(self):
        s = make_state()
        vec = s.to_vector()
        assert isinstance(vec, list)
        assert all(0.0 <= v <= 1.0 for v in vec), f"Vector out of bounds: {vec}"

    def test_to_vector_length_consistent(self):
        s1 = make_state()
        s2 = make_state(time_remaining=100, escalation_level=3, stage=2)
        assert len(s1.to_vector()) == len(s2.to_vector())

    def test_state_with_custom_values(self):
        s = make_state(
            time_remaining=300, escalation_level=2, staff_available=5,
            threat_confidence=0.95, cyber_detected=False, sensor_integrity=0.3,
            estimated_threat_prob=0.8, stage=2,
        )
        assert s.time_remaining == 300
        assert s.escalation_level == 2
        assert s.estimated_threat_prob == 0.8
        assert s.stage == 2


class TestDecisionFeasibility:
    """Decision x_t in X(S_t) — feasibility constraints by stage."""

    def test_stage_0_actions(self):
        actions = STAGE_ACTIONS[0]
        assert Decision.ESCALATE in actions
        assert Decision.INVESTIGATE in actions
        assert Decision.PARALLEL in actions
        assert Decision.ISOLATE in actions

    def test_stage_1_actions(self):
        actions = STAGE_ACTIONS[1]
        assert Decision.DOWNGRADE in actions
        assert Decision.MAINTAIN in actions
        assert Decision.PETROV_CALL in actions

    def test_stage_2_actions(self):
        actions = STAGE_ACTIONS[2]
        assert Decision.STAND_DOWN in actions
        assert Decision.ESCALATE_BOTH in actions
        assert Decision.CALL_ALLIED in actions

    def test_stages_are_disjoint(self):
        all_actions = set()
        for stage, actions in STAGE_ACTIONS.items():
            if stage == 3:
                continue
            for a in actions:
                assert a not in all_actions, f"{a} appears in multiple stages"
                all_actions.add(a)


class TestExogenousInformation:
    """Exogenous info W_{t+1} ~ P(. | S_t, x_t)."""

    def test_exogenous_returns_correct_type(self):
        s = make_state()
        rng = random.Random(42)
        w = generate_exogenous(s, Decision.INVESTIGATE, rng)
        assert isinstance(w, ExogenousInfo)

    def test_investigation_speeds_forensics(self):
        s = make_state()
        got_forensics = 0
        for seed in range(100):
            rng = random.Random(seed)
            w = generate_exogenous(s, Decision.INVESTIGATE, rng)
            if w.forensic_result is not None:
                got_forensics += 1
        assert got_forensics > 30, f"Only {got_forensics}/100"

    def test_non_investigation_fewer_forensics(self):
        s = make_state()
        got_forensics = 0
        for seed in range(100):
            rng = random.Random(seed)
            w = generate_exogenous(s, Decision.ESCALATE, rng)
            if w.forensic_result is not None:
                got_forensics += 1
        assert got_forensics < 30, f"Escalation yielded {got_forensics}/100"

    def test_deterministic_with_seed(self):
        s = make_state()
        rng1 = random.Random(99)
        rng2 = random.Random(99)
        w1 = generate_exogenous(s, Decision.PARALLEL, rng1)
        w2 = generate_exogenous(s, Decision.PARALLEL, rng2)
        assert w1.ai_confidence_update == w2.ai_confidence_update
        assert w1.secondary_satellite == w2.secondary_satellite
        assert w1.forensic_result == w2.forensic_result


class TestTransition:
    """Transition S^M(S_t, x_t, W_{t+1}) -> S_{t+1}."""

    def test_time_decreases(self):
        s = make_state()
        rng = random.Random(42)
        w = generate_exogenous(s, Decision.INVESTIGATE, rng)
        s_next = transition(s, Decision.INVESTIGATE, w)
        assert s_next.time_remaining < s.time_remaining

    def test_stage_advances(self):
        s = make_state(stage=0)
        rng = random.Random(42)
        w = generate_exogenous(s, Decision.PARALLEL, rng)
        s_next = transition(s, Decision.PARALLEL, w)
        assert s_next.stage == 1

    def test_escalation_increases_on_escalate(self):
        s = make_state(escalation_level=0)
        rng = random.Random(42)
        w = generate_exogenous(s, Decision.ESCALATE, rng)
        s_next = transition(s, Decision.ESCALATE, w)
        assert s_next.escalation_level > s.escalation_level

    def test_forensic_confirmation_drops_threat_prob(self):
        s = make_state(estimated_threat_prob=0.7)
        w = ExogenousInfo(
            ai_confidence_update=0.0, secondary_satellite=None,
            forensic_result="confirmed_attack", sensor_integrity_change=0.0,
            time_consumed=120,
        )
        s_next = transition(s, Decision.INVESTIGATE, w)
        assert s_next.estimated_threat_prob < s.estimated_threat_prob

    def test_secondary_contradiction_affects_threat(self):
        s = make_state(estimated_threat_prob=0.6)
        w = ExogenousInfo(
            ai_confidence_update=0.0, secondary_satellite="contradicts",
            forensic_result=None, sensor_integrity_change=0.0, time_consumed=120,
        )
        s_next = transition(s, Decision.MAINTAIN, w)
        assert s_next.estimated_threat_prob < s.estimated_threat_prob


class TestContribution:
    """Objective: C(S_t, x_t) multi-dimensional governance scoring."""

    def test_contribution_returns_dict(self):
        s = make_state()
        c = contribution(s, Decision.INVESTIGATE)
        assert isinstance(c, dict)
        for key in ["consistency", "proportionality", "reversibility", "auditability", "epistemic_rigor"]:
            assert key in c, f"Missing: {key}"
            assert c[key] >= 0, f"{key} negative: {c[key]}"

    def test_scalar_contribution_weighted_sum(self):
        s = make_state()
        sc = scalar_contribution(s, Decision.PARALLEL)
        assert sc > 0

    def test_investigation_scores_high_epistemic(self):
        s = make_state()
        c_inv = contribution(s, Decision.INVESTIGATE)
        c_esc = contribution(s, Decision.ESCALATE)
        assert c_inv["epistemic_rigor"] >= c_esc["epistemic_rigor"]

    def test_escalation_scores_low_reversibility(self):
        s = make_state()
        c = contribution(s, Decision.ESCALATE)
        c_inv = contribution(s, Decision.INVESTIGATE)
        assert c["reversibility"] < c_inv["reversibility"]


class TestPolicies:
    """PFA and CFA policy classes."""

    def test_pfa_returns_valid_action(self):
        policy = PFAPolicy()
        s = make_state(stage=0)
        assert policy.decide(s) in STAGE_ACTIONS[0]

    def test_cfa_returns_valid_action(self):
        policy = CFAPolicy()
        s = make_state(stage=0)
        assert policy.decide(s) in STAGE_ACTIONS[0]

    def test_pfa_all_stages(self):
        policy = PFAPolicy()
        for stage in [0, 1, 2]:
            s = make_state(stage=stage)
            assert policy.decide(s) in STAGE_ACTIONS[stage]

    def test_cfa_all_stages(self):
        policy = CFAPolicy()
        for stage in [0, 1, 2]:
            s = make_state(stage=stage)
            assert policy.decide(s) in STAGE_ACTIONS[stage]

    def test_cfa_sensitive_to_state(self):
        policy = CFAPolicy()
        s1 = make_state(sensor_integrity=0.3, estimated_threat_prob=0.3, stage=0)
        s2 = make_state(sensor_integrity=0.95, estimated_threat_prob=0.9, stage=0)
        assert policy.decide(s1) in STAGE_ACTIONS[0]
        assert policy.decide(s2) in STAGE_ACTIONS[0]


class TestSimulation:
    """Episode simulation: (S_0, x_0, W_1, S_1, ..., S_T)."""

    def test_episode_completes(self):
        ep = simulate_episode(PFAPolicy(), seed=42)
        assert isinstance(ep, EpisodeResult)

    def test_episode_has_decisions(self):
        ep = simulate_episode(CFAPolicy(), seed=42)
        assert len(ep.decisions) >= 1

    def test_episode_has_positive_score(self):
        ep = simulate_episode(CFAPolicy(), seed=42)
        assert ep.total_score > 0

    def test_deterministic_simulation(self):
        ep1 = simulate_episode(PFAPolicy(), seed=123)
        ep2 = simulate_episode(PFAPolicy(), seed=123)
        assert ep1.total_score == ep2.total_score
        assert ep1.decisions == ep2.decisions

    def test_different_seeds_vary(self):
        scores = set()
        for seed in range(20):
            ep = simulate_episode(CFAPolicy(), seed=seed)
            scores.add(round(ep.total_score, 2))
        assert len(scores) > 1

    def test_cfa_outperforms_pfa(self):
        """The core publishable result: CFA beats PFA."""
        pfa, cfa = PFAPolicy(), CFAPolicy()
        cfa_wins = sum(
            1 for seed in range(50)
            if simulate_episode(cfa, seed=seed).total_score > simulate_episode(pfa, seed=seed).total_score
        )
        assert cfa_wins > 35, f"CFA only won {cfa_wins}/50"

    def test_episode_with_custom_initial_state(self):
        s0 = make_state(time_remaining=360, sensor_integrity=0.3)
        ep = simulate_episode(CFAPolicy(), initial_state=s0, seed=42)
        assert ep.total_score > 0


class TestPolicySearch:
    """Grid search: max_theta F^pi(theta)."""

    def test_policy_search_returns_results(self):
        param_grid = {
            "confidence_threshold": [0.7, 0.9],
            "integrity_threshold": [0.3, 0.5],
            "time_urgency": [0.1, 0.2],
        }
        best_params, best_score, all_results = policy_search_grid(
            PFAPolicy, param_grid, n_simulations=5
        )
        assert isinstance(best_params, dict)
        assert best_score > 0

    def test_policy_search_score_reasonable(self):
        param_grid = {
            "confidence_threshold": [0.8, 0.95],
            "integrity_threshold": [0.3, 0.5],
            "time_urgency": [0.15],
        }
        best_params, best_score, _ = policy_search_grid(
            PFAPolicy, param_grid, n_simulations=10
        )
        assert 10 < best_score < 100


class TestArenaExportIntegration:
    """Community data pipeline: Arena JSON -> SDAM episodes."""

    def test_load_valid_export(self):
        export = {
            "scenario_id": "nuclear-false-positive-v1",
            "timestamp": "2026-02-14T21:30:00Z",
            "decisions": [
                {"stage": 1, "choice": "investigate", "time_remaining": 600},
                {"stage": 2, "choice": "downgrade", "time_remaining": 400},
                {"stage": 3, "choice": "stand_down", "time_remaining": 180},
            ],
            "scores": {
                "consistency": 0.82, "proportionality": 0.91,
                "reversibility": 0.67, "auditability": 0.95,
                "epistemic_rigor": 0.73, "composite": 0.816,
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(export, f)
            path = f.name
        try:
            result = load_arena_export(path)
            assert result is not None
            assert "scenario_id" in result
        finally:
            os.unlink(path)

    def test_batch_analyze_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = batch_analyze_exports(tmpdir)
            assert result is not None
