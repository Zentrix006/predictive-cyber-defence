"""Unit tests for counterfactual simulation, policy guardrails, and zero-loss rollback."""
import pytest
from app.services.counterfactual_simulator import simulate_counterfactual_actions
from app.services.policy_engine import evaluate_policy
from app.core.policy_config import PolicyAction


def test_counterfactual_standard_asset():
    result = simulate_counterfactual_actions(
        current_risk=80.0,
        asset_criticality="medium",
        novelty_score=0.20,
    )
    assert not result["zero_loss_guarantee_applied"]
    # For a high-risk standard asset, containment or isolation should be viable
    actions = {a["action_type"]: a for a in result["simulated_actions"]}
    assert not actions["contain"]["violates_critical_guardrail"]
    assert actions["contain"]["net_utility"] > 0


def test_counterfactual_critical_asset_guardrail():
    # Critical infrastructure: server / gateway
    result = simulate_counterfactual_actions(
        current_risk=85.0,
        asset_criticality="critical",
        novelty_score=0.85,
    )
    assert result["zero_loss_guarantee_applied"]
    actions = {a["action_type"]: a for a in result["simulated_actions"]}

    # Severe actions must violate guardrails for critical assets
    assert actions["isolate"]["violates_critical_guardrail"]
    assert actions["contain"]["violates_critical_guardrail"]
    assert actions["isolate"]["requires_human_approval"]

    # Recommended action must NOT violate guardrail and should favor deception / non-disruptive
    rec = result["recommended_action"]
    assert rec in ("prepare_deception", "monitor", "observe")
    assert not actions[rec]["violates_critical_guardrail"]


def test_policy_engine_novelty_routing():
    # 1. High novelty on standard asset -> contain
    std_decision = evaluate_policy(
        risk_score=50.0,
        confidence=0.5,
        asset_criticality="low",
        novelty_score=0.80,
    )
    assert std_decision.action == PolicyAction.CONTAIN
    assert std_decision.rule_id == "novel-threat-standard-asset"
    assert not std_decision.requires_human_approval

    # 2. High novelty on critical asset -> prepare_deception with human approval
    crit_decision = evaluate_policy(
        risk_score=50.0,
        confidence=0.5,
        asset_criticality="critical",
        novelty_score=0.80,
    )
    assert crit_decision.action == PolicyAction.PREPARE_DECEPTION
    assert crit_decision.rule_id == "novel-threat-critical-asset"
    assert crit_decision.requires_human_approval
