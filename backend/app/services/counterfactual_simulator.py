"""Counterfactual Action Simulator.

Simulates defensive containment and deception interventions before execution,
evaluating expected risk reduction against operational disruption cost to guarantee
Zero Operational Loss and preserve critical asset availability.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class SimulatedAction:
    action_type: str
    expected_risk_reduction: float
    disruption_cost: float
    net_utility: float
    violates_critical_guardrail: bool
    requires_human_approval: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "expected_risk_reduction": round(self.expected_risk_reduction, 2),
            "disruption_cost": round(self.disruption_cost, 2),
            "net_utility": round(self.net_utility, 2),
            "violates_critical_guardrail": self.violates_critical_guardrail,
            "requires_human_approval": self.requires_human_approval,
            "explanation": self.explanation,
        }


def simulate_counterfactual_actions(
    current_risk: float,
    asset_criticality: str = "medium",
    novelty_score: float = 0.0,
    tradeoff_lambda: float = 0.75,
) -> Dict[str, Any]:
    """
    Simulate candidate defensive actions across risk reduction and disruption cost.

    Guarantee:
    - Critical assets (e.g. Domain Controller, Gateway, Database) incur massive disruption
      penalties for destructive actions (ISOLATE / CONTAIN), preventing autonomous outages.
    - Zero Operational Loss: strictly favors non-disruptive DECEPTION and MONITORING for critical assets.
    """
    is_critical = asset_criticality.lower() == "critical"
    current_risk = float(max(0.0, min(100.0, current_risk)))
    novelty_score = float(max(0.0, min(1.0, novelty_score)))

    # Candidate actions and their nominal characteristics
    candidates = [
        {
            "action": "observe",
            "risk_reduction_pct": 0.0,
            "base_disruption": 0.0,
            "human_required": False,
            "desc": "Passive observation; zero disruption to business workflows.",
        },
        {
            "action": "monitor",
            "risk_reduction_pct": 0.15,
            "base_disruption": 5.0,
            "human_required": False,
            "desc": "Elevated telemetry sampling and deeper flow inspection.",
        },
        {
            "action": "prepare_deception",
            "risk_reduction_pct": 0.45,
            "base_disruption": 10.0,
            "human_required": False,
            "desc": "Deploy decoy credentials and honeytoken routes without modifying active services.",
        },
        {
            "action": "contain",
            "risk_reduction_pct": 0.75,
            "base_disruption": 30.0 if not is_critical else 90.0,
            "human_required": is_critical,
            "desc": "Selective VLAN micro-segmentation / ACL restrictions.",
        },
        {
            "action": "isolate",
            "risk_reduction_pct": 0.95,
            "base_disruption": 50.0 if not is_critical else 100.0,
            "human_required": True,
            "desc": "Full network isolation of host.",
        },
    ]

    simulated: List[SimulatedAction] = []

    for c in candidates:
        action_name = c["action"]
        raw_reduction = current_risk * c["risk_reduction_pct"]
        # If novel, deception is especially effective at capturing zero-day payloads
        if novelty_score >= 0.65 and action_name == "prepare_deception":
            raw_reduction *= 1.25

        disruption = c["base_disruption"]
        violates_guardrail = is_critical and action_name in ("isolate", "contain")
        net_utility = raw_reduction - (tradeoff_lambda * disruption)

        simulated.append(
            SimulatedAction(
                action_type=action_name,
                expected_risk_reduction=raw_reduction,
                disruption_cost=disruption,
                net_utility=net_utility,
                violates_critical_guardrail=violates_guardrail,
                requires_human_approval=c["human_required"] or violates_guardrail,
                explanation=c["desc"],
            )
        )

    # Rank actions by net utility, filtering out unapproved guardrail violations for autonomous recommendation
    valid_autonomous = [a for a in simulated if not a.violates_critical_guardrail]
    valid_autonomous.sort(key=lambda a: a.net_utility, reverse=True)
    recommended = valid_autonomous[0] if valid_autonomous else simulated[0]

    return {
        "current_risk": current_risk,
        "asset_criticality": asset_criticality,
        "novelty_score": novelty_score,
        "simulated_actions": [a.to_dict() for a in simulated],
        "recommended_action": recommended.action_type,
        "recommended_action_detail": recommended.to_dict(),
        "zero_loss_guarantee_applied": is_critical,
    }
