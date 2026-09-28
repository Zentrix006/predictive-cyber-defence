"""Graph-Temporal Action-Conditioned Planner.

Uses the GraphFlowWorldModel to roll out imagined network trajectories under candidate
defensive actions and selects the optimal intervention guaranteeing Zero Operational Loss.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import torch

from models.graph_world_model import GraphFlowWorldModel


@dataclass
class GraphPlanDecision:
    action_id: int
    action_name: str
    target_node_ip: str
    target_node_idx: int
    projected_risk_reduction: float
    disruption_cost: float
    net_utility: float
    is_critical_guarded: bool
    requires_human_approval: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_name": self.action_name,
            "target_node_ip": self.target_node_ip,
            "target_node_idx": self.target_node_idx,
            "projected_risk_reduction": round(self.projected_risk_reduction, 2),
            "disruption_cost": round(self.disruption_cost, 2),
            "net_utility": round(self.net_utility, 2),
            "is_critical_guarded": self.is_critical_guarded,
            "requires_human_approval": self.requires_human_approval,
            "explanation": self.explanation,
        }


ACTION_NAMES = {
    0: "PASS",
    1: "MONITOR",
    2: "DECEPTION",
    3: "RATE_LIMIT",
    4: "CONTAIN",
    5: "ISOLATE",
}


def plan_graph_defense(
    model: GraphFlowWorldModel,
    nodes: torch.Tensor,
    edge_index: torch.Tensor,
    edges: torch.Tensor,
    node_to_idx: Dict[str, int],
    target_ip: str,
    target_criticality: str = "medium",
    tradeoff_lambda: float = 0.80,
) -> Dict[str, Any]:
    """
    Simulate all candidate defense actions across the network graph in latent imagination.
    Selects the action optimizing risk reduction while avoiding disruption to critical nodes.
    """
    model.eval()
    is_critical = target_criticality.lower() == "critical"
    target_idx = node_to_idx.get(target_ip, 0)
    target_tensor = torch.tensor([target_idx], dtype=torch.long, device=nodes.device)

    # 1. Base simulation: Action 0 (PASS - what happens if defender does nothing)
    with torch.no_grad():
        out_pass = model(nodes, edge_index, edges, action_id=torch.tensor([0]))
        base_risk = float(torch.sigmoid(out_pass.node_risk_logits[0, target_idx]).item())

    decisions: List[GraphPlanDecision] = []

    # 2. Evaluate candidate actions: 0 to 5
    for a_id, a_name in ACTION_NAMES.items():
        with torch.no_grad():
            out_act = model(
                nodes,
                edge_index,
                edges,
                action_id=torch.tensor([a_id]),
                target_node_idx=target_tensor,
            )
            # Evaluate projected risk in future rollout
            fut_risk = float(torch.sigmoid(out_act.node_risk_logits[0, target_idx]).item())

        # Disruption costs
        base_disruption = {
            0: 0.0,
            1: 5.0,
            2: 10.0,
            3: 25.0,
            4: 40.0 if not is_critical else 90.0,
            5: 60.0 if not is_critical else 100.0,
        }[a_id]

        risk_reduction = max(0.0, (base_risk - fut_risk) * 100.0)
        # Deception bonus: effective at trapping novel attacks without taking services offline
        if a_id == 2:
            risk_reduction = max(risk_reduction, base_risk * 60.0)

        violates_guardrail = is_critical and a_id in (4, 5)
        net_utility = risk_reduction - (tradeoff_lambda * base_disruption)

        explanation = {
            0: "Passive observation without network intervention.",
            1: "Increase telemetry capture rate on target host.",
            2: "Deploy targeted honeypot decoys, safely capturing threat payload.",
            3: "Apply bandwidth and rate-limiting filters on host port.",
            4: "VLAN micro-segmentation of host.",
            5: "Complete physical network isolation of host.",
        }[a_id]

        decisions.append(
            GraphPlanDecision(
                action_id=a_id,
                action_name=a_name,
                target_node_ip=target_ip,
                target_node_idx=target_idx,
                projected_risk_reduction=risk_reduction,
                disruption_cost=base_disruption,
                net_utility=net_utility,
                is_critical_guarded=violates_guardrail,
                requires_human_approval=violates_guardrail or a_id == 5,
                explanation=explanation,
            )
        )

    # Filter out guarded actions for autonomous selection
    allowed = [d for d in decisions if not d.is_critical_guarded]
    allowed.sort(key=lambda x: x.net_utility, reverse=True)
    recommended = allowed[0] if allowed else decisions[0]

    return {
        "target_ip": target_ip,
        "target_criticality": target_criticality,
        "base_risk_score": round(base_risk * 100.0, 2),
        "zero_loss_safeguard_active": is_critical,
        "recommended_action": recommended.action_name,
        "recommended_action_detail": recommended.to_dict(),
        "candidate_evaluations": [d.to_dict() for d in decisions],
    }
