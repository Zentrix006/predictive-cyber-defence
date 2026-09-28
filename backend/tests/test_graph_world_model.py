"""Unit tests for GraphFlowWorldModel, Cyber-JEPA Surprisal, and Graph Planner."""
import pytest
import torch
import numpy as np

from models.graph_world_model import GraphFlowWorldModel
from features.graph_extractor import build_graph_from_flow_records
from app.services.graph_planner import plan_graph_defense


def test_graph_flow_world_model_forward():
    model = GraphFlowWorldModel(
        node_dim=8,
        edge_dim=12,
        d_model=32,
        num_stages=14,
        num_actions=6,
        horizon=3,
        num_layers=2,
    )
    model.eval()

    # Create synthetic graph: 4 nodes, 3 directed edges
    nodes = torch.randn(1, 4, 8)
    edge_index = torch.tensor([[[0, 1, 2], [1, 2, 3]]], dtype=torch.long)  # 0->1, 1->2, 2->3
    edges = torch.randn(1, 3, 12)

    with torch.no_grad():
        out = model(nodes, edge_index, edges, action_id=torch.tensor([0]))

    assert out.latent_state.shape == (1, 4, 32)
    assert out.predicted_latent_future.shape == (1, 3, 4, 32)
    assert out.node_risk_logits.shape == (1, 4)
    assert out.node_stage_logits.shape == (1, 4, 14)
    assert out.edge_flow_forecast.shape == (1, 3, 12)


def test_action_conditioned_isolation():
    model = GraphFlowWorldModel(
        node_dim=8,
        edge_dim=12,
        d_model=32,
        horizon=3,
    )
    model.eval()

    nodes = torch.randn(1, 4, 8)
    edge_index = torch.tensor([[[0, 1], [1, 2]]], dtype=torch.long)
    edges = torch.randn(1, 2, 12)

    with torch.no_grad():
        # Action 0: PASS
        out_pass = model(nodes, edge_index, edges, action_id=torch.tensor([0]))
        # Action 5: ISOLATE on node index 1
        out_isolate = model(
            nodes,
            edge_index,
            edges,
            action_id=torch.tensor([5]),
            target_node_idx=torch.tensor([1]),
        )

    # In imagination, node 1's latent state should be dampened under isolation
    norm_pass = torch.norm(out_pass.latent_state[0, 1])
    norm_isolate = torch.norm(out_isolate.latent_state[0, 1])
    assert norm_isolate < norm_pass


def test_cyber_jepa_latent_surprisal():
    model = GraphFlowWorldModel(
        node_dim=8,
        edge_dim=12,
        d_model=32,
    )
    model.eval()

    nodes = torch.randn(1, 3, 8)
    edge_index = torch.tensor([[[0, 1], [1, 2]]], dtype=torch.long)
    edges = torch.randn(1, 2, 12)

    # 1. Normal transition (small noise)
    normal_next = nodes + torch.randn_like(nodes) * 0.05
    out_normal = model(nodes, edge_index, edges, observed_next_nodes=normal_next)
    surprisal_normal = out_normal.jepa_surprisal.mean().item()

    # 2. Zero-Day Shock transition (massive anomaly)
    shock_next = nodes + torch.randn_like(nodes) * 5.0
    out_shock = model(nodes, edge_index, edges, observed_next_nodes=shock_next)
    surprisal_shock = out_shock.jepa_surprisal.mean().item()

    assert surprisal_shock > surprisal_normal


def test_graph_extractor_and_planner():
    # Simulate flow records
    flows = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "forward_packets": 10, "reverse_packets": 5},
        {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3", "forward_packets": 20, "reverse_packets": 15},
    ]
    snapshot = build_graph_from_flow_records(flows, node_dim=8, edge_dim=12)
    assert snapshot.num_nodes == 3
    assert snapshot.num_edges == 2
    assert "10.0.0.1" in snapshot.node_to_idx

    model = GraphFlowWorldModel(node_dim=8, edge_dim=12, d_model=32)

    # Plan on critical target (e.g. Domain Controller)
    plan = plan_graph_defense(
        model=model,
        nodes=snapshot.nodes,
        edge_index=snapshot.edge_index,
        edges=snapshot.edges,
        node_to_idx=snapshot.node_to_idx,
        target_ip="10.0.0.3",
        target_criticality="critical",
    )

    assert plan["zero_loss_safeguard_active"]
    # Severe actions must be guarded
    actions = {a["action_name"]: a for a in plan["candidate_evaluations"]}
    assert actions["ISOLATE"]["is_critical_guarded"]
    assert actions["CONTAIN"]["is_critical_guarded"]
    # Recommended action must not violate guardrails
    assert not actions[plan["recommended_action"]]["is_critical_guarded"]
