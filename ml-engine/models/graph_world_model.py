"""Dynamic Graph-Temporal World Model (G-FLOWWM) with Action-Conditioned Dynamics and Cyber-JEPA.

Realizes the foundational principles of a true Cyber World Model:
1. Dynamic Attributed Multigraph State G_t = (V_t, E_t) modeling host topology & flows.
2. Action-Conditioned Latent Transition P(z_{t+1} | z_t, a_t) enabling counterfactual imagination.
3. Self-Supervised Cyber-JEPA Latent Surprisal for principled zero-day anomaly discovery.
4. Topological Path Traversal modeling lateral movement across network edges.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import torch
import torch.nn as nn
import torch.nn.functional as F


@dataclass
class GraphWorldModelOutput:
    latent_state: torch.Tensor             # [B, N, D] current latent graph embedding
    predicted_latent_future: torch.Tensor  # [B, H, N, D] action-conditioned future rollout
    node_risk_logits: torch.Tensor         # [B, N] per-node compromise probability logits
    node_stage_logits: torch.Tensor        # [B, N, num_stages] per-node MITRE stage logits
    edge_flow_forecast: torch.Tensor       # [B, E, D_e] forecasted flow features on active edges
    jepa_surprisal: Optional[torch.Tensor] = None  # [B, N] latent prediction residual ||z - z_hat||^2
    action_impact_score: Optional[torch.Tensor] = None # [B] predicted risk reduction under action


class RelationalGraphMessagePassing(nn.Module):
    """Spatial message-passing layer over active network flows and topology edges."""

    def __init__(self, node_dim: int, edge_dim: int, hidden_dim: int):
        super().__init__()
        self.message_net = nn.Sequential(
            nn.Linear(2 * node_dim + edge_dim, hidden_dim),
            nn.GELU(),
            nn.LayerNorm(hidden_dim),
            nn.Linear(hidden_dim, hidden_dim),
        )
        self.node_update = nn.Sequential(
            nn.Linear(node_dim + hidden_dim, node_dim),
            nn.GELU(),
            nn.LayerNorm(node_dim),
        )

    def forward(
        self,
        nodes: torch.Tensor,       # [B, N, D_v]
        edge_index: torch.Tensor,  # [B, 2, E] (src, dst)
        edges: torch.Tensor,       # [B, E, D_e]
    ) -> torch.Tensor:
        b, n, _ = nodes.shape
        _, _, e = edge_index.shape

        if e == 0:
            return nodes

        # Gather source and target node representations for each edge
        src_idx = edge_index[:, 0, :]  # [B, E]
        dst_idx = edge_index[:, 1, :]  # [B, E]

        # Expand for gathering
        src_idx_exp = src_idx.unsqueeze(-1).expand(-1, -1, nodes.size(-1))
        dst_idx_exp = dst_idx.unsqueeze(-1).expand(-1, -1, nodes.size(-1))

        src_nodes = torch.gather(nodes, 1, src_idx_exp)  # [B, E, D_v]
        dst_nodes = torch.gather(nodes, 1, dst_idx_exp)  # [B, E, D_v]

        # Compute message along each edge
        edge_inputs = torch.cat([src_nodes, dst_nodes, edges], dim=-1)
        messages = self.message_net(edge_inputs)  # [B, E, D_h]

        # Aggregate messages at destination nodes via scatter mean
        aggregated = torch.zeros(b, n, messages.size(-1), device=nodes.device)
        dst_exp_msg = dst_idx.unsqueeze(-1).expand(-1, -1, messages.size(-1))
        aggregated.scatter_add_(1, dst_exp_msg, messages)

        # Update node states
        updated = self.node_update(torch.cat([nodes, aggregated], dim=-1))
        return updated


class GraphFlowWorldModel(nn.Module):
    """
    Action-Conditioned Graph-Temporal Cyber World Model with Cyber-JEPA Surprisal.
    """

    def __init__(
        self,
        node_dim: int = 16,
        edge_dim: int = 35,
        d_model: int = 64,
        num_stages: int = 14,
        num_actions: int = 6,
        action_dim: int = 16,
        horizon: int = 4,
        num_layers: int = 2,
    ):
        super().__init__()
        self.node_dim = node_dim
        self.edge_dim = edge_dim
        self.d_model = d_model
        self.num_stages = num_stages
        self.num_actions = num_actions
        self.horizon = horizon

        # Encoders for raw topology and flow features
        self.node_encoder = nn.Linear(node_dim, d_model)
        self.edge_encoder = nn.Linear(edge_dim, d_model)
        self.action_embedder = nn.Embedding(num_actions, action_dim)

        # Spatial Relational Graph Layers
        self.gnn_layers = nn.ModuleList([
            RelationalGraphMessagePassing(d_model, d_model, d_model)
            for _ in range(num_layers)
        ])

        # Action-Conditioned Dynamics Transition Module: P(z_{t+1} | z_t, a_t)
        self.action_transition = nn.Sequential(
            nn.Linear(d_model + action_dim, d_model * 2),
            nn.GELU(),
            nn.Linear(d_model * 2, d_model),
            nn.LayerNorm(d_model),
        )

        # Cyber-JEPA Predictor (Joint Embedding Predictive Architecture)
        self.jepa_predictor = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Linear(d_model, d_model),
            nn.LayerNorm(d_model),
        )

        # Task Heads
        self.risk_head = nn.Linear(d_model, 1)
        self.stage_head = nn.Linear(d_model, num_stages)
        self.edge_decoder = nn.Linear(d_model, edge_dim)

    def encode_graph(
        self,
        nodes: torch.Tensor,       # [B, N, D_v]
        edge_index: torch.Tensor,  # [B, 2, E]
        edges: torch.Tensor,       # [B, E, D_e]
    ) -> torch.Tensor:
        """Encode static/temporal graph state into latent node representations [B, N, D]."""
        h_nodes = F.gelu(self.node_encoder(nodes))
        h_edges = F.gelu(self.edge_encoder(edges))

        for gnn in self.gnn_layers:
            h_nodes = gnn(h_nodes, edge_index, h_edges)
        return h_nodes

    def forward(
        self,
        nodes: torch.Tensor,                  # [B, N, D_v]
        edge_index: torch.Tensor,             # [B, 2, E]
        edges: torch.Tensor,                  # [B, E, D_e]
        action_id: Optional[torch.Tensor] = None, # [B] or [B, 1] optional action integer (0=PASS)
        target_node_idx: Optional[torch.Tensor] = None, # [B] optional target of action (e.g. isolate host)
        observed_next_nodes: Optional[torch.Tensor] = None, # [B, N, D_v] for JEPA surprisal
    ) -> GraphWorldModelOutput:
        b, n, _ = nodes.shape
        z_t = self.encode_graph(nodes, edge_index, edges)  # [B, N, D]

        # 1. Action Conditioning
        if action_id is None:
            action_id = torch.zeros(b, dtype=torch.long, device=nodes.device)
        else:
            action_id = action_id.view(b)

        a_emb = self.action_embedder(action_id)  # [B, D_a]
        a_emb_nodes = a_emb.unsqueeze(1).expand(-1, n, -1)  # [B, N, D_a]

        # If action targets a specific node (e.g. ISOLATE_NODE), mask/modify its interaction
        # Action IDs: 0=PASS, 1=MONITOR, 2=DECEPTION, 3=RATE_LIMIT, 4=CONTAIN, 5=ISOLATE
        if target_node_idx is not None:
            for i in range(b):
                t_idx = target_node_idx[i]
                if 0 <= t_idx < n and action_id[i].item() in (4, 5):  # Contain or Isolate
                    # In imagination, dampening the isolated node's state representation
                    z_t[i, t_idx] = z_t[i, t_idx] * 0.1

        # 2. Multi-step Action-Conditioned Rollout in Latent Space
        imagined_futures = []
        curr_z = z_t
        for _ in range(self.horizon):
            delta = self.action_transition(torch.cat([curr_z, a_emb_nodes], dim=-1))
            curr_z = curr_z + delta
            imagined_futures.append(curr_z)
        predicted_latent_future = torch.stack(imagined_futures, dim=1)  # [B, H, N, D]

        # 3. Heads & Predictions
        node_risk_logits = self.risk_head(z_t).squeeze(-1)  # [B, N]
        node_stage_logits = self.stage_head(z_t)            # [B, N, num_stages]

        # Edge forecast (decode from src node representations)
        if edge_index.size(-1) > 0:
            src_idx = edge_index[:, 0, :].unsqueeze(-1).expand(-1, -1, z_t.size(-1))
            src_z = torch.gather(z_t, 1, src_idx)
            edge_flow_forecast = self.edge_decoder(src_z)
        else:
            edge_flow_forecast = torch.zeros(b, 0, self.edge_dim, device=nodes.device)

        # 4. Cyber-JEPA Latent Surprisal Calculation
        jepa_surprisal = None
        if observed_next_nodes is not None:
            # Target representation (StopGrad JEPA target)
            with torch.no_grad():
                z_target = self.encode_graph(observed_next_nodes, edge_index, edges).detach()
            # Predicted next state in latent space (step 1)
            z_pred_1 = self.jepa_predictor(predicted_latent_future[:, 0])
            # Latent cosine divergence + state-space prediction residual
            cos_div = 1.0 - F.cosine_similarity(z_pred_1, z_target, dim=-1)
            state_residual = F.mse_loss(nodes, observed_next_nodes, reduction="none").mean(dim=-1)
            jepa_surprisal = cos_div + 0.5 * state_residual  # [B, N]

        # 5. Action Impact Score: estimated risk reduction from base step to future horizon
        future_risk_logits = self.risk_head(predicted_latent_future[:, -1]).squeeze(-1)
        base_risk = torch.sigmoid(node_risk_logits).mean(dim=-1)
        future_risk = torch.sigmoid(future_risk_logits).mean(dim=-1)
        action_impact = (base_risk - future_risk).clamp(min=-1.0, max=1.0)

        return GraphWorldModelOutput(
            latent_state=z_t,
            predicted_latent_future=predicted_latent_future,
            node_risk_logits=node_risk_logits,
            node_stage_logits=node_stage_logits,
            edge_flow_forecast=edge_flow_forecast,
            jepa_surprisal=jepa_surprisal,
            action_impact_score=action_impact,
        )
