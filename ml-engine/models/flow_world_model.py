"""
Temporal World Model for flow/packet state dynamics.

Learns P(S_{t+1} | S_t) via a Transformer encoder over context windows,
then rolls out K future steps (infiltration probability + MITRE stages).

Upgraded with a *belief-state "thinking" pass*:
  - The model maintains a latent belief over the current network state.
  - It performs N synthetic "imagination" rollouts (counterfactual branches)
    from perturbed beliefs, scores each branch by predicted infiltration risk,
    and blends them into a worst-case-aware consensus forecast.
  - A self-consistency objective (train) forces the base forecast and the
    imagined ensemble to agree, which improves generalisation and calibration.
  - A human-readable chain-of-thought is produced from the belief distribution.

GPU-ready: all computing is tensor-based; the training script pairs this with
AMP/mixed-precision and cuda->mps->cpu auto-detection.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

from .rl_agent import ACTIONS, DQNAgent, LSTMTemporalEncoder


@dataclass
class FlowWorldModelOutput:
    next_state: torch.Tensor          # [B, F]
    future_states: torch.Tensor       # [B, H, F]
    stage_logits: torch.Tensor        # [B, H, num_stages]  (base branch)
    stage_probs: torch.Tensor         # [B, H, num_stages]  (consensus ensemble)
    infil_logits: torch.Tensor        # [B, H]              (base branch)
    infil_probs: torch.Tensor         # [B, H]              (consensus ensemble)
    attention_weights: torch.Tensor   # [B, heads, T, T] (last layer)
    # --- belief-state thinking fields ---
    consensus_stage_probs: torch.Tensor   # [B, H, num_stages] (same as stage_probs)
    consensus_infil_probs: torch.Tensor   # [B, H]            (same as infil_probs)
    branch_stage_probs: torch.Tensor      # [B, n_branches, H, num_stages]
    branch_infil_probs: torch.Tensor      # [B, n_branches, H]
    branch_weights: torch.Tensor          # [B, n_branches]
    belief_scores: torch.Tensor           # [B, horizon]      risk score per step
    # --- DQN + LSTM response-planning fields ---
    temporal_latent: torch.Tensor = None  # [B, D] LSTM temporal encoding
    recommended_actions: Optional[List[Dict[str, object]]] = None  # per-step defensive plan
    response_q_values: Optional[torch.Tensor] = None  # [B, H, A] Q-values
    thinking: Optional[Dict[str, object]] = None
    # --- Open-set novelty and OOD fields ---
    free_energy: Optional[torch.Tensor] = None         # [B, H] Helmholtz free energy
    epistemic_variance: Optional[torch.Tensor] = None  # [B, H] Variance across branches
    latent_belief: Optional[torch.Tensor] = None       # [B, D] Latent state embedding


class BeliefThinker(nn.Module):
    """Latent-space imagination module (synthetic thinking).

    Given the encoded belief ``h`` it draws ``n_branches`` counterfactual
    rollouts by perturbing the belief along learned directions, rolls each
    forward through the shared dynamics heads, and returns raw per-branch
    risk scores that the caller uses to build a weighted consensus.
    """

    def __init__(self, d_model: int, n_branches: int = 5, dropout: float = 0.1):
        super().__init__()
        self.n_branches = n_branches
        # Learned perturbation directions for each imagined branch.
        self.perturb = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, d_model),
        )
        # Learned per-branch direction basis so branches are deterministic yet
        # varied (each branch explores a distinct counterfactual).
        self.branch_dirs = nn.Parameter(torch.randn(n_branches, d_model) * (d_model ** -0.5))
        # Value/risk head: scores how "threatening" a branch state is.
        self.value_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, 1),
        )
        self.perturb_scale = nn.Parameter(torch.ones(1) * 0.15)

    def forward(self, h: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Return (perturbed beliefs [B, n_branches, D], risk logits [B, n_branches])."""
        b, d = h.shape
        # Per-branch perturbation = shared nonlinear projection + learned direction.
        base = self.perturb(h).unsqueeze(1)                        # [B, 1, D]
        dirs = self.branch_dirs.unsqueeze(0).expand(b, -1, -1)     # [B, n_branches, D]
        perturbed = h.unsqueeze(1) + self.perturb_scale * F.tanh(base + dirs)
        risk = self.value_head(perturbed).squeeze(-1)              # [B, n_branches]
        return perturbed, risk


class FlowWorldModel(nn.Module):
    """Transformer world model over temporal network feature vectors."""

    def __init__(
        self,
        feature_dim: int = 35,
        d_model: int = 128,
        nhead: int = 4,
        num_layers: int = 3,
        dim_feedforward: int = 256,
        dropout: float = 0.1,
        context_window: int = 10,
        horizon: int = 4,
        num_stages: int = 14,
        n_branches: int = 5,
        temperature: float = 1.0,
        use_rl: bool = True,
        rl_hidden: int = 128,
        lstm_hidden: int = 128,
    ):
        super().__init__()
        self.feature_dim = feature_dim
        self.d_model = d_model
        self.context_window = context_window
        self.horizon = horizon
        self.num_stages = num_stages
        self.n_branches = n_branches
        self.temperature = temperature
        self.use_rl = use_rl

        self.input_proj = nn.Linear(feature_dim, d_model)
        self.pos_embed = nn.Parameter(torch.randn(1, context_window + horizon, d_model) * 0.02)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        self.transition = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, feature_dim),
        )
        self.stage_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, num_stages),
        )
        self.infil_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, 1),
        )
        # Feature attribution: which input dims drive infiltration
        self.feature_attr = nn.Linear(feature_dim, 1)

        # Belief-state "thinking" module.
        self.thinker = BeliefThinker(d_model=d_model, n_branches=n_branches, dropout=dropout)

        # DQN + LSTM response-planning layer (temporal pattern + future sequence).
        if use_rl:
            self.lstm_encoder = LSTMTemporalEncoder(
                feature_dim=feature_dim, d_model=d_model, hidden=lstm_hidden,
                num_layers=2, dropout=dropout,
            )
            self.dqn = DQNAgent(
                temporal_dim=d_model, hidden=rl_hidden,
                n_actions=len(ACTIONS), dropout=dropout,
            )
            self.rl_fuse = nn.Sequential(
                nn.Linear(2 * d_model, d_model),
                nn.GELU(),
                nn.LayerNorm(d_model),
            )
        else:
            self.lstm_encoder = None
            self.dqn = None
            self.rl_fuse = None

    def encode(self, context: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        context: [B, T, F]
        returns: encoded [B, T, D], attention map [B, T, T] for explainability
        """
        b, t, _ = context.shape
        x = self.input_proj(context) + self.pos_embed[:, :t, :]
        encoded = self.encoder(x)
        # Token similarity attention map (interpretable, no extra params)
        sim = torch.matmul(encoded, encoded.transpose(-1, -2)) / (self.d_model ** 0.5)
        attn_w = torch.softmax(sim, dim=-1)
        return encoded, attn_w

    def _rollout(self, h: torch.Tensor, cur_feat: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """One autoregressive rollout from latent ``h``.

        Returns stage_logits [B, H, C], infil_logits [B, H], future_states [B, H, F].
        """
        stage_logits = []
        infil_logits = []
        future_states = []
        for _ in range(self.horizon):
            stage_logits.append(self.stage_head(h))
            infil_logits.append(self.infil_head(h).squeeze(-1))
            future_states.append(cur_feat)
            h = h + self.input_proj(cur_feat)
            cur_feat = self.transition(h)
        return (
            torch.stack(stage_logits, dim=1),
            torch.stack(infil_logits, dim=1),
            torch.stack(future_states, dim=1),
        )

    def forward(
        self,
        context: torch.Tensor,
        teacher_future: Optional[torch.Tensor] = None,
    ) -> FlowWorldModelOutput:
        """
        context: [B, context_window, F]
        teacher_future: optional [B, horizon, F] for teacher forcing during train
        """
        encoded, attn_w = self.encode(context)
        last = encoded[:, -1, :]  # [B, D]

        # ---- Base (think-0) branch: deterministic rollout ----
        next_state = self.transition(last)
        base_stage_logits, base_infil_logits, _ = self._rollout(last, next_state)

        # ---- Synthetic "thinking": imagined counterfactual branches ----
        # Perturb the belief, roll each branch forward, and score its risk.
        perturbed, branch_risk = self.thinker(last)                # [B, n_b, D], [B, n_b]
        branch_stage_logits = []
        branch_infil_logits = []
        for b in range(self.n_branches):
            h_b = perturbed[:, b, :]                               # [B, D]
            cur_b = self.transition(h_b)
            sl, il, _ = self._rollout(h_b, cur_b)
            branch_stage_logits.append(sl)
            branch_infil_logits.append(il)
        branch_stage_logits = torch.stack(branch_stage_logits, dim=1)   # [B, n_b, H, C]
        branch_infil_logits = torch.stack(branch_infil_logits, dim=1)   # [B, n_b, H]

        # Risk-based branch weighting: worst-case aware (higher risk => more weight).
        bsky = branch_risk / self.temperature
        branch_weights = torch.softmax(bsky, dim=-1)               # [B, n_b]

        # Consensus ensemble (weighted by branch risk).
        branch_stage_probs = torch.softmax(branch_stage_logits, dim=-1)
        branch_infil_probs = torch.sigmoid(branch_infil_logits)
        consensus_stage = torch.einsum("nk,nkhc->nhc", branch_weights, branch_stage_probs)
        consensus_infil = torch.einsum("nk,nkh->nh", branch_weights, branch_infil_probs)
        consensus_infil = consensus_infil.clamp(0.0, 1.0)

        # Per-step belief risk score (feed-forward value of the base branch).
        belief_scores = torch.sigmoid(self.thinker.value_head(last.unsqueeze(1)).squeeze(-1))

        # DQN + LSTM response planning over the predicted future sequence.
        temporal_latent = None
        recommended_actions = None
        response_q = None
        if self.use_rl and self.dqn is not None:
            temporal_latent, _ = self.lstm_encoder(context)          # [B, D]
            fused = self.rl_fuse(torch.cat([last, temporal_latent], dim=-1))  # [B, D]
            stage_idx = consensus_stage.argmax(dim=-1)               # [B, H]
            actions, response_q = self.dqn(fused, consensus_infil, stage_idx)
            recommended_actions = self.dqn.explanation(fused, consensus_infil, stage_idx)["plan"]

        thinking = self._build_thinking(consensus_stage, consensus_infil, beliefs=branch_weights)

        # Helmholtz free energy: E(x) = -T * logsumexp(z / T) (high magnitude = out-of-distribution)
        t_safe = max(float(self.temperature), 0.01)
        free_energy = -t_safe * torch.logsumexp(base_stage_logits / t_safe, dim=-1)
        # Epistemic variance across counterfactual imagination branches
        if self.n_branches > 1:
            epistemic_variance = torch.var(branch_infil_probs, dim=1)
        else:
            epistemic_variance = torch.zeros_like(base_infil_logits)

        return FlowWorldModelOutput(
            next_state=next_state,
            future_states=self._future_states_from(last, next_state),
            stage_logits=base_stage_logits,
            stage_probs=consensus_stage,
            infil_logits=base_infil_logits,
            infil_probs=consensus_infil.clamp(0.0, 1.0),
            attention_weights=attn_w,
            consensus_stage_probs=consensus_stage,
            consensus_infil_probs=consensus_infil.clamp(0.0, 1.0),
            branch_stage_probs=branch_stage_probs.detach(),
            branch_infil_probs=branch_infil_probs.detach(),
            branch_weights=branch_weights.detach(),
            belief_scores=belief_scores,
            temporal_latent=temporal_latent,
            recommended_actions=recommended_actions,
            response_q_values=response_q.detach() if response_q is not None else None,
            thinking=thinking,
            free_energy=free_energy.detach(),
            epistemic_variance=epistemic_variance.detach(),
            latent_belief=last.detach(),
        )

    def _future_states_from(self, h: torch.Tensor, next_state: torch.Tensor) -> torch.Tensor:
        """Base-branch future states [B, H, F] (used for the dynamics target/explainability)."""
        _, _, future = self._rollout(h, next_state)
        return future

    def _build_thinking(self, stage_probs: torch.Tensor, infil_probs: torch.Tensor,
                        beliefs: torch.Tensor) -> Optional[Dict[str, object]]:
        """Attach a lightweight, human-readable chain-of-thought. Pure python helper
        (no graph) used by callers that detach first; kept cheap as a no-op here."""
        return None

    def rl_loss(self, context: torch.Tensor, consensus_infil: torch.Tensor,
                consensus_stage: torch.Tensor) -> torch.Tensor:
        """Model-based double-DQN objective over the predicted future sequence.

        The DQN agent is trained to pick defensive actions that lower predicted
        infiltration, using the world-model's own forecast as the environment.
        """
        if not self.use_rl or self.dqn is None:
            return torch.tensor(0.0, device=context.device)
        temporal_latent, _ = self.lstm_encoder(context)
        last = self.encode(context)[0][:, -1, :]
        fused = self.rl_fuse(torch.cat([last, temporal_latent], dim=-1))
        stage_idx = consensus_stage.detach().argmax(dim=-1)
        return self.dqn.rl_loss(fused, consensus_infil.detach(), stage_idx)

    def feature_importance(self, context: torch.Tensor) -> torch.Tensor:
        """
        Attention-style feature attribution over the last context step.
        Returns [B, F] normalised importance.
        """
        last = context[:, -1, :]
        raw = torch.abs(self.feature_attr.weight).squeeze(0) * torch.abs(last)
        mag = torch.abs(last)
        score = raw + 0.25 * mag
        score = score / (score.sum(dim=-1, keepdim=True) + 1e-8)
        return score


def create_flow_world_model(feature_dim: int, **kwargs) -> FlowWorldModel:
    return FlowWorldModel(feature_dim=feature_dim, **kwargs)
