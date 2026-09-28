"""
Reinforcement-learning response layer: DQN over an LSTM temporal model.

Extends the world model with a *decision* layer. The base ``FlowWorldModel``
predicts a future sequence (infiltration trajectory + MITRE stages). This module
adds:

* :class:`LSTMTemporalEncoder` — an LSTM branch over the raw temporal context
  [B, T, F] that captures *sequential / ordering* patterns of network traffic
  (complementary to the transformer). It emits a temporal latent [B, D] and
  per-step cell state so it can model long-range temporal dependencies.
* :class:`DQNAgent` — a Double-DQN policy that, given the fused temporal state
  and the world model's own forecast, picks an optimal *defensive response
  action* at each step of the predicted future sequence. It is trained with a
  model-based objective against the world model's predicted infiltration
  (i.e. actions that lower predicted risk are reinforced).

GPU-ready: all tensor ops; pairs with the AMP/auto-device training script.
"""
from __future__ import annotations

import math
from typing import List, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


# Defensive response action space (index -> readable action + which kill-chain
# depth it is most effective against).
ACTIONS: List[str] = [
    "monitor",
    "block_src_ip",
    "isolate_host",
    "force_reauth",
    "terminate_session",
    "deploy_honeypot",
    "rate_limit",
    "patch_mitigate",
]
N_ACTIONS = len(ACTIONS)

# Per-action affinity to each MITRE stage (0..num_stages-1). Weights in [0,1]
# encode how appropriate an action is at a given kill-chain position. Used by
# the intrinsic (stage-aware) reward shaping term.
_STAGE_ACTION_AFFINITY: List[List[float]] = [
    #   analog of _SYNTHETIC_ORDER: recon, init-access, exec, persist,
    #   priv-esc, defense-evasion, credential-access, discovery, lateral,
    #   collection, c2, exfil, impact, unknown
    [0.90, 0.45, 0.25, 0.20, 0.15, 0.30, 0.40, 0.35, 0.30, 0.25, 0.30, 0.35, 0.45, 0.05],  # monitor
    [0.85, 0.80, 0.55, 0.45, 0.40, 0.50, 0.55, 0.45, 0.45, 0.40, 0.50, 0.55, 0.50, 0.05],  # block_src_ip
    [0.35, 0.70, 0.75, 0.70, 0.80, 0.70, 0.75, 0.70, 0.85, 0.75, 0.70, 0.75, 0.80, 0.05],  # isolate_host
    [0.20, 0.50, 0.60, 0.65, 0.75, 0.70, 0.85, 0.60, 0.55, 0.50, 0.45, 0.45, 0.40, 0.05],  # force_reauth
    [0.25, 0.55, 0.85, 0.70, 0.60, 0.65, 0.55, 0.50, 0.50, 0.45, 0.55, 0.60, 0.55, 0.05],  # terminate_session
    [0.60, 0.40, 0.30, 0.30, 0.35, 0.40, 0.35, 0.45, 0.50, 0.45, 0.60, 0.65, 0.55, 0.10],  # deploy_honeypot
    [0.30, 0.45, 0.40, 0.35, 0.40, 0.45, 0.40, 0.40, 0.45, 0.40, 0.50, 0.50, 0.45, 0.05],  # rate_limit
    [0.20, 0.30, 0.50, 0.55, 0.50, 0.55, 0.45, 0.45, 0.50, 0.50, 0.55, 0.55, 0.60, 0.05],  # patch_mitigate
]
_STAGE_ACTION = torch.tensor(_STAGE_ACTION_AFFINITY, dtype=torch.float32)  # [A, S]


class LSTMTemporalEncoder(nn.Module):
    """Bidirectional LSTM over the raw temporal context -> temporal latent.

    The output is fused with the transformer context inside ``FlowWorldModel``
    so the model can reason both over attention (global token relations) and
    recurrent order (sequential temporal dependencies).
    """

    def __init__(self, feature_dim: int, d_model: int, hidden: int = 128,
                 num_layers: int = 2, dropout: float = 0.1):
        super().__init__()
        self.proj_in = nn.Linear(feature_dim, hidden)
        self.lstm = nn.LSTM(
            hidden, hidden, num_layers=num_layers, batch_first=True,
            bidirectional=True, dropout=dropout if num_layers > 1 else 0.0,
        )
        self.proj_out = nn.Linear(2 * hidden, d_model)
        self.ln = nn.LayerNorm(d_model)

    def forward(self, context: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """context: [B, T, F] -> (temporal latent [B, D], last hidden [B, D])."""
        x = torch.tanh(self.proj_in(context))                 # [B, T, hidden]
        out, (h, _) = self.lstm(x)                            # out [B, T, 2H], h [2*L, B, H]
        # Concatenate final forward + backward hidden states -> temporal latent.
        hf = h[-2]                                            # forward  (last layer, direction 0)
        hb = h[-1]                                            # backward (last layer, direction 1)
        last = torch.cat([hf, hb], dim=-1)                    # [B, 2H]
        latent = self.ln(self.proj_out(last))                 # [B, D]
        pooled = self.ln(self.proj_out(out.mean(dim=1)))      # mean-pooled context [B, D]
        return latent, pooled


class QNetwork(nn.Module):
    """Fully-connected duelling-style Q-head.

    Input state vector [B, state_dim]; returns Q-values [B, n_actions] plus an
    advantage baseline used for the action-value explanation.
    """

    def __init__(self, state_dim: int, hidden: int = 128, n_actions: int = N_ACTIONS,
                 dropout: float = 0.1):
        super().__init__()
        self.n_actions = n_actions
        self.net = nn.Sequential(
            nn.Linear(state_dim, hidden),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, hidden),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.value = nn.Linear(hidden, 1)
        self.adv = nn.Linear(hidden, n_actions)

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        h = self.net(state)
        v = self.value(h)
        a = self.adv(h)
        q = v + a - a.mean(dim=-1, keepdim=True)              # duelling head
        return q


class DQNAgent(nn.Module):
    """Double-DQN response policy over the world model's predicted future.

    State per step = [temporal latent D] + [infiltration prob, stage scalar,
    step index, horizon-remaining] (the latter three live in a compact R=4
    "forecast feature" vector). The agent selects a defensive action for each
    predicted step. It is trained model-based: the world model's own predicted
    infiltration trajectory acts as the environment's next-state/reward source.
    """

    def __init__(self, temporal_dim: int, forecast_feat_dim: int = 4,
                 hidden: int = 128, n_actions: int = N_ACTIONS, gamma: float = 0.95,
                 tau: float = 0.005, dropout: float = 0.1):
        super().__init__()
        self.gamma = gamma
        self.tau = tau
        self.n_actions = n_actions
        self.state_dim = temporal_dim + forecast_feat_dim
        self.online = QNetwork(self.state_dim, hidden, n_actions, dropout)
        self.target = QNetwork(self.state_dim, hidden, n_actions, dropout)
        self.target.load_state_dict(self.online.state_dict())
        # Held constants shared with the training script.
        self.register_buffer("_stage_action", _STAGE_ACTION)

    # ---- feature shaping -------------------------------------------------
    def _forecast_feat(self, infil: torch.Tensor, stage_idx: torch.Tensor,
                       step: float, total: int) -> torch.Tensor:
        """Compact forecast feature vector [B, 4] describing the predicted step."""
        b = infil.size(0)
        remaining_m = float(total) - step
        feat = torch.stack([
            infil,                                               # [B]
            stage_idx.float() / max(1, self._stage_action.size(1) - 1),  # [B]
            torch.full((b,), float(step), device=infil.device),  # 0..1 progress
            torch.full((b,), remaining_m / max(1, total), device=infil.device),
        ], dim=-1)                                               # [B, 4]
        return feat

    def forward(self, temporal: torch.Tensor, infil: torch.Tensor,
                stage_idx: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Greedy action selection over a predicted future sequence.

        temporal: [B, D] LSTM temporal latent.
        infil:    [B, H]   predicted infiltration trajectory.
        stage_idx:[B, H]   predicted MITRE stage indices.

        Returns (actions [B, H], q_values [B, H, A]).
        """
        b, h = infil.shape
        inter = torch.arange(h, device=infil.device).float() / max(1, h)  # [H]
        all_q = []
        for t in range(h):
            feat = self._forecast_feat(infil[:, t], stage_idx[:, t],
                                       float(inter[t]), h)        # [B, 4]
            state = torch.cat([temporal, feat], dim=-1)          # [B, D+4]
            all_q.append(self.online(state))
        q = torch.stack(all_q, dim=1)                            # [B, H, A]
        actions = q.argmax(dim=-1)                               # [B, H]
        return actions, q

    def soft_policy(self, temporal: torch.Tensor, infil: torch.Tensor,
                    stage_idx: torch.Tensor, temperature: float = 1.0
                    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """A Boltzmann-soft selection; returns (probs [B,H,A], q [B,H,A])."""
        b, h = infil.shape
        inter = torch.arange(h, device=infil.device).float() / max(1, h)
        probs = []
        qs = []
        for t in range(h):
            feat = self._forecast_feat(infil[:, t], stage_idx[:, t],
                                       float(inter[t]), h)
            state = torch.cat([temporal, feat], dim=-1)
            q = self.online(state)
            qs.append(q)
            probs.append(F.softmax(q / max(temperature, 1e-3), dim=-1))
        return torch.stack(probs, dim=1), torch.stack(qs, dim=1)

    # ---- model-based RL objective ----------------------------------------
    def rl_loss(self, temporal: torch.Tensor, infil: torch.Tensor,
                stage_idx: torch.Tensor) -> torch.Tensor:
        """Model-based double-DQN loss.

        Treats the world model's infiltration trajectory as environment reward
        signal: acting on a step yields reward = affinity(action, stage)
        * (1 - infiltration) and transitions to the *next predicted step*
        (no discount issues since number of steps is fixed = horizon).

        The Bellman target uses the target network for the next step's Q.
        """
        b, h = infil.shape
        inter = torch.arange(h, device=infil.device).float() / max(1, h)
        affinity = self._stage_action.to(stage_idx.device)       # [A, S]
        total_loss = torch.tensor(0.0, device=infil.device)
        for t in range(h):
            feat = self._forecast_feat(infil[:, t], stage_idx[:, t],
                                       float(inter[t]), h)
            state = torch.cat([temporal, feat], dim=-1)
            q = self.online(state)                               # [B, A]
            # Intrinsic reward shaping. Stage-affinity (aff) tells us how
            # appropriate each action is for the current kill-chain stage.
            # Here rewards are scaled by *risk* (not safety): the more the world
            # model believes the host is compromised, the more value there is in
            # taking a mitigative (stage-appropriate) action. Passive monitoring
            # (action 0) is only rewarded when risk is low.
            aff = affinity[:, stage_idx[:, t].long()].t()    # [B, A] (cols = stage)
            risk = infil[:, t:t+1]                             # [B, 1]
            reward = aff * (0.2 + 1.3 * risk)                   # [B, A]
            reward[:, 0] = reward[:, 0] * (1.0 - risk).squeeze(-1)  # monitor only when safe
            # Greedy best action under behaviour policy (Double DQN).
            with torch.no_grad():
                best_action = q.argmax(dim=-1, keepdim=True)     # [B, 1]
                if t + 1 < h:
                    feat_n = self._forecast_feat(infil[:, t+1], stage_idx[:, t+1],
                                                 float(inter[t+1]), h)
                    state_n = torch.cat([temporal, feat_n], dim=-1)
                    q_next = self.target(state_n)                # [B, A]
                    target = reward.gather(1, best_action) + self.gamma * q_next.gather(1, best_action)
                else:
                    target = reward.gather(1, best_action)
            action_q = q.gather(1, best_action)
            total_loss = total_loss + F.smooth_l1_loss(action_q, target)
            # Soft-update target towards online.
            for tp, op in zip(self.target.parameters(), self.online.parameters()):
                tp.data.mul_(1.0 - self.tau).add_(self.tau * op.data)
        return total_loss / max(1, h)

    def explanation(self, temporal: torch.Tensor, infil: torch.Tensor,
                    stage_idx: torch.Tensor) -> dict:
        """Readable response plan for the API / UI."""
        actions, q = self.forward(temporal, infil, stage_idx)
        a_np = actions[0].detach().cpu().tolist()
        q_np = q[0].detach().cpu()                                # [H, A]
        plan = []
        for t in range(len(a_np)):
            a = a_np[t]
            plan.append({
                "step": t + 1,
                "action": ACTIONS[a],
                "action_index": a,
                "q_value": round(float(q_np[t, a].item()), 4),
                "confidence": round(float(F.softmax(q_np[t] / 1.0, dim=-1)[a].item()), 4),
            })
        # Overall best action to take right now.
        top = sorted(plan, key=lambda p: -p["q_value"])[0]
        return {"plan": plan, "recommended_action": top["action"],
                "recommended_step": top["step"], "n_actions": self.n_actions}


def create_dqn_agent(temporal_dim: int, **kwargs) -> DQNAgent:
    return DQNAgent(temporal_dim=temporal_dim, **kwargs)
