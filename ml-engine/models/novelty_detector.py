"""Tri-Factor Open-Set Novelty Detection Engine for Network Telemetry.

Computes out-of-distribution (OOD) and novel behavior metrics by combining:
1. World Dynamics Surprisal: Feature prediction residual ||S_{t+1} - S_hat_{t+1}||^2
2. Free-Energy OOD Score: Helmholtz free-energy over stage logits
3. Epistemic Disagreement: Variance across counterfactual imagination branches
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import deque
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import torch
import torch.nn.functional as F


@dataclass
class NoveltyAssessment:
    novelty_score: float             # Calibrated composite novelty score in [0.0, 1.0]
    is_novel: bool                  # Binary flag (novelty_score >= threshold)
    surprisal_score: float          # Next-state prediction error
    energy_score: float             # Free energy score (higher = more anomalous)
    epistemic_variance: float       # Disagreement between counterfactual branches
    top_anomalous_features: List[Dict[str, float]]  # Feature-level attribution for surprisal
    summary: str                    # Human-readable summary of novelty reason
    effective_threshold: float = 0.65  # Dynamic conformal threshold applied
    is_mimicry_detected: bool = False  # True if perturbation mimicry pattern is active


class TriFactorNoveltyDetector:
    """Evaluates whether an observed network state sequence represents novel/unseen behavior."""

    def __init__(
        self,
        novelty_threshold: float = 0.65,
        energy_scale: float = 10.0,
        surprisal_scale: float = 2.0,
        epistemic_scale: float = 0.15,
        feature_names: Optional[List[str]] = None,
        adaptive_conformal: bool = True,
        conformal_alpha: float = 0.05,
    ):
        self.novelty_threshold = novelty_threshold
        self.energy_scale = energy_scale
        self.surprisal_scale = surprisal_scale
        self.epistemic_scale = epistemic_scale
        self.feature_names = feature_names or []
        self.adaptive_conformal = adaptive_conformal
        self.conformal_alpha = conformal_alpha
        self.baseline_scores: deque[float] = deque(maxlen=200)

    def update_baseline(self, scores: Union[float, List[float], np.ndarray]) -> None:
        """Register verified benign observations to calibrate conformal threshold."""
        if isinstance(scores, (int, float)):
            self.baseline_scores.append(float(scores))
        else:
            for s in scores:
                self.baseline_scores.append(float(s))

    def get_effective_threshold(self) -> float:
        """Compute adaptive conformal threshold or return default static threshold."""
        if not self.adaptive_conformal or len(self.baseline_scores) < 20:
            return self.novelty_threshold
        q = float(np.quantile(list(self.baseline_scores), 1.0 - self.conformal_alpha))
        return float(np.clip(q + 0.05, 0.35, self.novelty_threshold))

    def assess(
        self,
        current_state: np.ndarray,
        predicted_future: np.ndarray,
        free_energy: float,
        epistemic_var: float,
        actual_next_state: Optional[np.ndarray] = None,
        auto_update_baseline: bool = True,
    ) -> NoveltyAssessment:
        """
        Assess novelty for a single sequence or window.
        - current_state: [F] or [T, F] observed feature vector(s)
        - predicted_future: [H, F] predicted future features from world model
        - free_energy: scalar free energy from model output
        - epistemic_var: scalar branch variance
        - actual_next_state: [F] optional observed next state to compute true surprisal;
          if None, evaluates self-consistency between current state and step-1 prediction
        """
        # 1. Surprisal calculation
        pred_next = predicted_future[0] if predicted_future.ndim > 1 else predicted_future
        target = actual_next_state if actual_next_state is not None else current_state[-1] if current_state.ndim > 1 else current_state
        
        diff = np.abs(target - pred_next)
        surprisal = float(np.mean(diff ** 2))

        # Identify top contributing features to surprisal
        top_indices = np.argsort(diff)[::-1][:5]
        top_features = []
        for idx in top_indices:
            name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            top_features.append({"feature": name, "deviation": float(diff[idx])})

        # 2. Free-energy normalization (sigmoid scaled around energy_scale)
        norm_energy = float(1.0 / (1.0 + np.exp(-(free_energy - 0.0) / max(self.energy_scale, 1e-4))))

        # 3. Surprisal normalization
        norm_surprisal = float(1.0 - np.exp(-surprisal / max(self.surprisal_scale, 1e-4)))

        # 4. Epistemic variance normalization
        norm_epistemic = float(1.0 - np.exp(-epistemic_var / max(self.epistemic_scale, 1e-4)))

        # Composite novelty score: weighted blend
        # Surprisal (40%) + Free Energy (35%) + Epistemic Disagreement (25%)
        composite = 0.40 * norm_surprisal + 0.35 * norm_energy + 0.25 * norm_epistemic
        composite = float(np.clip(composite, 0.0, 1.0))

        # 5. Adversarial Perturbation Mimicry & Conformal Thresholding
        effective_thresh = self.get_effective_threshold()
        is_mimicry = bool((norm_energy > 0.48 or norm_epistemic > 0.45) and (norm_surprisal < 0.15))

        reasons = []
        if norm_surprisal > 0.5:
            reasons.append(f"dynamics surprisal ({surprisal:.3f})")
        if norm_energy > 0.6:
            reasons.append(f"open-set free energy ({free_energy:.2f})")
        if norm_epistemic > 0.5:
            reasons.append(f"counterfactual branch disagreement ({epistemic_var:.4f})")
        if is_mimicry:
            effective_thresh = min(effective_thresh, 0.45)
            reasons.append("adversarial perturbation mimicry (suppressed surprisal with anomalous free-energy)")

        is_novel = bool(composite >= effective_thresh or is_mimicry)

        # Update baseline on verified benign states if requested
        if auto_update_baseline and not is_novel and not is_mimicry:
            self.baseline_scores.append(composite)

        # Build human-readable summary
        if is_novel:
            summary = f"Novel network behavior detected driven by: {', '.join(reasons) if reasons else 'composite anomaly'}."
        else:
            summary = "Behavior consistent with known network dynamics."

        return NoveltyAssessment(
            novelty_score=composite,
            is_novel=is_novel,
            surprisal_score=surprisal,
            energy_score=free_energy,
            epistemic_variance=epistemic_var,
            top_anomalous_features=top_features,
            summary=summary,
            effective_threshold=effective_thresh,
            is_mimicry_detected=is_mimicry,
        )
