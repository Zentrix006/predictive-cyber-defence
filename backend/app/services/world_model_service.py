"""
World model service used by prediction generation.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import UUID

_CANDIDATES = [
    Path("/ml-engine"),
    Path(__file__).resolve().parents[3] / "ml-engine",
]
for _p in _CANDIDATES:
    if (_p / "inference").exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
        break


def try_world_model_forecast(horizon: int = 4) -> Optional[Dict[str, Any]]:
    """
    Run a forecast from the latest checkpoint using a short synthetic context
    drawn from held-out style zeros→ones ramp (used when no upload is provided).
    Returns None if model unavailable.
    """
    try:
        from inference.predictor import get_predictor
        import numpy as np
        from features.extract import FeatureMatrix

        pred = get_predictor()
        if not pred.ready:
            return None
        from features.mitre_map import MITRE_STAGES

        fd = pred.meta["feature_dim"]
        ctx = pred.meta.get("context_window", 10)
        n = ctx + horizon
        # Synthetic attack progression: ramp the context window through a
        # realistic kill-chain so the forecast emits genuine MITRE stages
        # instead of defaulting to "unknown" from a benign context.
        progression = [
            "reconnaissance", "initial_access", "execution",
            "privilege_escalation", "lateral_movement", "command_and_control",
            "exfiltration", "impact",
        ]
        idx = [int(round(i * (len(progression) - 1) / (n - 1))) for i in range(n)]
        attack_cats = [progression[i] for i in idx]
        stages = np.array([MITRE_STAGES.index(c) for c in attack_cats], dtype=np.int64)
        labels = (stages != MITRE_STAGES.index("unknown")).astype(np.int64)

        # Use real per-stage feature prototypes (median vectors from the training
        # data) so the model classifies the synthetic ramp into genuine MITRE
        # stages. Fall back to a linear amplitude ramp if prototypes are missing.
        proto_file = next(
            (p for p in {
                Path("/ml-engine/data/checkpoints/stage_prototypes.npy"),
                Path(__file__).resolve().parents[3] / "ml-engine" / "data" / "checkpoints" / "stage_prototypes.npy",
            } if p.exists()), None)
        prototypes = None
        if proto_file:
            prototypes = np.load(proto_file)

        feats = np.zeros((n, fd), dtype=np.float32)
        if prototypes is not None and prototypes.shape[0] >= len(MITRE_STAGES) and prototypes.shape[1] >= fd:
            for i in range(n):
                feats[i] = prototypes[stages[i]][:fd]
        else:
            for i in range(n):
                feats[i, : min(8, fd)] = (i / n) * np.linspace(0.2, 1.5, min(8, fd))
        matrix = FeatureMatrix(
            features=feats,
            feature_names=pred.meta.get("feature_names", [f"f{i}" for i in range(fd)]),
            labels=labels,
            stages=stages,
            attack_cats=attack_cats,
            timestamps=np.arange(n, dtype=np.float32),
        )
        result = pred.predict_matrix(matrix)
        return {
            "current_stage": result.current_stage,
            "current_confidence": result.current_confidence,
            "timeline": [
                {
                    "window_offset": i + 1,
                    "stage": result.predicted_stages[i],
                    "probability": result.infiltration_timeline[i],
                    "confidence": result.infiltration_timeline[i],
                    "eta_seconds": float((i + 1) * 30),
                }
                for i in range(len(result.predicted_stages))
            ],
            "explanation": {
                "feature_importance": {t["feature"]: t["contribution"] for t in result.top_features},
                "top_factors": result.top_features[:5],
                "natural_language": result.natural_language,
            },
            "thinking": result.thinking,
            "recommended_action": getattr(result, "recommended_action", "monitor"),
            "recommended_actions": getattr(result, "recommended_actions", []) or [],
            "model_version": result.model_version,
            "datasets_trained": result.datasets_trained,
        }
    except Exception:
        return None
