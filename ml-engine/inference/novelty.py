"""Open-set novelty scoring for FLOWWM forecasts.

Novelty is deliberately separate from the MITRE stage classifier.  An event
which does not resemble the training distribution must remain reviewable rather
than being forced into the nearest known attack stage.
"""
from __future__ import annotations

from typing import Any, Dict

import numpy as np


def score_novelty(
    stage_probabilities: np.ndarray,
    *,
    consensus_agreement: float | None = None,
    unknown_index: int | None = None,
) -> Dict[str, Any]:
    """Return a bounded open-set score and its evidence.

    This is an operational guardrail until a calibrated open-set head is
    trained.  It combines the explicit unknown class, low known-stage
    confidence, and disagreement between imagined futures.  All terms are
    retained in the response so analysts can audit why activity was flagged.
    """
    probs = np.asarray(stage_probabilities, dtype=np.float32).reshape(-1)
    if probs.size == 0:
        return {
            "score": 1.0,
            "state": "insufficient_evidence",
            "review_required": True,
            "components": {},
        }

    probs = np.clip(probs, 0.0, 1.0)
    total = float(probs.sum())
    if total > 0:
        probs = probs / total
    unknown_index = probs.size - 1 if unknown_index is None else int(unknown_index)
    unknown_probability = float(probs[unknown_index]) if 0 <= unknown_index < probs.size else 0.0
    known = np.delete(probs, unknown_index) if 0 <= unknown_index < probs.size else probs
    known_confidence = float(known.max()) if known.size else 0.0
    entropy = float(-(probs * np.log(np.clip(probs, 1e-9, 1.0))).sum() / np.log(max(2, probs.size)))
    disagreement = 1.0 - float(np.clip(consensus_agreement if consensus_agreement is not None else 1.0, 0.0, 1.0))
    score = float(np.clip(
        0.55 * unknown_probability
        + 0.20 * (1.0 - known_confidence)
        + 0.15 * entropy
        + 0.10 * disagreement,
        0.0,
        1.0,
    ))
    state = "novel_suspicious" if score >= 0.60 else (
        "novel_activity" if score >= 0.40 else "within_known_distribution"
    )
    return {
        "score": round(score, 4),
        "state": state,
        "review_required": score >= 0.40,
        "components": {
            "unknown_probability": round(unknown_probability, 4),
            "known_stage_confidence": round(known_confidence, 4),
            "normalized_entropy": round(entropy, 4),
            "branch_disagreement": round(disagreement, 4),
        },
    }
