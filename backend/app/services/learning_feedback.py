"""Durable, reviewable feedback intake for continuous FLOWWM learning.

Feedback is stored as append-only JSONL under the mounted ML data directory.
It is training input, not an immediate production-weight update.  Promotion
still requires the offline evaluation and model-gate workflow.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _root() -> Path:
    configured = os.getenv("ML_ENGINE_PATH", "/ml-engine")
    root = Path(configured) / "data" / "feedback"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _path(kind: str) -> Path:
    safe = "novelty_events" if kind == "novelty" else "analyst_feedback"
    return _root() / f"{safe}.jsonl"


def append_feedback(payload: Dict[str, Any], *, kind: str = "analyst") -> Dict[str, Any]:
    event = {
        "feedback_id": payload.get("feedback_id") or os.urandom(12).hex(),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "schema_version": "1.0",
        **payload,
    }
    destination = _path(kind)
    # Append is atomic for a single line and avoids rewriting historical data.
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
    return event


def learning_status() -> Dict[str, Any]:
    result: Dict[str, Any] = {"feedback_events": 0, "novelty_events": 0, "last_feedback_at": None}
    for kind, key in (("analyst", "feedback_events"), ("novelty", "novelty_events")):
        path = _path(kind)
        if not path.exists():
            continue
        count = 0
        last = None
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                count += 1
                try:
                    last = json.loads(line).get("received_at")
                except json.JSONDecodeError:
                    continue
        result[key] = count
        if last and (result["last_feedback_at"] is None or last > result["last_feedback_at"]):
            result["last_feedback_at"] = last
    result["training_policy"] = "append_only_feedback; candidate_retraining_required"
    result["promotion_required"] = True
    return result
