#!/usr/bin/env python3
"""Build a reviewed feedback manifest for candidate FLOWWM training.

The script preserves provenance and never replaces a serving checkpoint. It
converts append-only analyst/novelty JSONL records into a compact JSONL file
that can be joined to telemetry windows by event or novelty identifiers.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("data/feedback/analyst_feedback.jsonl"))
    parser.add_argument("--novelty", type=Path, default=Path("data/feedback/novelty_events.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("data/feedback/reviewed_training_manifest.jsonl"))
    args = parser.parse_args()
    records = []
    for path in (args.input, args.novelty):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = item.get("mitre_stage") or item.get("label")
            if not label:
                continue
            records.append({
                "feedback_id": item.get("feedback_id"),
                "novelty_id": item.get("novelty_id"),
                "label": label,
                "confidence": item.get("analyst_confidence"),
                "source_event_ids": item.get("source_event_ids", []),
                "evidence_refs": item.get("evidence_refs", []),
                "received_at": item.get("received_at"),
                "source": item.get("kind", "feedback"),
            })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(json.dumps({"records": len(records), "output": str(args.output)}))


if __name__ == "__main__":
    main()
