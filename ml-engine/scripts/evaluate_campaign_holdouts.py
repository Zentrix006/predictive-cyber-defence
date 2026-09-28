#!/usr/bin/env python3
"""Run a real, fail-closed FLOWWM holdout evaluation.

All reported metrics come from the candidate checkpoint and locked test
partition. This script deliberately refuses to manufacture stage support or
accuracy values.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_baselines_v2 import run_benchmark


def evaluate_holdouts(data_path: Path, checkpoint_path: Path, output_path: Path,
                      batch_size: int = 128, device: str = "auto") -> dict:
    frame = pd.read_csv(data_path, usecols=["partition", "capture_id", "stage", "malicious"])
    test = frame[frame["partition"] == "test"].copy()
    if test.empty:
        raise ValueError("No locked test partition is available")
    captures = sorted(test["capture_id"].dropna().astype(str).unique().tolist())
    if len(captures) < 2:
        raise ValueError("Holdout must contain at least two independent captures")
    support = {
        "captures": captures,
        "rows": int(len(test)),
        "supported_stage_rows": int((test["stage"] >= 0).sum()),
        "stage_counts": {
            str(int(stage)): int(count)
            for stage, count in test.loc[test["stage"] >= 0, "stage"].value_counts().sort_index().items()
        },
    }
    benchmark_path = output_path.with_suffix(".benchmark.json")
    benchmark = run_benchmark(data_path, checkpoint_path, benchmark_path, batch_size, device)
    result = {
        "evaluation_type": "real_locked_campaign_holdout",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": str(data_path),
        "checkpoint": str(checkpoint_path),
        "holdout_support": support,
        "benchmark": benchmark,
        "promotion_eligible": bool(
            benchmark.get("promotion_gate_evaluation", {}).get("overall_promotion_recommended", False)
            and all(int(value) > 0 for value in support["stage_counts"].values())
        ),
        "limitations": [
            "Metrics apply only to the observed test captures and supported stages.",
            "Absent stage support cannot establish recall for that stage.",
            "Promotion requires independent campaigns with support for every promoted stage and calibrated probabilities.",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="/ml-engine/data/annotated_windows.csv")
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--out", default="/ml-engine/data/campaign_evaluation_report.json")
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--device", default="auto")
    args = parser.parse_args()
    evaluate_holdouts(Path(args.data), Path(args.checkpoint), Path(args.out), args.batch_size, args.device)
