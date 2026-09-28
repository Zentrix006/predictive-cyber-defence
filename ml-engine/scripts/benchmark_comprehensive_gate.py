#!/usr/bin/env python3
"""Evidence-backed promotion gate for FLOWWM candidates.

This module deliberately does *not* manufacture metrics.  A candidate can only
be promoted when a passed campaign manifest and an independently generated
metrics artifact are supplied.  The metrics artifact must contain predictions
from the locked test partition; hand-written or random values are rejected.
"""

import sys
import json
import time
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
APP_ROOT = ROOT.parent / "backend"
sys.path.insert(0, str(APP_ROOT))

def compute_ece(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
    if probs.ndim > 1:
        confidences = np.max(probs, axis=-1)
        predictions = np.argmax(probs, axis=-1)
    else:
        confidences = np.maximum(probs, 1.0 - probs)
        predictions = (probs >= 0.5).astype(int)
    accuracies = (predictions == labels).astype(float)
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        in_bin = (confidences > bin_boundaries[i]) & (confidences <= bin_boundaries[i + 1])
        prop_in_bin = np.mean(in_bin)
        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(accuracies[in_bin])
            avg_confidence_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
    return float(ece)

REQUIRED_STAGES = {
    "reconnaissance", "initial_access", "credential_access",
    "lateral_movement", "command_and_control", "exfiltration", "impact",
}


def _blocked_report(checkpoint_path: Path, reason: str, output: Path) -> int:
    report = {
        "checkpoint": str(checkpoint_path),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "promotion_gate": {"overall_promotion_eligible": False, "blocked_reason": reason},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report["promotion_gate"], indent=2))
    return 2


def _load_metrics(path: Path) -> dict:
    if not path.exists():
        raise ValueError(f"metrics artifact does not exist: {path}")
    payload = json.loads(path.read_text())
    if payload.get("source") in {"synthetic", "mock", "hardcoded"}:
        raise ValueError("synthetic or hand-written metrics are not eligible")
    predictions_artifact = payload.get("predictions_artifact")
    if predictions_artifact in (None, ""):
        raise ValueError("metrics must reference the raw predictions artifact")
    prediction_path = Path(predictions_artifact)
    if not prediction_path.is_absolute():
        prediction_path = path.parent / prediction_path
    if not prediction_path.exists():
        raise ValueError(f"raw predictions artifact does not exist: {prediction_path}")
    if payload.get("partition") not in {"test", "test-known", "test-novel", "locked_test"}:
        raise ValueError("metrics must be computed from a locked test partition")
    required = {"binary_risk", "stage_forecasting", "state_transition", "novelty_detection", "topology_and_timing"}
    missing = required - set(payload.get("metrics", payload).keys())
    if missing:
        raise ValueError(f"metrics artifact missing pillars: {sorted(missing)}")
    return payload.get("metrics", payload)


def run_comprehensive_gate(checkpoint_path: Path, metrics_path: Path | None = None,
                           output: Path | None = None) -> int:
    print("=" * 80)
    print(" FLOWWM COMPREHENSIVE PROMOTION GATE & INTELLIGENCE BENCHMARK")
    print("=" * 80)
    
    data_dir = ROOT / "data"
    manifest_path = data_dir / "multistage_campaign_manifest.json"
    output = output or checkpoint_path.parent / "comprehensive_gate_report.json"
    
    if not manifest_path.exists():
        return _blocked_report(checkpoint_path, "manifest_missing", output)
        
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
        
    if manifest.get("status") != "PASSED":
        return _blocked_report(checkpoint_path, f"manifest_failed_closed:{manifest.get('reason', 'unknown')}", output)
    if metrics_path is None:
        return _blocked_report(checkpoint_path, "metrics_artifact_required", output)
    try:
        metrics = _load_metrics(metrics_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _blocked_report(checkpoint_path, f"invalid_metrics:{exc}", output)

    binary_metrics = metrics["binary_risk"]
    stage_metrics = metrics["stage_forecasting"]
    state_metrics = metrics["state_transition"]
    novelty_metrics = metrics["novelty_detection"]
    topo_metrics = metrics["topology_and_timing"]
    stage_support = stage_metrics.get("stage_support", {})
    missing_stages = sorted(REQUIRED_STAGES - set(stage_support))
    
    # Evaluate Acceptance Criteria
    gate_results = {
        "binary_risk_passed": binary_metrics.get("ece", 1.0) <= 0.08 and binary_metrics.get("malicious_f1", 0.0) > binary_metrics.get("lr_baseline_f1", 1.0),
        "stage_forecasting_passed": stage_metrics.get("macro_f1", 0.0) >= 0.65 and not missing_stages and all(v >= 2 for v in stage_support.values()),
        "state_transition_passed": state_metrics["state_forecast_mse"] < state_metrics["persistence_mse"],
        "novelty_detection_passed": novelty_metrics.get("auroc", 0.0) >= 0.85,
        "topology_prediction_passed": topo_metrics.get("edge_prediction_auroc", 0.0) >= 0.80,
    }
    
    gate_results["overall_promotion_eligible"] = all(gate_results.values())
    
    report = {
        "checkpoint": str(checkpoint_path),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metrics": {
            "binary_risk": binary_metrics,
            "stage_forecasting": {**stage_metrics, "missing_stages": missing_stages},
            "state_transition": state_metrics,
            "novelty_detection": novelty_metrics,
            "topology_and_timing": topo_metrics
        },
        "promotion_gate": gate_results
    }
    
    out_file = output
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=4))
        
    print(json.dumps(gate_results, indent=4))
    print(f"\nComprehensive Gate Report saved to {out_file}")
    return 0 if gate_results["overall_promotion_eligible"] else 2

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=str, default="/ml-engine/data/temporal_candidate_v2_7/candidate.pt")
    parser.add_argument("--metrics", type=Path, help="Metrics generated from locked-test predictions")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raise SystemExit(run_comprehensive_gate(Path(args.checkpoint), args.metrics, args.output))
