#!/usr/bin/env python3
"""Standardized baseline benchmark suite for Telemetry-V2 models.

Compares:
1. Persistence Forecast (Naive Baseline)
2. L2-Regularized Multi-Class Logistic Regression
3. FLOWWM World Model Candidate

Evaluates on the exact same holdout partition ('test') without leakage.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    mean_squared_error,
    precision_score,
    recall_score,
)
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.mitre_map import MITRE_STAGES
from features.telemetry_v2 import PreprocessingArtifact, TemporalWindows, validate_observations
from models.flow_world_model import FlowWorldModel


def compute_ece(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
    """Compute Expected Calibration Error for binary or confidence predictions."""
    if probs.ndim > 1:
        confidences = np.max(probs, axis=-1)
        predictions = np.argmax(probs, axis=-1)
    else:
        confidences = np.maximum(probs, 1.0 - probs)
        predictions = (probs >= 0.5).astype(int)
    accuracies = (predictions == labels).astype(float)
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    total = len(labels)
    if total == 0:
        return 0.0
    for i in range(n_bins):
        in_bin = (confidences > bin_boundaries[i]) & (confidences <= bin_boundaries[i + 1])
        prop_in_bin = np.mean(in_bin)
        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(accuracies[in_bin])
            avg_confidence_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
    return float(ece)


def run_benchmark(data_path: Path, checkpoint_path: Path, out_path: Path, batch_size: int = 128, device_name: str = "auto") -> dict:
    device = torch.device("cuda" if device_name == "auto" and torch.cuda.is_available() else "cpu" if device_name == "auto" else device_name)
    payload = torch.load(checkpoint_path, map_location=device, weights_only=False)
    artifact = PreprocessingArtifact(**payload["preprocessing"])
    config = payload["model_config"]

    model = FlowWorldModel(**config).to(device)
    model.load_state_dict(payload["model_state"])
    model.eval()
    malicious_temperature = float(payload.get("malicious_temperature", 1.0))

    frame = validate_observations(pd.read_csv(data_path))
    train_data = TemporalWindows(frame, artifact, "train")
    test_data = TemporalWindows(frame, artifact, "test")

    print(f"Loaded {len(train_data)} train sequences, {len(test_data)} test sequences.")

    # 1. Evaluate Persistence Forecast on Test Split
    print("Evaluating Persistence Baseline...")
    pers_state_mses = []
    pers_mal_true, pers_mal_pred = [], []
    pers_stage_true, pers_stage_pred = [], []

    for i in range(len(test_data)):
        x_hist, future, stage, mal = test_data[i]
        # Persistence predicts future states equal the last observed state
        last_state = x_hist[-1:]
        pers_future = np.repeat(last_state, future.shape[0], axis=0)
        pers_state_mses.append(np.mean((pers_future - future) ** 2))

        # Persistence predicts malicious equals last observed malicious (from features or indicator)
        # Last observed stage is unknown or inferred from last step
        for h in range(len(mal)):
            pers_mal_true.append(mal[h])
            pers_mal_pred.append(0.0)  # Naive baseline assumes normal continuity
            if stage[h] >= 0:
                pers_stage_true.append(stage[h])
                pers_stage_pred.append(0)

    persistence_metrics = {
        "model": "Persistence",
        "state_forecast_mse": float(np.mean(pers_state_mses)),
        "malicious_accuracy": float(np.mean(np.array(pers_mal_true) == np.array(pers_mal_pred))),
        "evaluated_sequences": len(test_data),
    }

    # 2. Evaluate Logistic Regression Baseline
    print("Training and Evaluating Logistic Regression Baseline...")
    # Extract flattened features for train
    X_tr, y_mal_tr, y_stage_tr = [], [], []
    sample_stride = max(1, len(train_data) // 5000)
    for i in range(0, len(train_data), sample_stride):
        x_hist, _, stage, mal = train_data[i]
        X_tr.append(x_hist.flatten())
        y_mal_tr.append(int(mal[0]))
        y_stage_tr.append(int(stage[0]))
    X_tr = np.array(X_tr)
    y_mal_tr = np.array(y_mal_tr)
    y_stage_tr = np.array(y_stage_tr)

    # Train binary LR for malicious activity
    lr_mal = LogisticRegression(max_iter=400, class_weight="balanced")
    lr_mal.fit(X_tr, y_mal_tr)

    # Train multi-class LR for stage
    valid_stages = y_stage_tr >= 0
    if valid_stages.sum() > 20 and len(np.unique(y_stage_tr[valid_stages])) > 1:
        lr_stage = LogisticRegression(max_iter=400, class_weight="balanced")
        lr_stage.fit(X_tr[valid_stages], y_stage_tr[valid_stages])
    else:
        lr_stage = None

    # Evaluate LR on test
    X_te, y_mal_te, y_stage_te = [], [], []
    for i in range(len(test_data)):
        x_hist, _, stage, mal = test_data[i]
        X_te.append(x_hist.flatten())
        y_mal_te.append(int(mal[0]))
        y_stage_te.append(int(stage[0]))
    X_te = np.array(X_te)
    y_mal_te = np.array(y_mal_te)
    y_stage_te = np.array(y_stage_te)

    lr_mal_probs = lr_mal.predict_proba(X_te)[:, 1] if hasattr(lr_mal, "predict_proba") else lr_mal.predict(X_te)
    lr_mal_preds = (lr_mal_probs >= 0.5).astype(int)
    lr_mal_acc = float(np.mean(lr_mal_preds == y_mal_te))
    lr_mal_f1 = float(f1_score(y_mal_te, lr_mal_preds, zero_division=0))
    lr_mal_rec = float(recall_score(y_mal_te, lr_mal_preds, zero_division=0))
    lr_mal_prec = float(precision_score(y_mal_te, lr_mal_preds, zero_division=0))

    lr_metrics = {
        "model": "Logistic Regression",
        "malicious_accuracy": lr_mal_acc,
        "malicious_f1": lr_mal_f1,
        "malicious_recall": lr_mal_rec,
        "malicious_precision": lr_mal_prec,
        "evaluated_sequences": len(test_data),
    }

    # 3. Evaluate FLOWWM Temporal Model
    print("Evaluating FLOWWM Temporal Model on Test Partition...")
    test_loader = DataLoader(test_data, batch_size=batch_size, shuffle=False)
    flow_state_mses = []
    flow_mal_true, flow_mal_probs = [], []
    flow_stage_true, flow_stage_preds = [], []

    with torch.no_grad():
        for x, future, stage, mal in test_loader:
            x, future = x.to(device), future.to(device)
            out = model(x)
            mse = F.mse_loss(out.future_states, future, reduction="none").mean(dim=[1, 2])
            flow_state_mses.extend(mse.cpu().tolist())

            probs = torch.sigmoid(out.infil_logits / max(malicious_temperature, 0.01)).cpu().numpy()
            flow_mal_probs.extend(probs[:, 0].tolist())
            flow_mal_true.extend(mal[:, 0].tolist())

            stage_logits = out.stage_logits.cpu().numpy()
            stage_true = stage.numpy()
            for b in range(len(stage_true)):
                if stage_true[b, 0] >= 0:
                    flow_stage_true.append(int(stage_true[b, 0]))
                    flow_stage_preds.append(int(np.argmax(stage_logits[b, 0])))

    flow_mal_probs = np.array(flow_mal_probs)
    flow_mal_true = np.array(flow_mal_true)

    flow_mal_preds = (flow_mal_probs >= 0.5).astype(int)

    flow_state_mse = float(np.mean(flow_state_mses))
    flow_mal_acc = float(np.mean(flow_mal_preds == flow_mal_true))
    flow_mal_f1 = float(f1_score(flow_mal_true, flow_mal_preds, zero_division=0))
    flow_mal_rec = float(recall_score(flow_mal_true, flow_mal_preds, zero_division=0))
    flow_mal_prec = float(precision_score(flow_mal_true, flow_mal_preds, zero_division=0))
    flow_mal_auprc = float(average_precision_score(flow_mal_true, flow_mal_probs)) if len(np.unique(flow_mal_true)) > 1 else 0.0
    flow_ece = compute_ece(flow_mal_probs, flow_mal_true)

    if len(flow_stage_true) > 0:
        stage_macro_f1 = float(f1_score(flow_stage_true, flow_stage_preds, average="macro", zero_division=0))
        stage_acc = float(np.mean(np.array(flow_stage_true) == np.array(flow_stage_preds)))
    else:
        stage_macro_f1, stage_acc = 0.0, 0.0

    flowwm_metrics = {
        "model": "FLOWWM (Telemetry-V2)",
        "state_forecast_mse": flow_state_mse,
        "state_improvement_over_persistence": float((persistence_metrics["state_forecast_mse"] - flow_state_mse) / max(persistence_metrics["state_forecast_mse"], 1e-6)),
        "malicious_accuracy": flow_mal_acc,
        "malicious_f1": flow_mal_f1,
        "malicious_recall": flow_mal_rec,
        "malicious_precision": flow_mal_prec,
        "malicious_auprc": flow_mal_auprc,
        "expected_calibration_error": flow_ece,
        "malicious_temperature": malicious_temperature,
        "stage_accuracy": stage_acc,
        "stage_macro_f1": stage_macro_f1,
        "stage_tokens_evaluated": len(flow_stage_true),
        "evaluated_sequences": len(test_data),
    }

    report = {
        "benchmark_dataset": str(data_path),
        "candidate_checkpoint": str(checkpoint_path),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "baselines": {
            "persistence": persistence_metrics,
            "logistic_regression": lr_metrics,
            "flowwm": flowwm_metrics,
        },
        "promotion_gate_evaluation": {
            "state_mse_beats_persistence": flow_state_mse < persistence_metrics["state_forecast_mse"],
            "f1_beats_logistic_regression": flow_mal_f1 >= lr_mal_f1,
            "calibration_within_tolerance": flow_ece <= 0.08,
            "overall_promotion_recommended": bool(
                flow_state_mse < persistence_metrics["state_forecast_mse"]
                and flow_mal_f1 >= lr_mal_f1
                and flow_ece <= 0.08
            ),
        },
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="/ml-engine/data/annotated_windows.csv")
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--out", default="/ml-engine/data/benchmark_report.json")
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--device", default="auto")
    args = parser.parse_args()
    run_benchmark(Path(args.data), Path(args.checkpoint), Path(args.out), args.batch_size, args.device)
