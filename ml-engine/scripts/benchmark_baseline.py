#!/usr/bin/env python3
"""
Benchmark FlowWorldModel vs Logistic Regression baseline on the same features.

Reports Precision / Recall / F1 / FPR for infiltration detection.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features.extract import (  # noqa: E402
    build_state_sequences,
    dataframe_to_feature_matrix,
    load_cicflowmeter_csv,
    load_kdd99_csv,
    load_nsl_kdd_csv,
    load_unsw_csv,
)
from models.flow_world_model import FlowWorldModel  # noqa: E402


def load_all_matrices(raw_dir: Path, max_rows: int):
    """Load UNSW + NSL-KDD + KDD99 + CIC-IDS2017 + CTU-13 (same as training)."""
    matrices = []
    loaded = []

    def add(df, name):
        matrices.append(dataframe_to_feature_matrix(df))
        loaded.append(name)

    unsw_t = raw_dir / "UNSW_NB15_training-set.csv"
    unsw_e = raw_dir / "UNSW_NB15_testing-set.csv"
    nsl = raw_dir / "NSL_KDD_Train.csv"
    kdd = raw_dir / "kddcup99" / "kddcup.data_10_percent.txt"

    if unsw_t.exists():
        add(load_unsw_csv(unsw_t, max_rows=max_rows), "UNSW-train")
    if unsw_e.exists():
        add(load_unsw_csv(unsw_e, max_rows=max_rows // 2), "UNSW-test")
    if nsl.exists():
        add(load_nsl_kdd_csv(nsl, max_rows=max_rows // 2), "NSL-KDD")
    if kdd.exists():
        add(load_kdd99_csv(kdd, max_rows=max_rows), "KDD99")
    cic = raw_dir / "cicids2017"
    if cic.exists():
        for f in sorted(cic.glob("*.csv")):
            add(load_cicflowmeter_csv(f, max_rows=max_rows // 3), f"cic-{f.stem}")
    for f in raw_dir.glob("CTU13_*.csv"):
        add(load_cicflowmeter_csv(f, max_rows=max_rows // 3), f"ctu-{f.stem}")
    return matrices, loaded


def metrics(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / max(fp + tn, 1)
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fpr),
        "auc_roc": float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=str(ROOT / "data" / "raw"))
    parser.add_argument("--checkpoint", default=str(ROOT / "data" / "checkpoints" / "flow_world_model.pt"))
    parser.add_argument("--out", default=str(ROOT / "data" / "benchmarks" / "baseline_comparison.json"))
    parser.add_argument("--max-rows", type=int, default=40000)
    parser.add_argument("--context", type=int, default=10)
    parser.add_argument("--horizon", type=int, default=4)
    args = parser.parse_args()

    raw = Path(args.data_dir)
    matrices, loaded = load_all_matrices(raw, args.max_rows)
    Xs_c, Ys_i = [], []
    feature_names = matrices[0].feature_names
    for m in matrices:
        X_ctx, _, _, Y_infil = build_state_sequences(m, args.context, args.horizon)
        Xs_c.append(X_ctx)
        Ys_i.append(Y_infil)
    X_ctx = np.concatenate(Xs_c, axis=0)
    Y_infil = np.concatenate(Ys_i, axis=0)

    # Use max infiltration label in horizon as positive class
    y = (Y_infil.max(axis=1) > 0).astype(np.int64)
    # Flatten context for logistic regression
    X_flat = X_ctx.reshape(len(X_ctx), -1)

    X_tr, X_te, y_tr, y_te, ctx_tr, ctx_te = train_test_split(
        X_flat, y, X_ctx, test_size=0.2, random_state=42, stratify=y if y.sum() and (y == 0).sum() else None
    )

    # --- Logistic Regression baseline ---
    lr = LogisticRegression(max_iter=500, n_jobs=-1, class_weight="balanced")
    lr.fit(X_tr, y_tr)
    lr_prob = lr.predict_proba(X_te)[:, 1]
    lr_metrics = metrics(y_te, lr_prob)

    # --- World Model ---
    ckpt_path = Path(args.checkpoint)
    if not ckpt_path.exists():
        raise FileNotFoundError(f"Checkpoint not found: {ckpt_path}. Train first with train_real.py")
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    model = FlowWorldModel(
        feature_dim=ckpt["feature_dim"],
        context_window=ckpt["context_window"],
        horizon=ckpt["horizon"],
        num_stages=ckpt["num_stages"],
    )
    model.load_state_dict(ckpt["model_state"])
    model.eval()
    with torch.no_grad():
        out = model(torch.from_numpy(ctx_te.astype(np.float32)))
        wm_prob = out.infil_probs.max(dim=1).values.numpy()
    wm_metrics = metrics(y_te, wm_prob)

    report = {
        "dataset": ", ".join(loaded),
        "n_test": int(len(y_te)),
        "logistic_regression": lr_metrics,
        "world_model": wm_metrics,
        "improvement_f1": float(wm_metrics["f1"] - lr_metrics["f1"]),
        "improvement_fpr": float(lr_metrics["false_positive_rate"] - wm_metrics["false_positive_rate"]),
        "notes": "World model uses temporal context + K-step infiltration head; LR uses flattened context windows.",
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
