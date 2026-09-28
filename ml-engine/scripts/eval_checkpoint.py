"""Evaluate any FlowWorldModel checkpoint on the canonical train/val split.

Reuses train_real's exact data pipeline, split (seed 42), and metrics so that
multiple checkpoints can be compared head-to-head on an identical validation set.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import train_real  # noqa: E402
from scripts.train_real import (  # noqa: E402
    MITRE_STAGES,
    FlowWorldModel,
    SequenceDataset,
    build_state_sequences,
    load_all_matrices,
    per_class_metrics,
    pick_device,
    source_tail_split,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a FlowWorldModel checkpoint")
    parser.add_argument("--checkpoint", type=str, required=True)
    parser.add_argument("--max-rows", type=int, default=30000)
    parser.add_argument("--context", type=int, default=10)
    parser.add_argument("--horizon", type=int, default=4)
    parser.add_argument("--n-branches", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()

    ckpt = torch.load(args.checkpoint, map_location="cpu")
    meta = ckpt.get("meta", {})
    feature_dim = ckpt.get("feature_dim") or meta.get("feature_dim") or 35
    context = ckpt.get("context_window") or args.context
    horizon = ckpt.get("horizon") or args.horizon
    n_branches = ckpt.get("n_branches") or args.n_branches
    num_stages = ckpt.get("num_stages") or len(MITRE_STAGES)
    datasets = ckpt.get("datasets") or meta.get("datasets") or []

    device = pick_device(args.device)

    matrices, loaded_names = load_all_matrices(train_real.ROOT / "data" / "raw", args.max_rows)
    Xs, Yns, Yss, Yis, sequence_lengths = [], [], [], [], []
    for m in matrices:
        x, yn, ys, yi = build_state_sequences(m, context, horizon)
        Xs.append(x); Yns.append(yn); Yss.append(ys); Yis.append(yi)
        sequence_lengths.append(len(x))

    X = np.concatenate(Xs, axis=0)
    Y_next = np.concatenate(Yns, axis=0)
    Y_stage = np.concatenate(Yss, axis=0)
    Y_infil = np.concatenate(Yis, axis=0)

    dataset = SequenceDataset(X, Y_next, Y_stage, Y_infil)
    _train_ds, val_ds = source_tail_split(dataset, sequence_lengths, context, horizon)
    n_val = len(val_ds)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)

    model = FlowWorldModel(
        feature_dim=feature_dim,
        context_window=context,
        horizon=horizon,
        num_stages=num_stages,
        n_branches=n_branches,
        use_rl=True,
    ).to(device)
    model.load_state_dict(ckpt["model_state"], strict=False)
    model.eval()

    all_pred, all_lbl, all_infil_p, all_infil_l = [], [], [], []
    import torch.nn.functional as F
    val_loss = 0.0
    with torch.no_grad():
        for xb, ynext, ystage, yinfil in val_loader:
            xb = xb.to(device); ynext = ynext.to(device)
            ystage = ystage.to(device); yinfil = yinfil.to(device)
            out = model(xb)
            val_loss += (
                F.mse_loss(out.next_state, ynext)
                + 1.5 * F.cross_entropy(out.stage_logits.reshape(-1, out.stage_logits.size(-1)), ystage.reshape(-1))
                + 1.25 * F.binary_cross_entropy_with_logits(out.infil_logits, yinfil)
            ).item() * len(xb)
            pred = out.stage_probs.argmax(dim=-1)
            all_pred.append(pred.reshape(-1).cpu().numpy())
            all_lbl.append(ystage.reshape(-1).cpu().numpy())
            all_infil_p.append(out.infil_probs.reshape(-1).cpu().numpy())
            all_infil_l.append(yinfil.reshape(-1).cpu().numpy())

    val_loss /= n_val
    preds = np.concatenate(all_pred)
    labels = np.concatenate(all_lbl)
    acc = float((preds == labels).mean())
    per_stage, macro = per_class_metrics(preds, labels, num_stages, MITRE_STAGES)
    attack_macro_f1 = float(np.mean([row["f1"] for row in per_stage[:-1]]))
    infil_p = np.concatenate(all_infil_p)
    infil_l = np.concatenate(all_infil_l)
    infil_acc = float(((infil_p > 0.5).astype(int) == infil_l).mean())

    print(f"Checkpoint : {args.checkpoint}")
    print(f"Data       : {len(X)} sequences, {feature_dim} features, val={n_val} (source-tail, embargo={context + horizon - 1})")
    print(f"Datasets   : {', '.join(datasets or loaded_names)}")
    print(f"val_loss={val_loss:.4f}  stage_acc={acc:.4f}  "
          f"macro-F1={macro['f1']:.4f}  attack-macro-F1={attack_macro_f1:.4f}  infil_acc={infil_acc:.4f}")
    print("Per-stage (precision / recall / F1 / count):")
    for r in per_stage:
        flag = "" if r["f1"] > 0 or r["count"] > 0 else "    (zero support)"
        print(f"  {r['stage']:<20} {r['precision']:.4f} {r['recall']:.4f} "
              f"{r['f1']:.4f} {r['count']:>7}{flag}")


if __name__ == "__main__":
    main()
