#!/usr/bin/env python3
"""
Train FlowWorldModel on UNSW-NB15 + NSL-KDD + KDD99 + CIC-IDS2017 (+ any
extra CSVs in data/raw).

Upgrades over the baseline trainer:
  * Synthetic "thinking" curriculum — injects plausible multi-step MITRE attack
    progressions so the model learns *ordering* of stages even where the raw
    datasets are dominated by benign/unknown rows (class imbalance).
  * Self-supervised consistency objective — the base forecast must agree with
    the belief-state imagination ensemble (see flow_world_model.py).
  * Linear-warmup + cosine LR schedule and AdamW.
  * GPU-ready mixed precision (AMP autocast + GradScaler) with
    --device auto (cuda -> mps -> cpu).
  * Rich per-stage metrics (precision/recall/F1/AUC) written to history.

Usage (inside backend container, which mounts /ml-engine):
  python /ml-engine/scripts/train_real.py --epochs 8 --max-rows 120000 --device auto
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset, Subset, WeightedRandomSampler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features.extract import (  # noqa: E402
    build_state_sequences,
    dataframe_to_feature_matrix,
    detect_cicflowmeter,
    load_cicflowmeter_csv,
    load_kdd99_csv,
    load_nsl_kdd_csv,
    load_unsw_csv,
)
from features.mitre_map import MITRE_STAGES  # noqa: E402
from models.flow_world_model import FlowWorldModel  # noqa: E402

# A realistic "attack chain" ordering used by the synthetic curriculum: stages
# later in this list are strictly further along the kill chain. Windows whose
# synthetic targets are swapped use these to build a progressive rollout.
_SYNTHETIC_ORDER = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]
_STAGE_TO_POS = {s: i for i, s in enumerate(_SYNTHETIC_ORDER)}


def pick_device(device_arg: str) -> torch.device:
    """Resolve the best device: explicit, or auto cuda -> mps -> cpu."""
    if device_arg != "auto":
        return torch.device(device_arg)
    if torch.cuda.is_available():
        print(f"  -> using CUDA device {torch.cuda.get_device_name(0)}")
        return torch.device("cuda")
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        print("  -> using Apple MPS")
        return torch.device("mps")
    print("  -> no accelerator found, using CPU")
    return torch.device("cpu")


class SequenceDataset(Dataset):
    def __init__(self, X, Y_next, Y_stage, Y_infil):
        self.X = torch.from_numpy(X)
        self.Y_next = torch.from_numpy(Y_next)
        self.Y_stage = torch.from_numpy(Y_stage)
        self.Y_infil = torch.from_numpy(Y_infil).float()

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.Y_next[idx], self.Y_stage[idx], self.Y_infil[idx]


def build_stage_prototypes(X: np.ndarray, Y_stage: np.ndarray, num_stages: int) -> np.ndarray:
    """Build robust, telemetry-derived state prototypes for each MITRE stage.

    These are used only to construct internally consistent imagined rollouts
    during training.  They are medians of observed flow states, never hand-made
    feature ramps, and are not used for validation or live inference.
    """
    last_observed = X[:, -1, :]
    next_stage = Y_stage[:, 0]
    global_median = np.median(last_observed, axis=0).astype(np.float32)
    prototypes = np.empty((num_stages, X.shape[-1]), dtype=np.float32)
    for stage in range(num_stages):
        rows = last_observed[next_stage == stage]
        prototypes[stage] = (
            np.median(rows, axis=0).astype(np.float32) if len(rows) >= 8 else global_median
        )
    return prototypes


def synthesize_progressions(
    x: torch.Tensor,
    ynext: torch.Tensor,
    ystage: torch.Tensor,
    yinfil: torch.Tensor,
    stage_prototypes: torch.Tensor,
    synthetic_fraction: float,
) -> int:
    """Create a small, feature/label-aligned imagination curriculum.

    Earlier code replaced labels on otherwise unrelated real windows.  That
    teaches contradictory supervision.  Here each selected attack window gets
    a short *telemetry-derived* state trace ending at the observed attack stage,
    an aligned next state, and a monotonic plausible future.  This is synthetic
    reasoning for the model, not a substitute for captured telemetry: normal
    samples and the complete validation set remain untouched.
    """
    if synthetic_fraction <= 0 or ystage.size(0) < 2:
        return 0
    unknown = len(MITRE_STAGES) - 1
    candidates = ((ystage[:, 0] >= 0) & (ystage[:, 0] < unknown)).nonzero(as_tuple=True)[0]
    if candidates.numel() == 0:
        return 0
    selected = candidates[torch.rand(candidates.numel(), device=x.device) < synthetic_fraction]
    if selected.numel() == 0:
        return 0

    context = x.size(1)
    horizon = ystage.size(1)
    trace_len = max(2, context // 2)
    for idx in selected.tolist():
        start = int(ystage[idx, 0].item())
        start_pos = _STAGE_TO_POS.get(MITRE_STAGES[start], 0)
        # The observed tail advances toward the current known threat stage.
        first_pos = max(0, start_pos - trace_len + 1)
        for offset in range(trace_len):
            pos = min(start_pos, first_pos + offset)
            stage_id = MITRE_STAGES.index(_SYNTHETIC_ORDER[pos])
            x[idx, context - trace_len + offset] = stage_prototypes[stage_id]

        pos = start_pos
        future: list[int] = []
        for _ in range(horizon):
            # Mostly advance, occasionally persist; never regress.
            if torch.rand((), device=x.device).item() < 0.72:
                pos = min(len(_SYNTHETIC_ORDER) - 1, pos + int(torch.randint(0, 3, ()).item()))
            future.append(MITRE_STAGES.index(_SYNTHETIC_ORDER[pos]))
        ystage[idx] = torch.tensor(future, dtype=ystage.dtype, device=ystage.device)
        ynext[idx] = stage_prototypes[future[0]]
        yinfil[idx] = torch.linspace(0.35, 1.0, horizon, device=yinfil.device)
    return int(selected.numel())


def source_tail_split(
    dataset: SequenceDataset,
    sequence_lengths: list[int],
    context: int,
    horizon: int,
    validation_fraction: float = 0.15,
) -> tuple[Subset, Subset]:
    """Chronological per-source split with an embargo against overlapping windows.

    A random split leaks nearly identical sliding windows into train and
    validation.  Holding out the tail of every source is a much stricter proxy
    for future live telemetry while retaining representation from each corpus.
    """
    train_indices: list[int] = []
    val_indices: list[int] = []
    offset = 0
    embargo = context + horizon - 1
    for length in sequence_lengths:
        val_count = max(1, int(length * validation_fraction))
        val_start = offset + length - val_count
        train_end = max(offset, val_start - embargo)
        train_indices.extend(range(offset, train_end))
        val_indices.extend(range(val_start, offset + length))
        offset += length
    if not train_indices or not val_indices:
        raise ValueError("Source-tail split produced an empty train or validation partition")
    return Subset(dataset, train_indices), Subset(dataset, val_indices)


def stage_class_weights(dataset: SequenceDataset, train_ds: Subset, unknown_weight: float) -> torch.Tensor:
    """Moderate inverse-frequency weighting computed strictly from train labels."""
    indices = torch.as_tensor(train_ds.indices, dtype=torch.long)
    labels = dataset.Y_stage[indices].reshape(-1)
    counts = torch.bincount(labels, minlength=len(MITRE_STAGES)).float().clamp_min(1.0)
    # Square-root balancing avoids overfitting extremely rare taxonomy classes.
    weights = torch.sqrt(counts.max() / counts).clamp(max=5.0)
    weights[-1] *= unknown_weight
    return weights / weights.mean().clamp_min(1e-6)


def balanced_stage_sampler(dataset: SequenceDataset, train_ds: Subset, unknown_weight: float) -> WeightedRandomSampler:
    """Sample training sequences by their first predicted stage.

    Loss weights alone do not ensure that rare attack stages reach a minibatch;
    a corpus with long benign runs can still produce batches containing almost
    exclusively ``unknown`` labels.  This sampler is train-only (validation
    retains the chronological source-tail distribution) and uses capped
    inverse-frequency weights to avoid replacing one majority bias with noisy
    single-example overfitting.
    """
    indices = torch.as_tensor(train_ds.indices, dtype=torch.long)
    labels = dataset.Y_stage[indices, 0].long()
    counts = torch.bincount(labels, minlength=len(MITRE_STAGES)).float().clamp_min(1.0)
    inverse = torch.sqrt(counts.max() / counts).clamp(max=8.0)
    inverse[-1] *= unknown_weight
    sample_weights = inverse[labels].double()
    return WeightedRandomSampler(sample_weights, num_samples=len(indices), replacement=True)


def write_training_status(path: Path, **status) -> None:
    """Persist small, non-sensitive progress metadata for model observability."""
    path.write_text(json.dumps(status, indent=2))


def load_all_matrices(raw_dir: Path, max_rows: int):
    matrices = []
    loaded_names = []

    def add(df, name, rows=None):
        try:
            matrices.append(dataframe_to_feature_matrix(df))
            loaded_names.append(name)
        except Exception as e:  # noqa: BLE001
            print(f"  ! skipped {name}: {e}")

    unsw_train = raw_dir / "UNSW_NB15_training-set.csv"
    unsw_test = raw_dir / "UNSW_NB15_testing-set.csv"
    nsl = raw_dir / "NSL_KDD_Train.csv"
    kdd = raw_dir / "kddcup99" / "kddcup.data_10_percent.txt"

    if unsw_train.exists():
        print(f"Loading {unsw_train.name}")
        add(load_unsw_csv(unsw_train, max_rows=max_rows), "UNSW-NB15-train")
    if unsw_test.exists():
        print(f"Loading {unsw_test.name}")
        add(load_unsw_csv(unsw_test, max_rows=max_rows // 2), "UNSW-NB15-test")
    if nsl.exists():
        print(f"Loading {nsl.name}")
        add(load_nsl_kdd_csv(nsl, max_rows=max_rows // 2), "NSL-KDD")
    if kdd.exists():
        print(f"Loading {kdd.name} (DARPA-era KDD Cup 99)")
        add(load_kdd99_csv(kdd, max_rows=max_rows), "KDD99")

    # CIC-IDS2017 / CTU-13 (CICFlowMeter) CSVs anywhere under raw dir
    cic_dir = raw_dir / "cicids2017"
    if cic_dir.exists():
        for f in sorted(cic_dir.glob("*.csv")):
            print(f"Loading {f.name}")
            add(load_cicflowmeter_csv(f, max_rows=max_rows // 2), f"cicids2017-{f.stem}")
    for f in raw_dir.glob("CTU13_*.csv"):
        print(f"Loading {f.name}")
        add(load_cicflowmeter_csv(f, max_rows=max_rows // 2), f"ctu13-{f.stem}")

    # Any other CSV that looks like CICFlowMeter / UNSW
    for f in sorted(raw_dir.glob("*.csv")):
        if f.name in {
            "UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv",
            "NSL_KDD_Train.csv",
        } or f.name.startswith("CTU13_"):
            continue
        try:
            probe = pd.read_csv(f, nrows=2)
            if detect_cicflowmeter(probe):
                print(f"Loading {f.name} (CICFlowMeter)")
                add(load_cicflowmeter_csv(f, max_rows=max_rows // 2), f"auto-{f.stem}")
        except Exception:  # noqa: BLE001
            continue

    if not matrices:
        raise FileNotFoundError(f"No datasets found in {raw_dir}")
    print("Datasets loaded:", ", ".join(loaded_names))
    return matrices, loaded_names


def per_class_metrics(preds, labels, num_classes, names):
    """Per-class precision / recall / F1 plus macro average.

    Macro-F1 is the arithmetic mean of the per-class F1 scores (any class with
    zero support contributes 0), so a dominant majority class like "unknown"
    can no longer inflate the headline number.
    """
    rows = []
    for c in range(num_classes):
        tp = int(((preds == c) & (labels == c)).sum())
        fp = int(((preds == c) & (labels != c)).sum())
        fn = int(((preds != c) & (labels == c)).sum())
        p = tp / (tp + fp + 1e-9)
        r = tp / (tp + fn + 1e-9)
        f1 = 2 * p * r / (p + r + 1e-9)
        rows.append({"stage": names[c], "precision": round(p, 4),
                     "recall": round(r, 4), "f1": round(f1, 4), "count": int((labels == c).sum())})
    macro_p = sum(r["precision"] for r in rows) / num_classes
    macro_r = sum(r["recall"] for r in rows) / num_classes
    macro_f1 = sum(r["f1"] for r in rows) / num_classes
    return rows, {"precision": round(macro_p, 4), "recall": round(macro_r, 4),
                  "f1": round(macro_f1, 4)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=str(ROOT / "data" / "raw"))
    parser.add_argument("--out-dir", default=str(ROOT / "data" / "checkpoints"))
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--lr", type=float, default=1.5e-3)
    parser.add_argument("--warmup-steps", type=int, default=200)
    parser.add_argument("--context", type=int, default=10)
    parser.add_argument("--horizon", type=int, default=4)
    parser.add_argument("--max-rows", type=int, default=120000)
    parser.add_argument("--n-branches", type=int, default=5)
    parser.add_argument("--synthetic-frac", type=float, default=0.15,
                        help="fraction of eligible attack windows receiving feature-aligned imagined rollouts")
    parser.add_argument("--unknown-weight", type=float, default=0.35,
                        help="relative loss weight for benign/unknown class; <1 counters its dominance")
    parser.add_argument("--consistency-weight", type=float, default=0.4)
    parser.add_argument("--rl-weight", type=float, default=0.6,
                        help="weight of the DQN model-based objective in the total loss")
    parser.add_argument("--infil-pos-weight", default="auto",
                        help="positive-class BCE weight for infiltration labels; auto derives it from train only")
    parser.add_argument("--balanced-sampling", type=int, default=1,
                        help="oversample rare attack-stage sequences in training only (0/1)")
    parser.add_argument("--min-validation-support", type=int, default=0,
                        help="minimum target windows required per stage in validation; 0 reports only")
    parser.add_argument("--require-validation-support", type=int, default=0,
                        help="fail before training when any stage is below min-validation-support (0/1)")
    parser.add_argument("--use-rl", type=int, default=1,
                        help="enable the DQN+LSTM response-planning layer (0/1)")
    parser.add_argument("--device", default="auto")
    parser.add_argument("--resume", type=str, default="",
                        help="path to a checkpoint whose model_state is used to warm-start")
    args = parser.parse_args()
    if not 0.0 <= args.synthetic_frac <= 1.0:
        parser.error("--synthetic-frac must be between 0 and 1")
    if args.unknown_weight <= 0:
        parser.error("--unknown-weight must be positive")

    raw_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    status_path = out_dir / "training_status.json"
    write_training_status(
        status_path,
        status="running",
        model_version="flow-wm-v3.1.0-live-balanced",
        epochs_requested=args.epochs,
        current_epoch=0,
        started_at=datetime.now(timezone.utc).isoformat(),
        synthetic_mode="telemetry_derived_feature_aligned_imagination",
    )

    device = pick_device(args.device)
    use_amp = device.type == "cuda"

    matrices, loaded_names = load_all_matrices(raw_dir, args.max_rows)
    Xs, Yns, Yss, Yis, sequence_lengths = [], [], [], [], []
    feature_names = matrices[0].feature_names
    for m in matrices:
        x, yn, ys, yi = build_state_sequences(m, args.context, args.horizon)
        Xs.append(x); Yns.append(yn); Yss.append(ys); Yis.append(yi)
        sequence_lengths.append(len(x))
        print(f"  sequences: {len(x)}  features: {m.num_features}")

    X = np.concatenate(Xs, axis=0)
    Y_next = np.concatenate(Yns, axis=0)
    Y_stage = np.concatenate(Yss, axis=0)
    Y_infil = np.concatenate(Yis, axis=0)
    print(f"Total sequences: {len(X)}")

    dataset = SequenceDataset(X, Y_next, Y_stage, Y_infil)
    train_ds, val_ds = source_tail_split(dataset, sequence_lengths, args.context, args.horizon)
    n_train, n_val = len(train_ds), len(val_ds)
    val_indices = torch.as_tensor(val_ds.indices, dtype=torch.long)
    validation_support = torch.bincount(
        dataset.Y_stage[val_indices].reshape(-1), minlength=len(MITRE_STAGES)
    ).tolist()
    print("Validation stage support:", ", ".join(
        f"{stage}={int(count)}" for stage, count in zip(MITRE_STAGES, validation_support)))
    if args.require_validation_support and args.min_validation_support > 0:
        insufficient = [
            f"{stage}={int(count)}" for stage, count in zip(MITRE_STAGES, validation_support)
            if int(count) < args.min_validation_support
        ]
        if insufficient:
            raise ValueError(
                "Validation support gate failed; collect more time-held-out telemetry before training: "
                + ", ".join(insufficient)
            )
    # Validation targets must never influence the augmentation curriculum.
    prototypes = torch.from_numpy(build_stage_prototypes(
        X[train_ds.indices], Y_stage[train_ds.indices], len(MITRE_STAGES)
    )).to(device)
    class_weights = stage_class_weights(dataset, train_ds, args.unknown_weight).to(device)
    print(f"Split: source-tail with {args.context + args.horizon - 1}-window embargo; "
          f"train={n_train}, validation={n_val}")
    print("Stage loss weights:", ", ".join(
        f"{name}={weight:.2f}" for name, weight in zip(MITRE_STAGES, class_weights.detach().cpu().tolist())))
    train_indices = torch.as_tensor(train_ds.indices, dtype=torch.long)
    train_infil = dataset.Y_infil[train_indices]
    positives = float(train_infil.sum().item())
    negatives = float(train_infil.numel() - positives)
    if str(args.infil_pos_weight).lower() == "auto":
        resolved_infil_pos_weight = float(np.clip(negatives / max(positives, 1.0), 1.0, 20.0))
    else:
        resolved_infil_pos_weight = float(args.infil_pos_weight)
    if resolved_infil_pos_weight <= 0:
        parser.error("--infil-pos-weight must be positive or auto")
    infil_pos_weight = torch.tensor(resolved_infil_pos_weight, dtype=torch.float32, device=device)
    print(f"Infiltration train balance: positives={int(positives)} negatives={int(negatives)} "
          f"pos_weight={resolved_infil_pos_weight:.3f}")
    sampler = balanced_stage_sampler(dataset, train_ds, args.unknown_weight) if args.balanced_sampling else None
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=sampler is None,
                              sampler=sampler, num_workers=0, drop_last=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)

    model = FlowWorldModel(
        feature_dim=X.shape[-1],
        context_window=args.context,
        horizon=args.horizon,
        num_stages=len(MITRE_STAGES),
        n_branches=args.n_branches,
        use_rl=bool(args.use_rl),
    ).to(device)
    # Optionally warm-start from a previously trained checkpoint (resume).
    if args.resume:
        rp = Path(args.resume)
        if rp.exists():
            print(f"Resuming from {rp}")
            model.load_state_dict(torch.load(rp, map_location=device)["model_state"], strict=False)
        else:
            print(f"  ! resume checkpoint not found: {rp}")
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    steps_per_epoch = max(1, len(train_loader))
    total_steps = steps_per_epoch * args.epochs
    scheduler = torch.optim.lr_scheduler.LambdaLR(
        opt,
        lr_lambda=lambda step: _warmup_cosine(step, args.warmup_steps, total_steps),
    )
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)

    history = []
    best_score = float("-inf")
    best_val = float("inf")
    best_path = out_dir / "flow_world_model.pt"
    global_step = 0

    for epoch in range(1, args.epochs + 1):
        model.train()
        tr_loss = 0.0
        synthetic_windows = 0
        for xb, ynext, ystage, yinfil in train_loader:
            xb = xb.to(device); ynext = ynext.to(device); ystage = ystage.to(device); yinfil = yinfil.to(device)

            # Feature-aligned synthetic "thinking" curriculum. It is applied
            # to a subset of real attack windows, never to validation data.
            synthetic_windows += synthesize_progressions(
                xb, ynext, ystage, yinfil, prototypes, args.synthetic_frac)

            teacher = ynext.unsqueeze(1).repeat(1, args.horizon, 1)
            opt.zero_grad()

            with torch.autocast("cuda", enabled=use_amp):
                out = model(xb, teacher_future=teacher)
                loss_dyn = F.mse_loss(out.next_state, ynext)
                loss_stage = F.cross_entropy(
                    out.stage_logits.reshape(-1, out.stage_logits.size(-1)),
                    ystage.reshape(-1), weight=class_weights)
                loss_infil = F.binary_cross_entropy_with_logits(
                    out.infil_logits, yinfil, pos_weight=infil_pos_weight)
                # Self-supervised consistency: base agrees with imagination ensemble.
                consensus_stage = out.consensus_stage_probs.detach()
                consensus_infil = out.consensus_infil_probs.detach()
                loss_cons = F.kl_div(
                    torch.log_softmax(out.stage_logits, dim=-1),
                    consensus_stage, reduction="batchmean")
                loss_cons = loss_cons + F.binary_cross_entropy_with_logits(
                    out.infil_logits, consensus_infil)
                loss = loss_dyn + 1.5 * loss_stage + 1.25 * loss_infil \
                    + args.consistency_weight * loss_cons
                # DQN + LSTM model-based objective: pick defensive actions that
                # lower predicted infiltration over the future sequence.
                if args.use_rl and args.rl_weight > 0:
                    loss_rl = model.rl_loss(xb, out.consensus_infil_probs,
                                            out.consensus_stage_probs)
                    loss = loss + args.rl_weight * loss_rl

            if not torch.isfinite(loss):
                raise FloatingPointError("Nonfinite training loss; refusing to save this candidate")
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            previous_scale = scaler.get_scale()
            scaler.step(opt)
            scaler.update()
            if scaler.get_scale() >= previous_scale:
                scheduler.step()
                global_step += 1
            tr_loss += loss.item() * len(xb)
        tr_loss /= n_train

        model.eval()
        va_loss = 0.0
        all_pred = []
        all_lbl = []
        all_infil_p = []
        all_infil_l = []
        with torch.no_grad():
            for xb, ynext, ystage, yinfil in val_loader:
                xb = xb.to(device); ynext = ynext.to(device); ystage = ystage.to(device); yinfil = yinfil.to(device)
                out = model(xb)
                loss = (
                    F.mse_loss(out.next_state, ynext)
                    + 1.5 * F.cross_entropy(out.stage_logits.reshape(-1, out.stage_logits.size(-1)), ystage.reshape(-1))
                    + 1.25 * F.binary_cross_entropy_with_logits(
                        out.infil_logits, yinfil, pos_weight=infil_pos_weight)
                )
                va_loss += loss.item() * len(xb)
                pred = out.stage_probs.argmax(dim=-1)
                all_pred.append(pred.reshape(-1).cpu().numpy())
                all_lbl.append(ystage.reshape(-1).cpu().numpy())
                all_infil_p.append(out.infil_probs.reshape(-1).cpu().numpy())
                all_infil_l.append(yinfil.reshape(-1).cpu().numpy())
        va_loss /= n_val

        preds = np.concatenate(all_pred)
        labels = np.concatenate(all_lbl)
        acc = float((preds == labels).mean())
        per_stage, macro = per_class_metrics(preds, labels, len(MITRE_STAGES), MITRE_STAGES)
        attack_macro = {
            key: round(float(np.mean([row[key] for row in per_stage[:-1]])), 4)
            for key in ("precision", "recall", "f1")
        }
        infil_p = np.concatenate(all_infil_p)
        infil_l = np.concatenate(all_infil_l)
        infil_acc = float(((infil_p > 0.5).astype(int) == infil_l).mean())

        history.append({
            "epoch": epoch, "train_loss": round(tr_loss, 4),
            "val_loss": round(va_loss, 4), "stage_acc": round(acc, 4),
            "stage_macro": macro, "attack_stage_macro": attack_macro, "per_stage": per_stage,
            "infil_acc": round(infil_acc, 4),
            "synthetic_windows": synthetic_windows,
        })
        write_training_status(
            status_path,
            status="running",
            model_version="flow-wm-v3.1.0-live-balanced",
            epochs_requested=args.epochs,
            current_epoch=epoch,
            latest={"val_loss": round(va_loss, 4), "attack_macro_f1": attack_macro["f1"], "infil_acc": round(infil_acc, 4)},
            synthetic_mode="telemetry_derived_feature_aligned_imagination",
        )
        print(f"Epoch {epoch}/{args.epochs}  train={tr_loss:.4f}  val={va_loss:.4f}  "
              f"stage_acc={acc:.3f}  macro-F1={macro['f1']:.3f}  "
              f"attack-F1={attack_macro['f1']:.3f}  infil_acc={infil_acc:.3f}  "
              f"imagined={synthetic_windows}")

        # Promotion follows attack-stage macro F1, not majority-class dominated
        # loss. Infiltration accuracy is a secondary tie-breaker.
        selection_score = attack_macro["f1"] + 0.001 * infil_acc
        if selection_score > best_score:
            best_score = selection_score
            best_val = va_loss
            torch.save(
                {
                    "model_state": model.state_dict(),
                    "feature_dim": X.shape[-1],
                    "feature_names": feature_names,
                    "context_window": args.context,
                    "horizon": args.horizon,
                    "num_stages": len(MITRE_STAGES),
                    "n_branches": args.n_branches,
                    "mitre_stages": MITRE_STAGES,
                    "datasets": loaded_names,
                    "val_loss": best_val,
                    "stage_acc": acc,
                    "stage_macro": macro,
                    "attack_stage_macro": attack_macro,
                    "infil_acc": infil_acc,
                    "synthetic_frac": args.synthetic_frac,
                    "synthetic_mode": "telemetry_derived_feature_aligned_imagination",
                    "synthetic_validation": False,
                    "validation_split": "source_tail_chronological_with_window_embargo",
                    "validation_stage_support": {
                        stage: int(count) for stage, count in zip(MITRE_STAGES, validation_support)
                    },
                    "validation_support_gate": {
                        "minimum": args.min_validation_support,
                        "required": bool(args.require_validation_support),
                        "passed": not args.require_validation_support or all(
                            int(count) >= args.min_validation_support for count in validation_support
                        ),
                    },
                    "validation_embargo_windows": args.context + args.horizon - 1,
                    "unknown_weight": args.unknown_weight,
                    "infil_pos_weight": resolved_infil_pos_weight,
                    "stage_class_weights": class_weights.detach().cpu().tolist(),
                    "selection_metric": "attack_stage_macro_f1",
                    "selection_score": selection_score,
                    "consistency_weight": args.consistency_weight,
                    "use_rl": bool(args.use_rl),
                    "rl_weight": args.rl_weight,
                    "rl_actions": 8,
                    "model_version": "flow-wm-v3.1.0-live-balanced",
                },
                best_path,
            )
            print(f"  saved {best_path}")

    meta_path = out_dir / "training_history.json"
    meta_path.write_text(json.dumps({
        "history": history,
        "best_val": best_val,
        "best_selection_score": best_score,
        "selection_metric": "attack_stage_macro_f1",
        "validation_split": "source_tail_chronological_with_window_embargo",
        "validation_stage_support": {
            stage: int(count) for stage, count in zip(MITRE_STAGES, validation_support)
        },
        "validation_support_gate": {
            "minimum": args.min_validation_support,
            "required": bool(args.require_validation_support),
            "passed": not args.require_validation_support or all(
                int(count) >= args.min_validation_support for count in validation_support
            ),
        },
        "synthetic_mode": "telemetry_derived_feature_aligned_imagination",
        "infil_pos_weight": resolved_infil_pos_weight,
    }, indent=2))
    write_training_status(
        status_path,
        status="completed",
        model_version="flow-wm-v3.1.0-live-balanced",
        epochs_requested=args.epochs,
        current_epoch=args.epochs,
        best_selection_score=best_score,
        best_validation_loss=best_val,
        finished_at=datetime.now(timezone.utc).isoformat(),
    )
    print(f"Done. Best checkpoint: {best_path}")


def _warmup_cosine(step: int, warmup: int, total: int) -> float:
    """Linear warmup then cosine decay to ~5% of max LR."""
    if step < warmup:
        return float(step + 1) / float(max(1, warmup))
    progress = (step - warmup) / float(max(1, total - warmup))
    return 0.05 + 0.95 * 0.5 * (1.0 + np.cos(np.pi * min(progress, 1.0)))


if __name__ == "__main__":
    main()
