#!/usr/bin/env python3
"""Train research candidates from annotated telemetry-v2 segment windows.

Use --sanity-check for an explicitly artificial gradient/overfit diagnostic.
This script never overwrites or promotes a serving checkpoint.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import sys
import time

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.telemetry_v2 import PreprocessingArtifact, TemporalWindows, validate_observations, quality_summary
from models.flow_world_model import FlowWorldModel


def focal_loss(logits, targets, alpha=None, gamma=2.0, label_smoothing=0.1):
    ce_loss = F.cross_entropy(logits, targets, reduction="none", weight=alpha, label_smoothing=label_smoothing)
    pt = torch.exp(-ce_loss)
    focal = ((1.0 - pt) ** gamma) * ce_loss
    return focal.mean()


def objective_components(output, future, stage, malicious, alpha=None, pos_weight=None,
                        gamma=2.0, label_smoothing=0.1, weights=None):
    dynamics = F.mse_loss(output.future_states, future)
    supported = stage >= 0
    if supported.any():
        stage_loss = focal_loss(output.stage_logits[supported], stage[supported], alpha=alpha, gamma=gamma, label_smoothing=label_smoothing)
    else:
        stage_loss = output.stage_logits.sum() * 0.0
    # Smooth the binary targets for malicious prediction to reduce ECE overconfidence
    smoothed_malicious = malicious.float() * (1.0 - label_smoothing) + 0.5 * label_smoothing
    infil_loss = F.binary_cross_entropy_with_logits(
        output.infil_logits, smoothed_malicious, pos_weight=pos_weight
    )
    weights = weights or {"dynamics": 1.0, "stage": 1.0, "infiltration": 1.0}
    return {"dynamics": dynamics * weights["dynamics"], "stage": stage_loss * weights["stage"], "infiltration": infil_loss * weights["infiltration"]}


def objective(output, future, stage, malicious, alpha=None, pos_weight=None, gamma=2.0,
              label_smoothing=0.1, weights=None):
    parts = objective_components(output, future, stage, malicious, alpha=alpha,
                                pos_weight=pos_weight, gamma=gamma,
                                label_smoothing=label_smoothing, weights=weights)
    return sum(parts.values())


def sanity(device):
    torch.manual_seed(42)
    model = FlowWorldModel(feature_dim=4, d_model=32, nhead=2, num_layers=1,
                          dim_feedforward=64, dropout=0, context_window=4,
                          horizon=2, num_stages=13, n_branches=1, use_rl=False).to(device)
    x = torch.randn(8, 4, 4, device=device) * 0.1
    future = x[:, -1:].repeat(1, 2, 1)
    stage = torch.zeros(8, 2, dtype=torch.long, device=device)
    labels = torch.zeros(8, 2, device=device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.003)
    losses = []
    for _ in range(80):
        optimizer.zero_grad()
        loss = objective(model(x), future, stage, labels)
        if not torch.isfinite(loss):
            raise RuntimeError("Nonfinite sanity loss")
        loss.backward()
        if model.input_proj.weight.grad is None or not torch.isfinite(model.input_proj.weight.grad).all():
            raise RuntimeError("Encoder gradient missing or nonfinite")
        optimizer.step()
        losses.append(loss.item())
    if losses[-1] >= losses[0] * 0.2:
        raise RuntimeError(f"Small-batch overfit failed: {losses[0]} -> {losses[-1]}")
    return {"diagnostic_only": True, "device": str(device), "initial_loss": losses[0],
            "final_loss": losses[-1], "passed": True}


def run(args):
    torch.set_num_threads(2)
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    device = torch.device("cuda" if args.device == "auto" and torch.cuda.is_available()
                          else "cpu" if args.device == "auto" else args.device)
    if args.sanity_check:
        print(json.dumps(sanity(device), indent=2))
        return
    if not args.input or not args.out_dir:
        raise ValueError("--input and --out-dir are required for training")
    destination = Path(args.out_dir)
    # Preserve prior experiments, including partial runs.
    destination.mkdir(parents=True, exist_ok=False)
    status_path = destination / "training_status.json"

    def status(state, **detail):
        status_path.write_text(json.dumps({"status": state, **detail}, indent=2))

    status("preparing")
    try:
        path = Path(args.input)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        frame = validate_observations(pd.read_csv(path))
        quality = quality_summary(frame)
        (destination / "dataset_quality.json").write_text(json.dumps(quality, indent=2))
        artifact = PreprocessingArtifact.fit(frame[frame.partition == "train"], [digest])
        datasets = {part: TemporalWindows(frame, artifact, part)
                    for part in ("train", "development", "calibration", "test")}
        if any(len(data) == 0 for data in datasets.values()):
            raise ValueError("Each partition needs an independent capture with at least 18 consecutive 10-second windows")

        # Class frequency balance and positive infiltration weighting
        train_stages = datasets["train"].stage
        train_supported = train_stages[train_stages >= 0]
        stage_counts = torch.bincount(torch.from_numpy(train_supported), minlength=13).float()
        alpha = 1.0 / torch.sqrt(torch.clamp(stage_counts, min=1.0))
        alpha = (alpha / alpha.mean()).to(device)

        train_malicious = datasets["train"].malicious
        pos_count = float(train_malicious.sum())
        neg_count = float(len(train_malicious) - pos_count)
        # Class weighting is useful for recall, but it changes the numeric scale
        # of BCE and can make the aggregate objective look worse even when
        # calibration improves. Keep it explicit and tunable rather than
        # silently forcing a larger loss.
        raw_pos_weight = neg_count / max(pos_count, 1.0)
        pos_weight_scale = float(getattr(args, "pos_weight_scale", 1.0))
        pos_weight = (torch.tensor([raw_pos_weight * pos_weight_scale], device=device)
                      if pos_weight_scale > 0 else None)
        print(f"Training stage counts: {stage_counts.tolist()}")
        print(f"Infiltration balance: pos={int(pos_count)} neg={int(neg_count)} "
              f"pos_weight={raw_pos_weight:.2f} applied={0.0 if pos_weight is None else float(pos_weight):.2f}")

        loss_weights = {"dynamics": args.dynamics_weight, "stage": args.stage_weight, "infiltration": args.infiltration_weight}
        config = dict(feature_dim=len(artifact.feature_names), context_window=12,
                      horizon=6, num_stages=13, n_branches=1, use_rl=False)
        model = FlowWorldModel(**config).to(device)
        learning_rate = float(getattr(args, "lr", 3e-4))
        patience = int(getattr(args, "patience", 4))
        min_delta = float(getattr(args, "min_delta", 1e-4))
        optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.05)
        # The existing run overfit after epoch 5 (training loss kept falling
        # while development loss oscillated).  Adapt the learning rate to the
        # development objective and stop on the best checkpoint instead of
        # training until the model memorises the training partition.
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode="min", factor=0.5, patience=2, threshold=min_delta,
            threshold_mode="abs", min_lr=1e-6,
        )
        loaders = {part: DataLoader(data, batch_size=args.batch_size,
                    shuffle=part == "train", pin_memory=device.type == "cuda", num_workers=0)
                   for part, data in datasets.items() if part in {"train", "development"}}
        history, best = [], float("inf")
        stale_epochs = 0
        for epoch in range(args.epochs):
            status("running", epoch=epoch + 1, epochs=args.epochs, device=str(device))
            started = time.monotonic()
            scores = {}
            for part, loader in loaders.items():
                model.train(part == "train")
                total, count = 0.0, 0
                component_totals = {"dynamics": 0.0, "stage": 0.0, "infiltration": 0.0}
                with torch.set_grad_enabled(part == "train"):
                    for batch in loader:
                        x, future, stage, malicious = [v.to(device, non_blocking=True) for v in batch]
                        output = model(x)
                        parts = objective_components(output, future, stage, malicious,
                                                     alpha=alpha, pos_weight=pos_weight,
                                                     gamma=getattr(args, "gamma", 2.0), weights=loss_weights)
                        loss = sum(parts.values())
                        if not torch.isfinite(loss):
                            raise FloatingPointError(f"Nonfinite {part} loss")
                        if part == "train":
                            optimizer.zero_grad()
                            loss.backward()
                            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0, error_if_nonfinite=True)
                            optimizer.step()
                        total += loss.item() * len(x)
                        for name, value in parts.items():
                            component_totals[name] += value.item() * len(x)
                        count += len(x)
                scores[part] = total / count
                for name, value in component_totals.items():
                    scores[f"{part}_{name}"] = value / count
            history.append({"epoch": epoch + 1, **scores, "seconds": time.monotonic() - started})
            scheduler.step(scores["development"])
            current_lr = optimizer.param_groups[0]["lr"]
            history[-1]["learning_rate"] = current_lr
            if scores["development"] < best - min_delta:
                best = scores["development"]
                stale_epochs = 0
                torch.save({"model_state": model.state_dict(), "model_config": config,
                            "loss_weights": loss_weights, "dataset_quality": quality,
                            "preprocessing": asdict(artifact), "preprocessing_sha256": artifact.sha256,
                            "feature_names": artifact.feature_names, "seed": args.seed,
                            "forecast_branch": "base", "promotion_eligible": False,
                            "promotion_reason": "Independent benchmark and calibration pending",
                            "schema_version": "telemetry-v2"}, destination / "candidate.pt")
            else:
                stale_epochs += 1
            (destination / "history.json").write_text(json.dumps(history, indent=2))
            print(json.dumps(history[-1]), flush=True)
            if stale_epochs >= patience:
                print(f"Early stopping after {stale_epochs} stale development epochs")
                break

        # Temperature scaling must be fitted on the selected best-development
        # checkpoint, not on the final epoch (which may not be the checkpoint
        # saved above). Calibrate both heads independently.
        best_payload = torch.load(destination / "candidate.pt", map_location=device, weights_only=False)
        model.load_state_dict(best_payload["model_state"], strict=True)
        model.eval()

        # Temperature Scaling calibration on the dedicated calibration split
        print("Optimizing temperature scaling on calibration split...")
        cal_loader = DataLoader(datasets["calibration"], batch_size=args.batch_size, shuffle=False)
        stage_temp_param = torch.nn.Parameter(torch.ones(1, device=device) * 1.5)
        malicious_temp_param = torch.nn.Parameter(torch.ones(1, device=device) * 1.5)
        stage_opt = torch.optim.LBFGS([stage_temp_param], lr=0.05, max_iter=50)
        malicious_opt = torch.optim.LBFGS([malicious_temp_param], lr=0.05, max_iter=50)

        cal_logits, cal_stages, cal_mal_logits, cal_malicious = [], [], [], []
        with torch.no_grad():
            for batch in cal_loader:
                x, _, stage, malicious = [v.to(device) for v in batch]
                out = model(x)
                supp = stage >= 0
                if supp.any():
                    cal_logits.append(out.stage_logits[supp])
                    cal_stages.append(stage[supp])
                cal_mal_logits.append(out.infil_logits.reshape(-1))
                cal_malicious.append(malicious.reshape(-1))

        if cal_logits:
            all_logits = torch.cat(cal_logits, dim=0)
            all_stages = torch.cat(cal_stages, dim=0)
            def stage_closure():
                stage_opt.zero_grad()
                loss = F.cross_entropy(all_logits / torch.clamp(stage_temp_param, min=0.1, max=1.2), all_stages)
                loss.backward()
                return loss
            stage_opt.step(stage_closure)
            stage_temperature = float(torch.clamp(stage_temp_param, min=0.1, max=1.2).item())
        else:
            stage_temperature = 1.0

        if cal_mal_logits and torch.unique(torch.cat(cal_malicious, dim=0)).numel() > 1:
            all_mal_logits = torch.cat(cal_mal_logits, dim=0)
            all_malicious = torch.cat(cal_malicious, dim=0)
            def malicious_closure():
                malicious_opt.zero_grad()
                loss = F.binary_cross_entropy_with_logits(
                    all_mal_logits / torch.clamp(malicious_temp_param, min=0.1, max=1.2), all_malicious
                )
                loss.backward()
                return loss
            malicious_opt.step(malicious_closure)
            malicious_temperature = float(torch.clamp(malicious_temp_param, min=0.1, max=1.2).item())
        else:
            malicious_temperature = 1.0
        print(f"Calibrated temperatures: stage={stage_temperature:.3f} malicious={malicious_temperature:.3f}")

        # Update candidate checkpoint with calibrated temperature
        if (destination / "candidate.pt").exists():
            saved_payload = torch.load(destination / "candidate.pt", map_location="cpu", weights_only=False)
            saved_payload["temperature"] = stage_temperature  # backwards-compatible alias
            saved_payload["stage_temperature"] = stage_temperature
            saved_payload["malicious_temperature"] = malicious_temperature
            torch.save(saved_payload, destination / "candidate.pt")

        status("completed", promotion_eligible=False, best_development_loss=best,
               input_sha256=digest, preprocessing_sha256=artifact.sha256,
               temperature=stage_temperature, stage_temperature=stage_temperature,
               malicious_temperature=malicious_temperature)
    except KeyboardInterrupt:
        status("cancelled")
        raise
    except Exception as exc:
        status("failed", error=str(exc))
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input")
    parser.add_argument("--out-dir")
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--patience", type=int, default=4, help="Early-stopping patience on development loss")
    parser.add_argument("--min-delta", type=float, default=1e-4, help="Minimum development-loss improvement")
    parser.add_argument("--lr", type=float, default=3e-4, help="Initial AdamW learning rate")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--gamma", type=float, default=2.0, help="Focal loss gamma focusing parameter")
    parser.add_argument("--pos-weight-scale", type=float, default=1.0,
                        help="Multiplier for imbalance weighting; set 0 to optimize unweighted calibrated loss")
    parser.add_argument("--dynamics-weight", type=float, default=1.0)
    parser.add_argument("--stage-weight", type=float, default=1.0)
    parser.add_argument("--infiltration-weight", type=float, default=1.0)
    parser.add_argument("--sanity-check", action="store_true")
    run(parser.parse_args())
