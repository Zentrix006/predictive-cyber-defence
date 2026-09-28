# World Model Evaluation — honest metrics

This document records the head-to-head evaluation of `flow-wm-v3.0.0` checkpoints on the
fixed evaluation harness (`ml-engine/scripts/eval_checkpoint.py`).

## Evaluation protocol

- **Data**: 239,818 sequences from 14 datasets (UNSW-NB15, NSL-KDD, KDD99, CICIDS2017,
  CTU-13).
- **Val split**: 15%, reproducible (seed 42), 35,972 sequences.
- **Metrics**:
  - `stage_acc` — pooled stage accuracy over all samples.
  - `macro-F1` — true macro: arithmetic mean of per-class precision, recall, F1 across the
    14 MITRE-stage classes (zero-support classes contribute 0). This replaced the earlier
    `stage_macro` field, which was misleadingly identical to `stage_acc` (a micro/pooled
    measurement, not a mean over classes).
  - `infil_acc` — infiltration-risk binary accuracy.
  - `val_loss` — cross-entropy + auxiliary losses on validation.
- Full per-stage precision/recall/F1 and support counts are on the final line of every
  `eval_checkpoint.py` run.

## Results (seed-42 val, 35,972 sequences)

| Checkpoint | stage_acc | macro-F1 | infil_acc | val_loss | Notes |
|---|---|---|---|---|---|
| v1 baseline (16 ep, pre-fix) | 0.8755 | 0.2144 | 0.9666 | 3.2246 | command_and_control F1 0.0 (CTU-13 labels collapsed) |
| v2 short (4 ep, fixed pipeline) | 0.9390 | 0.3085 | 0.9666 | 2.4902 | interim baseline; c2 F1 1.0, execution F1 0.617 |
| v2 full (16 ep, fixed pipeline) | 0.9457 | 0.3099 | 0.9665 | 2.4633 | **promoted to production**; beat v2 short on stage_acc + macro-F1 (infil ties within 0.99); c2 F1 1.0, impact F1 0.775, credential_access F1 0.941 |

### Production selection

The fixed pipeline (v2) is the production checkpoint. v2 full (16 epochs) won the
head-to-head vs v2 short under the promotion rule (≥ short on stage_acc AND macro-F1,
infil ≥ 0.99·short), so `flow_world_model.pt` is the 16-epoch retrain. Final numbers above
were produced by `eval_checkpoint.py` on the same seed-42 15% split used for v1 and v2 short.

### Why v1 looked better than it was

`training_history.json` (v1) recorded `stage_macro` with f1 ≈ stage_acc. That value was the
pooled accuracy, not a class-mean macro. Honest macro-F1 for v1 is **0.2144** (measured via
`eval_checkpoint.py`), because rare stages (initial_access, persistence, privilege_escalation,
lateral_movement, exfiltration) are heavily under-represented and the model had essentially no
recall on them.

### What the v2 pipeline fixed

- `extract.py` numeric-label branch now preserves raw tokens (`"1"`/`"0"`), so CTU-13
  `command_and_control` is labelable — v1 had **0.0** F1 on 9,132 samples; v2 reaches
  ~1.0.
- `per_class_metrics` in `train_real.py` computes a true macro and per-class rows.

## Artifacts

- `ml-engine/scripts/eval_checkpoint.py` — reproduction harness.
- `ml-engine/data/checkpoints/flow_world_model_v1_baseline.pt` — pre-fix baseline.
- `ml-engine/data/checkpoints/flow_world_model_v2_short.pt` — 4-epoch interim.
- `ml-engine/data/checkpoints/flow_world_model_v2_full.pt` — 16-epoch full retrain (production).
- Finalizer log: `/tmp/opencode/v2_finalize.log`; eval output: `/tmp/opencode/v2_eval.txt`.