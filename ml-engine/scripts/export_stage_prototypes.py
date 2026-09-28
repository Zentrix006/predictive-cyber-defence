"""Export per-MITRE-stage feature prototypes from the real training data.

For each stage, the "prototype" is the median last-frame feature vector over all
sequence windows whose terminal frame carries that stage label. The result is a
compact [num_stages, feature_dim] matrix used to build realistic synthetic
attack-progression ramps for demo forecasts (instead of arbitrary ramps that the
model classifies as "unknown").
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import train_real  # noqa: E402
from scripts.train_real import MITRE_STAGES, build_state_sequences, load_all_matrices  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Export per-stage prototypes")
    parser.add_argument("--max-rows", type=int, default=30000)
    parser.add_argument("--context", type=int, default=10)
    parser.add_argument("--horizon", type=int, default=4)
    parser.add_argument("--out", type=str, default=str(ROOT / "data" / "checkpoints" / "stage_prototypes.npy"))
    args = parser.parse_args()

    matrices, loaded_names = load_all_matrices(train_real.ROOT / "data" / "raw", args.max_rows)
    feats_per_stage = [[] for _ in range(len(MITRE_STAGES))]
    for m in matrices:
        x, yn, ys, yi = build_state_sequences(m, args.context, args.horizon)
        for i in range(len(x)):
            stage = int(ys[i][-1])
            if 0 <= stage < len(MITRE_STAGES):
                feats_per_stage[stage].append(x[i][-1])

    prototypes = np.zeros((len(MITRE_STAGES), matrices[0].num_features), dtype=np.float32)
    reports = []
    for s, vecs in enumerate(feats_per_stage):
        if vecs:
            arr = np.stack(vecs)
            prototypes[s] = np.median(arr, axis=0)
        ok = "ok " if vecs else "empt"
        reports.append(f"{MITRE_STAGES[s]:<20} {ok} samples={len(vecs)}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    np.save(out, prototypes)
    print(f"Saved {out}  shape={prototypes.shape}")
    for r in reports:
        print(" ", r)


if __name__ == "__main__":
    main()