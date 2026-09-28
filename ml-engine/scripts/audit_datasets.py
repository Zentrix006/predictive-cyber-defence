#!/usr/bin/env python3
"""Audit training corpora before a FLOWWM run.

The audit is deliberately read-only.  It records file hashes, row counts,
label/stage support, missingness, and parser provenance so a candidate model
can be reproduced and rejected when its validation support is inadequate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features.extract import (  # noqa: E402
    dataframe_to_feature_matrix,
    detect_cicflowmeter,
    load_cicflowmeter_csv,
    load_kdd99_csv,
    load_nsl_kdd_csv,
    load_unsw_csv,
)
from features.mitre_map import MITRE_STAGES  # noqa: E402


def sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record(path: Path, loader, source: str, max_rows: int | None) -> dict:
    frame = loader(path, max_rows=max_rows)
    matrix = dataframe_to_feature_matrix(frame)
    stage_values = matrix.stages if matrix.stages is not None else []
    attack_values = matrix.attack_cats if matrix.attack_cats is not None else []
    stages = Counter(MITRE_STAGES[int(v)] for v in stage_values)
    labels = Counter(str(v) for v in attack_values)
    # Inspect BEFORE normalization/imputation, which erase missingness.
    missing = {}
    for name in matrix.feature_names:
        if name not in frame:
            missing[name] = len(frame)
        elif name in ("proto", "service", "state"):
            missing[name] = int(frame[name].isna().sum())
        else:
            values = pd.to_numeric(frame[name], errors="coerce").to_numpy(dtype=float)
            missing[name] = int((~np.isfinite(values)).sum())
    return {
        "source": source,
        "path": str(path),
        "sha256": sha256(path),
        "bytes": path.stat().st_size,
        "rows_audited": int(len(frame)),
        "features": int(matrix.num_features),
        "stage_support": dict(sorted(stages.items())),
        "label_support": dict(labels.most_common(30)),
        "missing_values_before_normalization": missing,
        "missingness_scope": "mapped frame only; legacy loaders may already have filled missing fields",
        "sample_policy": "prefix" if max_rows else "entire_file",
        "max_rows": max_rows,
        "timestamp_quality": "not_verified_by_legacy_loader",
        "parser": "features.extract.dataframe_to_feature_matrix",
    }


def discover(raw: Path):
    entries = []
    candidates = [
        (raw / "UNSW_NB15_training-set.csv", load_unsw_csv, "UNSW-NB15-train"),
        (raw / "UNSW_NB15_testing-set.csv", load_unsw_csv, "UNSW-NB15-test"),
        (raw / "NSL_KDD_Train.csv", load_nsl_kdd_csv, "NSL-KDD"),
        (raw / "kddcup99" / "kddcup.data_10_percent.txt", load_kdd99_csv, "KDD99"),
    ]
    candidates.extend((f, load_cicflowmeter_csv, f"CIC-IDS2017-{f.stem}")
                      for f in sorted((raw / "cicids2017").glob("*.csv")))
    candidates.extend((f, load_cicflowmeter_csv, f"CTU13-{f.stem}")
                      for f in sorted(raw.glob("CTU13_*.csv")))
    return [(p, loader, name) for p, loader, name in candidates if p.exists()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only FLOWWM dataset audit")
    parser.add_argument("--data-dir", default=str(ROOT / "data" / "raw"))
    parser.add_argument("--out", default=str(ROOT / "data" / "dataset_audit.json"))
    parser.add_argument("--max-rows", type=int, default=0,
                        help="audit only this many rows per file (0 = all rows)")
    args = parser.parse_args()
    raw = Path(args.data_dir)
    limit = args.max_rows or None
    records = []
    errors = []
    for path, loader, source in discover(raw):
        try:
            print(f"Auditing {source}: {path.name}")
            records.append(_record(path, loader, source, limit))
        except Exception as exc:  # noqa: BLE001
            errors.append({"source": source, "path": str(path), "error": str(exc)})

    aggregate = Counter()
    for record in records:
        aggregate.update(record["stage_support"])
    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_dir": str(raw),
        "stage_order": MITRE_STAGES,
        "files": records,
        "aggregate_stage_support": dict(sorted(aggregate.items())),
        "errors": errors,
        "quality": {
            "file_count": len(records),
            "error_count": len(errors),
            "zero_support_stages": [s for s in MITRE_STAGES if not aggregate.get(s)],
            "warning": "Rows are not a campaign timeline until session/capture ordering is supplied.",
        },
    }
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["quality"], indent=2))
    if errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
