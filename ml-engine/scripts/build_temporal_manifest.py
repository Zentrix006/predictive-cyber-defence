#!/usr/bin/env python3
"""Build a provenance-aware temporal training manifest from dataset_audit.json.

The manifest does not invent timestamps.  It records which ordering is
trusted, where row-order is only a deterministic fallback, and the exact file
hashes used by a candidate run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build FLOWWM temporal manifest")
    parser.add_argument("--audit", default="ml-engine/data/dataset_audit.json")
    parser.add_argument("--out", default="ml-engine/data/temporal_manifest.json")
    parser.add_argument("--context", type=int, default=10)
    parser.add_argument("--horizon", type=int, default=4)
    parser.add_argument("--validation-fraction", type=float, default=0.15)
    args = parser.parse_args()

    audit_path = Path(args.audit)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    files = []
    for item in audit.get("files", []):
        files.append({
            "source": item.get("source"),
            "path": item.get("path"),
            "sha256": item.get("sha256"),
            "rows_audited": item.get("rows_audited", 0),
            "stage_support": item.get("stage_support", {}),
            "ordering": "capture_timestamp" if item.get("timestamp_column") else "row_order_unverified",
            "partition_policy": {
                "train": "chronological_prefix",
                "validation": "chronological_tail",
                "test": "held_out_source_or_later_capture",
                "embargo_windows": args.context + args.horizon - 1,
                "validation_fraction": args.validation_fraction,
            },
        })
    manifest = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "audit_file": str(audit_path),
        "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
        "context_window": args.context,
        "forecast_horizon": args.horizon,
        "temporal_policy": "source-separated chronological holdout; no cross-source windows",
        "trusted_timestamps_required_for_production": True,
        "promotion_eligible": False,
        "partition_status": "proposed_only; no capture partitions assigned",
        "files": files,
        "quality": {
            "audit_errors": audit.get("errors", []),
            "zero_support_stages": audit.get("quality", {}).get("zero_support_stages", []),
            "row_order_warning": "row_order_unverified sources are auditable but not sufficient evidence of attacker chronology",
        },
    }
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "files": len(files),
        "zero_support_stages": manifest["quality"]["zero_support_stages"],
        "output": str(output),
    }, indent=2))


if __name__ == "__main__":
    main()
