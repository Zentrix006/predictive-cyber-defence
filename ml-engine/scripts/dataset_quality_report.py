#!/usr/bin/env python3
"""Produce a deterministic pre-training quality report for GraphWindow JSONL."""
import argparse, json, sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dataset.window_schema import GraphWindow, DatasetQualityReport

def main() -> int:
    p = argparse.ArgumentParser(); p.add_argument("input", type=Path); p.add_argument("--dataset-version", required=True); p.add_argument("--partition", required=True); p.add_argument("--max-missingness", type=float, default=0.5); p.add_argument("--output", type=Path)
    args = p.parse_args(); rows = [GraphWindow.model_validate_json(line) for line in args.input.read_text().splitlines() if line.strip()]
    campaigns = {r.campaign_id for r in rows}; captures = {r.capture_id for r in rows}; stages = Counter(r.label.mitre_stage for r in rows if r.label.mitre_stage); families = Counter(r.label.attack_family for r in rows if r.label.attack_family)
    quality = {"packet_coverage": sum(r.quality.packet_coverage for r in rows)/max(1,len(rows)), "flow_coverage": sum(r.quality.flow_coverage for r in rows)/max(1,len(rows)), "identity_coverage": sum(r.quality.identity_coverage for r in rows)/max(1,len(rows)), "topology_coverage": sum(r.quality.topology_coverage for r in rows)/max(1,len(rows))}
    warnings = [f"{k} missingness exceeds threshold" for k,v in quality.items() if 1-v > args.max_missingness]
    report = DatasetQualityReport(dataset_version=args.dataset_version, partition=args.partition, campaigns=len(campaigns), captures=len(captures), windows=len(rows), stage_support=dict(stages), attack_family_support=dict(families), missingness={k:round(1-v,6) for k,v in quality.items()}, label_confidence_mean=sum(r.label.label_confidence for r in rows)/max(1,len(rows)), warnings=warnings, passed=not warnings)
    payload = report.model_dump(mode="json"); print(json.dumps(payload, indent=2))
    if args.output: args.output.write_text(json.dumps(payload, indent=2) + "\n")
    return 0 if report.passed else 2
if __name__ == "__main__": raise SystemExit(main())
