#!/usr/bin/env python3
"""Convert official CSE-CIC-IDS2018 flow CSVs to telemetry-v2 states."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from features.mitre_map import MITRE_STAGES


PARTITIONS = {
    "Wednesday-14-02-2018": "train",
    "Thursday-15-02-2018": "development",
    "Friday-16-02-2018": "train",
    "Thuesday-20-02-2018": "train",
    "Wednesday-21-02-2018": "calibration",
    "Thursday-22-02-2018": "train",
    "Friday-23-02-2018": "development",
    "Wednesday-28-02-2018": "calibration",
    "Thursday-01-03-2018": "split",
    "Friday-02-03-2018": "split",
}

SUM_COLUMNS = {
    "Tot Fwd Pkts": "forward_packets", "Tot Bwd Pkts": "reverse_packets",
    "TotLen Fwd Pkts": "forward_bytes", "TotLen Bwd Pkts": "reverse_bytes",
    "FIN Flag Cnt": "fin_count", "SYN Flag Cnt": "syn_count",
    "RST Flag Cnt": "rst_count", "PSH Flag Cnt": "psh_count",
    "ACK Flag Cnt": "ack_count", "URG Flag Cnt": "urg_count",
}
MEAN_COLUMNS = {
    "Flow Duration": "duration_seconds", "Flow IAT Mean": "iat_mean_seconds",
    "Flow IAT Std": "iat_std_seconds", "Pkt Len Mean": "payload_mean_bytes",
    "Pkt Len Var": "payload_variance_bytes2",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage_for(label: str) -> int:
    value = str(label).strip().lower().replace("–", "-")
    if value == "benign":
        return -1
    if "infilteration" in value or "infiltration" in value:
        return MITRE_STAGES.index("lateral_movement")
    if "bot" in value:
        return MITRE_STAGES.index("command_and_control")
    if any(token in value for token in ("brute", "heartbleed")):
        return MITRE_STAGES.index("credential_access")
    if any(token in value for token in ("sql", "xss", "web attack")):
        return MITRE_STAGES.index("initial_access")
    if any(token in value for token in ("dos", "ddos")):
        return MITRE_STAGES.index("impact")
    return -1


def prepare_file(path: Path, chunk_size: int) -> tuple[list[dict], dict]:
    capture_id = path.name.split("_TrafficForML", 1)[0]
    partition = PARTITIONS.get(capture_id)
    if partition is None:
        raise ValueError(f"No capture-level partition for {capture_id}")
    accum = defaultdict(lambda: {
        "rows": 0, "sum": Counter(), "mean_sum": Counter(), "mean_count": Counter(),
        "iat_max": float("-inf"), "ports": set(), "protocol": Counter(),
        "labels": Counter(), "tcp_window_sum": 0.0, "tcp_window_count": 0,
    })
    usecols = ["Dst Port", "Protocol", "Timestamp", "Flow IAT Max", "Init Fwd Win Byts",
               "Init Bwd Win Byts", "Label", *SUM_COLUMNS, *MEAN_COLUMNS]
    bad_timestamps = 0
    total_rows = 0
    for chunk in pd.read_csv(path, usecols=usecols, chunksize=chunk_size, low_memory=False):
        chunk.columns = [str(c).strip() for c in chunk.columns]
        timestamps = pd.to_datetime(chunk["Timestamp"], dayfirst=True, errors="coerce", utc=True)
        bad_timestamps += int(timestamps.isna().sum())
        chunk = chunk.loc[timestamps.notna()].copy()
        chunk["window"] = timestamps[timestamps.notna()].dt.floor("10s")
        total_rows += len(chunk)
        for window, group in chunk.groupby("window", sort=False):
            state = accum[window]
            state["rows"] += len(group)
            for source, target in SUM_COLUMNS.items():
                state["sum"][target] += float(pd.to_numeric(group[source], errors="coerce").fillna(0).sum())
            for source, target in MEAN_COLUMNS.items():
                values = pd.to_numeric(group[source], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
                state["mean_sum"][target] += float(values.sum())
                state["mean_count"][target] += len(values)
            maxima = pd.to_numeric(group["Flow IAT Max"], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
            if len(maxima):
                state["iat_max"] = max(state["iat_max"], float(maxima.max()))
            state["ports"].update(pd.to_numeric(group["Dst Port"], errors="coerce").dropna().astype(int).tolist())
            state["protocol"].update(pd.to_numeric(group["Protocol"], errors="coerce").dropna().astype(int).tolist())
            state["labels"].update(group["Label"].astype(str).str.strip().tolist())
            windows = pd.concat([pd.to_numeric(group["Init Fwd Win Byts"], errors="coerce"),
                                 pd.to_numeric(group["Init Bwd Win Byts"], errors="coerce")])
            windows = windows[windows >= 0].dropna()
            state["tcp_window_sum"] += float(windows.sum())
            state["tcp_window_count"] += len(windows)

    output = []
    sorted_items = sorted(accum.items())
    total_w = len(sorted_items)

    for idx, (timestamp, state) in enumerate(sorted_items):
        if partition == "split":
            split_idx = int(total_w * 0.70)
            embargo_w = 180  # 30-minute embargo window
            if idx < split_idx:
                row_partition = "train"
                row_capture_id = f"cse-cic-ids2018:{capture_id}-train"
            elif idx >= split_idx + embargo_w:
                row_partition = "test"
                row_capture_id = f"cse-cic-ids2018:{capture_id}-test"
            else:
                continue
        else:
            row_partition = partition
            row_capture_id = f"cse-cic-ids2018:{capture_id}"

        malicious_labels = Counter({label: count for label, count in state["labels"].items()
                                    if str(label).strip().lower() != "benign"})
        selected_label = malicious_labels.most_common(1)[0][0] if malicious_labels else "Benign"
        protocol = state["protocol"].most_common(1)[0][0] if state["protocol"] else None
        protocol_name = {1: "icmp", 6: "tcp", 17: "udp"}.get(protocol, str(protocol) if protocol is not None else None)
        forward = state["sum"]["forward_packets"]
        reverse = state["sum"]["reverse_packets"]
        mean = lambda name: (state["mean_sum"][name] / state["mean_count"][name]
                             if state["mean_count"][name] else np.nan)
        iat_std = mean("iat_std_seconds")
        output.append({
            "capture_id": row_capture_id, "segment_id": "enterprise",
            "timestamp": timestamp.isoformat(), "partition": row_partition,
            "malicious": int(bool(malicious_labels)), "stage": stage_for(selected_label),
            "label_confidence": 0.70 if malicious_labels else 1.0,
            "label_source": "CSE-CIC-IDS2018 documented flow label", "attack_label": selected_label,
            "duration_seconds": mean("duration_seconds") / 1e6,
            "forward_packets": forward, "reverse_packets": reverse,
            "forward_bytes": state["sum"]["forward_bytes"], "reverse_bytes": state["sum"]["reverse_bytes"],
            "iat_mean_seconds": mean("iat_mean_seconds") / 1e6,
            "iat_variance_seconds2": (iat_std / 1e6) ** 2,
            "iat_max_seconds": state["iat_max"] / 1e6 if np.isfinite(state["iat_max"]) else np.nan,
            "tcp_window_mean": state["tcp_window_sum"] / state["tcp_window_count"] if state["tcp_window_count"] else np.nan,
            "payload_mean_bytes": mean("payload_mean_bytes"),
            "payload_variance_bytes2": mean("payload_variance_bytes2"),
            "fin_count": state["sum"]["fin_count"], "syn_count": state["sum"]["syn_count"],
            "rst_count": state["sum"]["rst_count"], "psh_count": state["sum"]["psh_count"],
            "ack_count": state["sum"]["ack_count"], "urg_count": state["sum"]["urg_count"],
            "unique_destination_ports": len(state["ports"]),
            "bidirectional_ratio": reverse / max(forward, 1.0), "protocol": protocol_name,
        })
    return output, {"capture_id": capture_id, "partition": partition, "sha256": sha256(path),
                    "rows": total_rows, "windows": len(output), "bad_timestamps": bad_timestamps}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--chunk-size", type=int, default=200_000)
    args = parser.parse_args()
    files = sorted(Path(args.input_dir).glob("*_TrafficForML_CICFlowMeter.csv"))
    if set(PARTITIONS) != {f.name.split("_TrafficForML", 1)[0] for f in files}:
        raise ValueError("Expected the complete ten-file official processed CSE-CIC-IDS2018 set")
    rows, sources = [], []
    for path in files:
        print(f"Preparing {path.name}", flush=True)
        prepared, source = prepare_file(path, args.chunk_size)
        rows.extend(prepared); sources.append(source)
    frame = pd.DataFrame(rows).sort_values(["capture_id", "timestamp"])
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    manifest = {"schema_version": "telemetry-v2", "dataset": "CSE-CIC-IDS2018",
                "output_sha256": sha256(output), "sources": sources,
                "stage_support_windows": frame[frame.stage >= 0].stage.value_counts().sort_index().to_dict(),
                "partition_windows": frame.partition.value_counts().to_dict(),
                "label_policy": "weak phase mapping from official flow labels; confidence 0.70",
                "promotion_eligible": False}
    Path(args.manifest).write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
