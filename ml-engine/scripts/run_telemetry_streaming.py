#!/usr/bin/env python3
"""Live Execution Runner for Multi-Sensor Telemetry Streaming & Continuous G-FLOWWM Ingestion.

Simulates a continuous multi-source sensor feed (Zeek, Suricata EVE, NetFlow) and demonstrates:
1. High-throughput lossless ring buffering (Zero Data Loss guarantee).
2. Continuous graph snapshot generation.
3. Live real-time GraphFlowWorldModel inference and Cyber-JEPA surprisal monitoring.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
APP_ROOT = ROOT.parent / "backend"
sys.path.insert(0, str(APP_ROOT))

from features.streaming_telemetry import (
    MultiSensorTelemetryNormalizer,
    StreamingTelemetryBuffer,
    ContinuousGraphStreamer,
)
from models.graph_world_model import GraphFlowWorldModel


def main():
    print("=" * 75)
    print("   PHASE 3: MULTI-SENSOR STREAMING TELEMETRY & G-FLOWWM PIPELINE")
    print("=" * 75)

    # 1. Initialize Pipeline Components
    print("\n[Step 1] Initializing Streaming Telemetry Ingestion Pipeline...")
    normalizer = MultiSensorTelemetryNormalizer()
    buffer = StreamingTelemetryBuffer(capacity=50_000, high_watermark_pct=0.85)
    streamer = ContinuousGraphStreamer(buffer=buffer, window_size_seconds=5.0, node_dim=16, edge_dim=35)
    
    model = GraphFlowWorldModel(node_dim=16, edge_dim=35, d_model=64, horizon=3)
    model.eval()
    print("  Buffer Capacity       : 50,000 events (Lossless Ring Buffer)")
    print("  Graph Streamer Window : 5.0 seconds dynamic temporal aggregation")
    print("  Inference World Model : GraphFlowWorldModel (d_model=64, horizon=3)")

    # 2. Simulate Multi-Sensor Real-Time Telemetry Feed
    print("\n[Step 2] Ingesting Live Telemetry Streams (Zeek, Suricata EVE, NetFlow)...")
    
    stream_events = [
        # Sensor 1: Zeek conn.log (DMZ Web Server -> Domain Controller)
        {
            "id.orig_h": "10.0.1.10", "id.resp_h": "10.0.2.20", "id.orig_p": 49152, "id.resp_p": 88,
            "proto": "tcp", "orig_pkts": 45, "resp_pkts": 32, "orig_bytes": 4800, "resp_bytes": 3500,
            "duration": 0.42, "history": "ShADdFf"
        },
        # Sensor 2: Suricata EVE Alert (Suspicious Workstation -> Domain Controller SMB Exploit)
        {
            "event_type": "alert", "src_ip": "10.0.3.50", "dest_ip": "10.0.2.20", "src_port": 51200, "dest_port": 445,
            "proto": "TCP", "flow": {"pkts_toserver": 88, "pkts_toclient": 14, "bytes_toserver": 14500, "bytes_toclient": 920, "age": 0.85},
            "tcp": {"syn": True, "ack": True, "rst": False, "psh": True},
            "alert": {"signature": "ET EXPLOIT EternalBlue SMB MS17-010 Probe", "severity": 1}
        },
        # Sensor 3: NetFlow v9 IPFIX (Domain Controller -> Database SQL Sync)
        {
            "IPV4_SRC_ADDR": "10.0.2.20", "IPV4_DST_ADDR": "10.0.4.100", "L4_SRC_PORT": 33060, "L4_DST_PORT": 3306,
            "PROTOCOL": 6, "IN_PKTS": 60, "OUT_PKTS": 40, "IN_BYTES": 6500, "OUT_BYTES": 4200, "DURATION": 1.2
        },
        # Sensor 4: Zeek conn.log (Workstation-2 -> Web Server benign HTTPS)
        {
            "id.orig_h": "10.0.3.51", "id.resp_h": "10.0.1.10", "id.orig_p": 52100, "id.resp_p": 443,
            "proto": "tcp", "orig_pkts": 18, "resp_pkts": 22, "orig_bytes": 1200, "resp_bytes": 15000,
            "duration": 0.15, "history": "ShADfFa"
        },
        # Sensor 5: Suricata EVE Flow (Edge Firewall -> Web Server external traffic)
        {
            "event_type": "flow", "src_ip": "198.51.100.25", "dest_ip": "10.0.1.10", "src_port": 44300, "dest_port": 443,
            "proto": "TCP", "flow": {"pkts_toserver": 110, "pkts_toclient": 90, "bytes_toserver": 12000, "bytes_toclient": 65000, "age": 2.1}
        }
    ]

    for raw_evt in stream_events:
        normalized = normalizer.normalize(raw_evt)
        buffer.push(normalized)
        source_label = normalized.sensor_source.upper()
        sig_info = f" | Alert: {normalized.alert_signature}" if normalized.alert_signature else ""
        print(f"  --> Ingested [{source_label:<14}]: {normalized.src_ip}:{normalized.src_port} -> {normalized.dst_ip}:{normalized.dst_port} ({normalized.protocol}){sig_info}")

    # 3. Buffer Health & Lossless Metrics
    print("\n[Step 3] Verifying Zero Data Loss Ingestion Metrics...")
    buf_metrics = buffer.metrics()
    print(f"  Total Ingested Events : {buf_metrics['total_ingested']}")
    print(f"  Total Dropped Events  : {buf_metrics['total_dropped']}")
    print(f"  Buffer Capacity Used  : {buf_metrics['utilization_pct']}% ({buf_metrics['current_depth']} / {buf_metrics['capacity']})")
    print(f"  Zero Loss Guarantee   : {'PASSED (Zero Drops)' if buf_metrics['zero_loss_status'] else 'FAILED'}")

    # 4. Generate Dynamic Graph Snapshot from Stream
    print("\n[Step 4] Continuous Dynamic Graph Snapshot Aggregation...")
    snapshot = streamer.generate_next_snapshot()
    if snapshot is None:
        raise RuntimeError("Failed to generate graph snapshot from stream")

    print(f"  Snapshot Generated Successfully:")
    print(f"    - Unique Topology Nodes : {snapshot.num_nodes}")
    print(f"    - Active Flow Edges     : {snapshot.num_edges}")
    print(f"    - Node Adjacency Mapping: {list(snapshot.node_to_idx.keys())}")

    # 5. Live G-FLOWWM Inference & Threat Scoring
    print("\n[Step 5] Real-Time Graph World Model Inference & Cyber-JEPA Surprisal...")
    with torch.no_grad():
        out = model(snapshot.nodes, snapshot.edge_index, snapshot.edges)

    print("  Per-Node Threat Risk Forecast:")
    for ip, idx in sorted(snapshot.node_to_idx.items(), key=lambda x: x[1]):
        risk_pct = torch.sigmoid(out.node_risk_logits[0, idx]).item() * 100.0
        print(f"    Node #{idx:<2} ({ip:<15}): Threat Risk = {risk_pct:>5.1f}%")

    print("\n" + "=" * 75)
    print("   PHASE 3 EXECUTION COMPLETE: STREAMING PIPELINE VERIFIED OPERATIONAL")
    print("=" * 75)


if __name__ == "__main__":
    main()
