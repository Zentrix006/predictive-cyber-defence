"""Unit tests for MultiSensorTelemetryNormalizer, StreamingTelemetryBuffer, and ContinuousGraphStreamer."""
import pytest
import torch

from features.streaming_telemetry import (
    MultiSensorTelemetryNormalizer,
    StreamingTelemetryBuffer,
    ContinuousGraphStreamer,
    NormalizedFlow,
)
from models.graph_world_model import GraphFlowWorldModel


def test_zeek_normalizer():
    normalizer = MultiSensorTelemetryNormalizer()
    zeek_record = {
        "id.orig_h": "192.168.1.100",
        "id.resp_h": "10.0.0.1",
        "id.orig_p": 54321,
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_pkts": 12,
        "resp_pkts": 15,
        "orig_bytes": 1400,
        "resp_bytes": 4500,
        "duration": 1.25,
        "history": "ShADdFf",
    }
    flow = normalizer.normalize(zeek_record)
    assert flow.sensor_source == "zeek"
    assert flow.src_ip == "192.168.1.100"
    assert flow.dst_ip == "10.0.0.1"
    assert flow.src_port == 54321
    assert flow.dst_port == 443
    assert flow.forward_packets == 12
    assert flow.reverse_packets == 15
    assert flow.tcp_flags.get("syn") == 1
    assert flow.tcp_flags.get("fin") == 1

    vec = flow.to_feature_vector(feature_dim=35)
    assert len(vec) == 35
    assert vec[0] == 12.0
    assert vec[1] == 15.0


def test_suricata_eve_normalizer():
    normalizer = MultiSensorTelemetryNormalizer()
    eve_alert = {
        "event_type": "alert",
        "src_ip": "172.16.0.5",
        "dest_ip": "10.0.0.50",
        "src_port": 49152,
        "dest_port": 445,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 8,
            "pkts_toclient": 2,
            "bytes_toserver": 1200,
            "bytes_toclient": 180,
            "age": 0.45,
        },
        "tcp": {"syn": True, "ack": True, "rst": False},
        "alert": {
            "signature": "ET EXPLOIT SMB Remote Code Execution",
            "severity": 1,
        },
    }
    flow = normalizer.normalize(eve_alert)
    assert flow.sensor_source == "suricata"
    assert flow.src_ip == "172.16.0.5"
    assert flow.dst_ip == "10.0.0.50"
    assert flow.dst_port == 445
    assert flow.forward_packets == 8
    assert flow.alert_signature == "ET EXPLOIT SMB Remote Code Execution"
    assert flow.tcp_flags.get("syn") == 1


def test_netflow_ipfix_normalizer():
    normalizer = MultiSensorTelemetryNormalizer()
    netflow_record = {
        "IPV4_SRC_ADDR": "10.0.2.15",
        "IPV4_DST_ADDR": "10.0.3.20",
        "L4_SRC_PORT": 38920,
        "L4_DST_PORT": 3306,
        "PROTOCOL": 6,
        "IN_PKTS": 40,
        "OUT_PKTS": 25,
        "IN_BYTES": 4200,
        "OUT_BYTES": 12500,
        "DURATION": 3.5,
    }
    flow = normalizer.normalize(netflow_record)
    assert flow.sensor_source == "netflow_ipfix"
    assert flow.src_ip == "10.0.2.15"
    assert flow.dst_ip == "10.0.3.20"
    assert flow.dst_port == 3306
    assert flow.forward_packets == 40
    assert flow.forward_bytes == 4200


def test_streaming_buffer_lossless():
    buffer = StreamingTelemetryBuffer(capacity=100)
    for i in range(50):
        flow = NormalizedFlow(
            src_ip=f"10.0.0.{i}",
            dst_ip="10.0.1.1",
            src_port=1000 + i,
            dst_port=80,
            protocol="TCP",
            forward_packets=5,
            reverse_packets=3,
            forward_bytes=500,
            reverse_bytes=300,
            duration_seconds=0.1,
        )
        ok = buffer.push(flow)
        assert ok

    metrics = buffer.metrics()
    assert metrics["current_depth"] == 50
    assert metrics["total_ingested"] == 50
    assert metrics["total_dropped"] == 0
    assert metrics["zero_loss_status"] is True

    # Drain window
    drained = buffer.drain_window(max_items=30)
    assert len(drained) == 30
    assert len(buffer.buffer) == 20


def test_continuous_graph_streaming_and_world_model_inference():
    buffer = StreamingTelemetryBuffer(capacity=500)
    streamer = ContinuousGraphStreamer(buffer=buffer, node_dim=16, edge_dim=35)
    normalizer = MultiSensorTelemetryNormalizer()

    # Stream multi-source flows into buffer
    zeek_evt = {
        "id.orig_h": "10.0.1.10", "id.resp_h": "10.0.2.20", "id.orig_p": 44321, "id.resp_p": 88,
        "proto": "tcp", "orig_pkts": 50, "resp_pkts": 40, "orig_bytes": 5000, "resp_bytes": 4000,
        "duration": 0.5, "history": "ShADdFf"
    }
    suricata_evt = {
        "event_type": "alert", "src_ip": "10.0.3.50", "dest_ip": "10.0.2.20", "src_port": 50000, "dest_port": 445,
        "proto": "TCP", "flow": {"pkts_toserver": 30, "pkts_toclient": 10, "bytes_toserver": 3000, "bytes_toclient": 1000, "age": 0.2},
        "alert": {"signature": "ET LATERAL SMB Relay", "severity": 2}
    }
    netflow_evt = {
        "IPV4_SRC_ADDR": "10.0.2.20", "IPV4_DST_ADDR": "10.0.4.100", "L4_SRC_PORT": 5555, "L4_DST_PORT": 3306,
        "PROTOCOL": 6, "IN_PKTS": 20, "OUT_PKTS": 15, "IN_BYTES": 2000, "OUT_BYTES": 1500, "DURATION": 1.0
    }

    buffer.push(normalizer.normalize(zeek_evt))
    buffer.push(normalizer.normalize(suricata_evt))
    buffer.push(normalizer.normalize(netflow_evt))

    # Generate graph snapshot
    snapshot = streamer.generate_next_snapshot()
    assert snapshot is not None
    assert snapshot.num_nodes == 4
    assert snapshot.num_edges == 3
    assert streamer.snapshots_generated == 1

    # Feed snapshot directly into G-FLOWWM for live inference
    model = GraphFlowWorldModel(node_dim=16, edge_dim=35, d_model=32, horizon=2)
    model.eval()

    with torch.no_grad():
        out = model(snapshot.nodes, snapshot.edge_index, snapshot.edges)

    assert out.latent_state.shape == (1, 4, 32)
    assert out.predicted_latent_future.shape == (1, 2, 4, 32)
    assert out.node_risk_logits.shape == (1, 4)
