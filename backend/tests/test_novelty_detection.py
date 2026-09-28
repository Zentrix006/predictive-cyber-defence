"""Unit tests for TriFactorNoveltyDetector and OnlineNoveltyClusterer."""
import numpy as np
import pytest
import torch

from models.flow_world_model import FlowWorldModel
from models.novelty_detector import TriFactorNoveltyDetector
from models.novelty_clusterer import OnlineNoveltyClusterer


def test_flow_world_model_novelty_outputs():
    model = FlowWorldModel(feature_dim=10, d_model=32, nhead=2, num_layers=2, context_window=5, horizon=3, n_branches=3)
    model.eval()

    x = torch.randn(2, 5, 10)
    with torch.no_grad():
        out = model(x)

    assert out.free_energy is not None
    assert out.free_energy.shape == (2, 3)
    assert out.epistemic_variance is not None
    assert out.epistemic_variance.shape == (2, 3)
    assert out.latent_belief is not None
    assert out.latent_belief.shape == (2, 32)


def test_novelty_detector_benign_vs_anomalous():
    feature_names = [f"feat_{i}" for i in range(10)]
    detector = TriFactorNoveltyDetector(
        novelty_threshold=0.60,
        energy_scale=10.0,
        surprisal_scale=1.0,
        epistemic_scale=0.10,
        feature_names=feature_names,
    )

    # 1. Normal benign observation: small prediction error, low free energy, low branch variance
    cur_state = np.zeros(10, dtype=np.float32)
    pred_future = np.zeros((3, 10), dtype=np.float32)
    benign_eval = detector.assess(
        current_state=cur_state,
        predicted_future=pred_future,
        free_energy=-5.0,
        epistemic_var=0.001,
        actual_next_state=np.zeros(10, dtype=np.float32),
    )
    assert not benign_eval.is_novel
    assert benign_eval.novelty_score < 0.50
    assert "consistent" in benign_eval.summary.lower()

    # 2. Strong novel anomaly: massive surprisal, high free energy, high epistemic disagreement
    anom_next = np.ones(10, dtype=np.float32) * 5.0
    anom_eval = detector.assess(
        current_state=cur_state,
        predicted_future=pred_future,
        free_energy=15.0,
        epistemic_var=0.25,
        actual_next_state=anom_next,
    )
    assert anom_eval.is_novel
    assert anom_eval.novelty_score >= 0.60
    assert len(anom_eval.top_anomalous_features) == 5
    assert "novel" in anom_eval.summary.lower()


def test_online_novelty_clusterer():
    feature_names = ["syn_ratio", "byte_vol", "duration", "flow_rate"]
    clusterer = OnlineNoveltyClusterer(distance_threshold=1.5, max_clusters=10, feature_names=feature_names)
    baseline_mean = np.array([0.1, 100.0, 1.0, 50.0], dtype=np.float32)

    # First event: novel burst
    emb1 = np.array([1.0, 2.0, 0.5], dtype=np.float32)
    feat1 = np.array([0.9, 5000.0, 0.01, 1000.0], dtype=np.float32)
    c1 = clusterer.assign_or_create(emb1, feat1, baseline_mean=baseline_mean)
    assert c1.cluster_id == "proto_cluster_1"
    assert c1.sample_count == 1
    assert "elevated" in c1.signature.lower()

    # Second event: similar embedding, should merge into cluster 1
    emb2 = np.array([1.1, 1.9, 0.6], dtype=np.float32)
    feat2 = np.array([0.85, 4800.0, 0.01, 950.0], dtype=np.float32)
    c2 = clusterer.assign_or_create(emb2, feat2, baseline_mean=baseline_mean)
    assert c2.cluster_id == "proto_cluster_1"
    assert c2.sample_count == 2

    # Third event: radically different embedding, should create proto_cluster_2
    emb3 = np.array([10.0, -8.0, 5.0], dtype=np.float32)
    feat3 = np.array([0.0, 10.0, 3600.0, 0.1], dtype=np.float32)
    c3 = clusterer.assign_or_create(emb3, feat3, baseline_mean=baseline_mean)
    assert c3.cluster_id == "proto_cluster_2"
    assert c3.sample_count == 1

    active = clusterer.get_active_clusters()
    assert len(active) == 2
    assert active[0]["cluster_id"] == "proto_cluster_1"
    assert active[0]["sample_count"] == 2


def test_adaptive_conformal_and_mimicry_detection():
    detector = TriFactorNoveltyDetector(
        novelty_threshold=0.65,
        adaptive_conformal=True,
        conformal_alpha=0.05,
    )
    # Calibrate baseline with low scores
    detector.update_baseline([0.10, 0.12, 0.11, 0.15, 0.13] * 5)
    eff_thresh = detector.get_effective_threshold()
    assert 0.35 <= eff_thresh < 0.65

    # Test adversarial perturbation mimicry: low surprisal but high free energy
    cur = np.zeros(10, dtype=np.float32)
    pred = np.zeros((3, 10), dtype=np.float32)
    next_s = np.zeros(10, dtype=np.float32) + 0.001
    eval_adv = detector.assess(
        current_state=cur,
        predicted_future=pred,
        free_energy=16.0,
        epistemic_var=0.15,
        actual_next_state=next_s,
    )
    assert eval_adv.is_mimicry_detected
    assert eval_adv.is_novel


def test_supernode_pooling_and_shannon_entropy():
    from features.extract import shannon_entropy
    from features.graph_extractor import build_graph_from_flow_records

    # 1. Shannon entropy tests
    h_benign = shannon_entropy("api.github.com")
    h_tunnel = shannon_entropy("a9f83b2e71d4c09a8e6b12f45da812ef")
    assert h_tunnel > 3.6
    assert h_tunnel > h_benign

    # 2. Supernode pooling: 1000 external flows must be bounded <= 34 vertices
    flows = [
        {"src_ip": f"45.{i % 250}.{(i * 3) % 250}.{(i * 7) % 250 + 1}", "dst_ip": "10.0.0.1"}
        for i in range(1000)
    ]
    snap = build_graph_from_flow_records(flows, max_external_nodes=32)
    assert snap.num_nodes <= 34
    assert "EXT_SPOOFED_CLUSTER" in snap.node_to_idx
