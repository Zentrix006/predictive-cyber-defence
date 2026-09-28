import pytest
import torch
import torch.nn as nn
from app.services.canary_gate import (
    compute_ece,
    TemperatureScaler,
    DualModelShadowPipeline,
    CanaryGateManager,
    DeploymentPhase,
)
from models.flow_world_model import FlowWorldModel
from models.graph_world_model import GraphFlowWorldModel


def test_ece_computation():
    # Synthetic overconfident logits
    torch.manual_seed(42)
    logits = torch.randn(100, 5) * 5.0  # high confidence
    labels = torch.randint(0, 5, (100,))
    ece = compute_ece(logits, labels, n_bins=10)
    assert isinstance(ece, float)
    assert 0.0 <= ece <= 1.0


def test_temperature_scaling_calibration():
    torch.manual_seed(42)
    val_logits = torch.randn(200, 10) * 3.5
    val_labels = torch.randint(0, 10, (200,))

    scaler = TemperatureScaler(init_temp=1.0)
    metrics = scaler.tune_temperature(val_logits, val_labels, max_iters=25)

    assert metrics.optimal_temperature > 0.0
    assert metrics.ece_after <= metrics.ece_before + 0.05
    assert metrics.brier_score >= 0.0


def test_dual_model_shadow_execution():
    torch.manual_seed(42)
    serving = FlowWorldModel(feature_dim=10, context_window=4, horizon=2, num_stages=5)
    candidate = GraphFlowWorldModel(node_dim=10, edge_dim=6, d_model=16, num_stages=5)

    pipeline = DualModelShadowPipeline(serving_model=serving, candidate_model=candidate)
    assert pipeline.phase == DeploymentPhase.SHADOW

    flow_seq = torch.randn(1, 4, 10)
    nodes = torch.randn(1, 4, 10)
    edges = torch.tensor([[[0, 1], [1, 2]]], dtype=torch.long)
    edge_attr = torch.randn(1, 2, 6)

    # In SHADOW mode, active decision must come from serving model
    res_shadow = pipeline.execute_dual_inference(flow_seq, nodes, edges, edge_attr)
    assert res_shadow["active_model"] == "serving_flow-wm-v3.0.0"
    assert "primary_decision" in res_shadow
    assert "serving_metrics" in res_shadow
    assert "candidate_metrics" in res_shadow
    assert res_shadow["candidate_metrics"]["latency_ms"] >= 0.0

    # In PROMOTED mode, active decision must come from candidate model
    pipeline.phase = DeploymentPhase.PROMOTED
    res_promo = pipeline.execute_dual_inference(flow_seq, nodes, edges, edge_attr)
    assert res_promo["active_model"] == "candidate_G-FLOWWM"


def test_canary_gating_and_fail_closed_rollback():
    torch.manual_seed(42)
    serving = FlowWorldModel(feature_dim=10, context_window=4, horizon=2, num_stages=5)
    candidate = GraphFlowWorldModel(node_dim=10, edge_dim=6, d_model=16, num_stages=5)
    pipeline = DualModelShadowPipeline(serving_model=serving, candidate_model=candidate)
    manager = CanaryGateManager(dual_pipeline=pipeline)

    val_logits = torch.randn(50, 5)
    val_labels = torch.randint(0, 5, (50,))

    # 1. Test Passing All Gates
    report_pass = manager.evaluate_promotion_gates(
        val_logits=val_logits,
        val_labels=val_labels,
        retained_accuracy=0.96,
        critical_asset_protection_rate=1.0,
    )
    # If ECE is within tolerance, advance
    if report_pass.passed_all_gates:
        phase = manager.advance_deployment(report_pass)
        assert phase == DeploymentPhase.CANARY_10
        phase = manager.advance_deployment(report_pass)
        assert phase == DeploymentPhase.CANARY_50
        phase = manager.advance_deployment(report_pass)
        assert phase == DeploymentPhase.PROMOTED

    # 2. Test Failing Gating (e.g. Critical Asset Protection Compromised) -> Instant Rollback
    report_fail = manager.evaluate_promotion_gates(
        val_logits=val_logits,
        val_labels=val_labels,
        retained_accuracy=0.96,
        critical_asset_protection_rate=0.85,  # Violates zero-loss requirement
    )
    assert not report_fail.passed_all_gates
    assert report_fail.gate_details["zero_loss_critical_protection"] is False

    rollback_phase = manager.advance_deployment(report_fail)
    assert rollback_phase == DeploymentPhase.ROLLED_BACK
    assert pipeline.phase == DeploymentPhase.ROLLED_BACK


def test_rare_stage_recall_and_quality_gating():
    """Verify promotion is strictly blocked when rare-stage recall regresses or calibration error increases."""
    serving = FlowWorldModel(feature_dim=10, context_window=4, horizon=2, num_stages=5)
    candidate = GraphFlowWorldModel(node_dim=10, edge_dim=6, d_model=16, num_stages=5)
    pipeline = DualModelShadowPipeline(serving_model=serving, candidate_model=candidate)
    manager = CanaryGateManager(dual_pipeline=pipeline)

    val_logits = torch.randn(50, 5)
    val_labels = torch.randint(0, 5, (50,))

    # 1. Rare-stage recall regression blocks promotion
    report_regress = manager.evaluate_promotion_gates(
        val_logits=val_logits,
        val_labels=val_labels,
        retained_accuracy=0.95,
        critical_asset_protection_rate=1.0,
        rare_stage_recall=0.72,          # Regressed below 0.85 threshold!
        min_rare_stage_recall=0.85,
    )
    assert not report_regress.passed_all_gates
    assert report_regress.gate_details["rare_stage_recall_preserved"] is False
    assert report_regress.rare_stage_recall == 0.72

    # 2. Calibration error exceeding baseline blocks promotion
    report_ece_fail = manager.evaluate_promotion_gates(
        val_logits=val_logits,
        val_labels=val_labels,
        retained_accuracy=0.95,
        critical_asset_protection_rate=1.0,
        rare_stage_recall=0.92,
        baseline_ece=0.001,              # Strict baseline that calibrated logits exceed
    )
    assert not report_ece_fail.passed_all_gates
    assert report_ece_fail.gate_details["ece_within_tolerance"] is False


def test_rollback_frequency_gating():
    """Verify promotion is blocked when recent rollback frequency exceeds stability tolerance."""
    serving = FlowWorldModel(feature_dim=10, context_window=4, horizon=2, num_stages=5)
    candidate = GraphFlowWorldModel(node_dim=10, edge_dim=6, d_model=16, num_stages=5)
    pipeline = DualModelShadowPipeline(serving_model=serving, candidate_model=candidate)
    manager = CanaryGateManager(dual_pipeline=pipeline)

    val_logits = torch.randn(50, 5)
    val_labels = torch.randint(0, 5, (50,))

    # Inject multiple failed/rolled-back gate evaluations into history
    for _ in range(5):
        manager.evaluate_promotion_gates(
            val_logits=val_logits,
            val_labels=val_labels,
            retained_accuracy=0.80,  # Fails
        )

    # Next evaluation with otherwise good accuracy must fail on rollback frequency guardrail
    report = manager.evaluate_promotion_gates(
        val_logits=val_logits,
        val_labels=val_labels,
        retained_accuracy=0.98,
        critical_asset_protection_rate=1.0,
        rare_stage_recall=0.95,
        max_allowed_rollback_frequency=0.10,
    )
    assert not report.passed_all_gates
    assert report.gate_details["rollback_frequency_within_tolerance"] is False
    assert report.rollback_frequency > 0.10


@pytest.mark.asyncio
async def test_novel_vector_feedback_intake_api():
    """Verify SOC analyst feedback intake for confirmed novel attack vectors feeds learning queue."""
    from app.api.v1.endpoints.canary import (
        intake_novel_vector_feedback,
        get_learning_feedback_status,
        NovelVectorFeedbackRequest,
    )

    mock_user = {"sub": "senior_threat_analyst_01", "role": "admin"}
    req = NovelVectorFeedbackRequest(
        vector_name="lateral_rdp_hijack_unobserved_path",
        mitre_stage="T1563.002",
        evidence_summary="Discovered suspicious RDP pivot across unmapped interface switchport",
        novelty_score=0.91,
        analyst_verdict="CONFIRMED_NOVEL",
        target_ip="172.22.192.152",
        notes="High-confidence lateral movement via hijacked terminal services session",
    )

    res = await intake_novel_vector_feedback(req, current_user=mock_user)
    assert res["status"] == "queued_for_candidate_retraining"
    assert res["vector_name"] == "lateral_rdp_hijack_unobserved_path"
    assert res["verdict"] == "CONFIRMED_NOVEL"
    assert "feedback_id" in res

    # Verify status reflects feedback count
    status = await get_learning_feedback_status()
    assert status["novelty_events"] >= 1
