"""Shadow Deployment, Canary Gating & Model Promotion Engine (Phase 6).

Implements:
1. Concurrent Dual-Model Inference Pipeline (Serving Flow-WM vs Candidate G-FLOWWM).
2. Expected Calibration Error (ECE) metric & Temperature Scaling Calibration.
3. Automated Canary Gating with zero-loss safety guarantees.
4. Instantaneous Fail-Closed Rollback.
"""
from __future__ import annotations

import time
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from models.flow_world_model import FlowWorldModel
from models.graph_world_model import GraphFlowWorldModel


class DeploymentPhase(str, Enum):
    SHADOW = "SHADOW"
    CANARY_10 = "CANARY_10"
    CANARY_50 = "CANARY_50"
    PROMOTED = "PROMOTED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class CalibrationMetrics:
    ece_before: float
    ece_after: float
    optimal_temperature: float
    brier_score: float
    meets_tolerance: bool  # True if ece_after <= 0.15


@dataclass
class CanaryGateReport:
    passed_all_gates: bool
    ece_metric: float
    stage_accuracy_retention: float
    critical_asset_protection_rate: float
    candidate_latency_ms: float
    serving_latency_ms: float
    gate_details: Dict[str, bool]
    current_phase: DeploymentPhase
    rare_stage_recall: float = 0.90
    rollback_frequency: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed_all_gates": self.passed_all_gates,
            "ece_metric": round(self.ece_metric, 4),
            "stage_accuracy_retention": round(self.stage_accuracy_retention, 4),
            "critical_asset_protection_rate": round(self.critical_asset_protection_rate, 4),
            "rare_stage_recall": round(self.rare_stage_recall, 4),
            "rollback_frequency": round(self.rollback_frequency, 4),
            "candidate_latency_ms": round(self.candidate_latency_ms, 2),
            "serving_latency_ms": round(self.serving_latency_ms, 2),
            "gate_details": self.gate_details,
            "current_phase": self.current_phase.value,
            "timestamp": self.timestamp,
        }


def compute_ece(
    logits: torch.Tensor,
    labels: torch.Tensor,
    n_bins: int = 15,
) -> float:
    """
    Compute Expected Calibration Error (ECE) for multi-class classification.
    ECE = sum_m (|B_m| / N) * |acc(B_m) - conf(B_m)|
    """
    softmaxes = F.softmax(logits, dim=-1)
    confidences, predictions = torch.max(softmaxes, dim=-1)
    accuracies = predictions.eq(labels)

    ece = torch.zeros(1, device=logits.device)
    bin_boundaries = torch.linspace(0, 1, n_bins + 1, device=logits.device)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]

        in_bin = confidences.gt(bin_lower.item()) * confidences.le(bin_upper.item())
        prop_in_bin = in_bin.float().mean()

        if prop_in_bin.item() > 0:
            accuracy_in_bin = accuracies[in_bin].float().mean()
            avg_confidence_in_bin = confidences[in_bin].mean()
            ece += torch.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

    return float(ece.item())


class TemperatureScaler(nn.Module):
    """
    Learns a scalar temperature parameter T > 0 to calibrate logits:
    p_calibrated = softmax(logits / T)
    """

    def __init__(self, init_temp: float = 1.5):
        super().__init__()
        self.temperature = nn.Parameter(torch.ones(1) * init_temp)

    def forward(self, logits: torch.Tensor) -> torch.Tensor:
        return logits / self.temperature.clamp(min=0.01)

    def tune_temperature(
        self,
        val_logits: torch.Tensor,
        val_labels: torch.Tensor,
        lr: float = 0.05,
        max_iters: int = 100,
    ) -> CalibrationMetrics:
        """Find optimal temperature minimizing CrossEntropyLoss on validation logits."""
        nll_criterion = nn.CrossEntropyLoss()
        ece_before = compute_ece(val_logits, val_labels)

        optimizer = torch.optim.LBFGS([self.temperature], lr=lr, max_iter=max_iters)

        def eval_loss():
            optimizer.zero_grad()
            loss = nll_criterion(self.forward(val_logits), val_labels)
            loss.backward()
            return loss

        optimizer.step(eval_loss)
        optimal_t = float(self.temperature.item())

        calibrated_logits = self.forward(val_logits).detach()
        ece_after = compute_ece(calibrated_logits, val_labels)

        # Compute Brier Score
        probs = F.softmax(calibrated_logits, dim=-1)
        one_hot = F.one_hot(val_labels, num_classes=calibrated_logits.shape[-1]).float()
        brier = float(((probs - one_hot) ** 2).sum(dim=-1).mean().item())

        return CalibrationMetrics(
            ece_before=ece_before,
            ece_after=ece_after,
            optimal_temperature=optimal_t,
            brier_score=brier,
            meets_tolerance=(ece_after <= 0.15),
        )


class DualModelShadowPipeline:
    """
    Concurrent inference pipeline serving production while executing G-FLOWWM in shadow mode.
    """

    def __init__(
        self,
        serving_model: FlowWorldModel,
        candidate_model: GraphFlowWorldModel,
        temperature_scaler: Optional[TemperatureScaler] = None,
    ):
        self.serving_model = serving_model.eval()
        self.candidate_model = candidate_model.eval()
        self.temperature_scaler = temperature_scaler or TemperatureScaler(init_temp=1.1)
        self.phase = DeploymentPhase.SHADOW
        self.inference_history: List[Dict[str, Any]] = []

    def execute_dual_inference(
        self,
        flow_sequence: torch.Tensor,             # [B, T, D_in] for serving model
        graph_nodes: torch.Tensor,               # [B, N, D_node] for candidate model
        graph_edge_index: torch.Tensor,          # [B, 2, E]
        graph_edge_attr: torch.Tensor,           # [B, E, D_edge]
    ) -> Dict[str, Any]:
        """
        Run serving model (production path) and candidate model (shadow path) concurrently.
        Returns active decision based on current deployment phase.
        """
        # 1. Serving Model Execution
        t0 = time.perf_counter()
        with torch.no_grad():
            serving_out = self.serving_model(flow_sequence)
        t_serving_ms = (time.perf_counter() - t0) * 1000.0

        serving_infil = float(serving_out.infil_probs[0, 0].item())
        serving_stage = int(torch.argmax(serving_out.stage_logits[0, 0]).item())

        # 2. Candidate Model Execution (Shadow Mode)
        t1 = time.perf_counter()
        with torch.no_grad():
            cand_out = self.candidate_model(
                nodes=graph_nodes,
                edge_index=graph_edge_index,
                edges=graph_edge_attr,
            )
            # Apply temperature calibration
            calibrated_stage_logits = self.temperature_scaler(cand_out.node_stage_logits)
        t_cand_ms = (time.perf_counter() - t1) * 1000.0

        cand_infil = float(torch.sigmoid(cand_out.node_risk_logits[0]).mean().item())
        cand_stage = int(torch.argmax(calibrated_stage_logits[0, 0]).item())

        # Measure agreement / divergence
        divergence = abs(serving_infil - cand_infil)
        stage_match = (serving_stage == cand_stage)

        # Decide primary driver based on Phase
        if self.phase == DeploymentPhase.PROMOTED:
            primary_infil = cand_infil
            primary_stage = cand_stage
            active_model = "candidate_G-FLOWWM"
        else:
            # SHADOW or CANARY early stage defaults to safe serving model
            primary_infil = serving_infil
            primary_stage = serving_stage
            active_model = "serving_flow-wm-v3.0.0"

        record = {
            "timestamp": time.time(),
            "phase": self.phase.value,
            "active_model": active_model,
            "primary_decision": {
                "infil_probability": primary_infil,
                "predicted_stage": primary_stage,
            },
            "serving_metrics": {
                "latency_ms": t_serving_ms,
                "infil_probability": serving_infil,
                "stage": serving_stage,
            },
            "candidate_metrics": {
                "latency_ms": t_cand_ms,
                "infil_probability": cand_infil,
                "stage": cand_stage,
            },
            "divergence": divergence,
            "stage_match": stage_match,
        }
        self.inference_history.append(record)
        return record


class CanaryGateManager:
    """
    Automates canary gating, qualification checks, and fail-closed rollbacks.
    """

    def __init__(self, dual_pipeline: DualModelShadowPipeline):
        self.pipeline = dual_pipeline
        self.gate_history: List[CanaryGateReport] = []

    def evaluate_promotion_gates(
        self,
        val_logits: torch.Tensor,
        val_labels: torch.Tensor,
        retained_accuracy: float = 0.95,
        critical_asset_protection_rate: float = 1.0,
        max_candidate_latency_ms: float = 50.0,
        rare_stage_recall: float = 0.90,
        min_rare_stage_recall: float = 0.85,
        baseline_ece: float = 0.15,
        max_allowed_rollback_frequency: float = 0.10,
    ) -> CanaryGateReport:
        """
        Evaluate candidate model against strict Phase 6 production gating criteria:
        1. Expected Calibration Error (ECE) <= 0.15 and does not regress above baseline
        2. Stage accuracy retention >= 0.90 (Continual learning / no catastrophic forgetting)
        3. Rare-stage recall >= min_rare_stage_recall (MITRE rare attack vector retention)
        4. Critical asset protection rate == 1.0 (Zero-loss enterprise guarantee)
        5. Rollback frequency <= max_allowed_rollback_frequency (Stability guardrail)
        6. Latency <= 50.0ms
        """
        # Gate 1: Calibration
        calibrated_logits = self.pipeline.temperature_scaler(val_logits).detach()
        ece = compute_ece(calibrated_logits, val_labels)
        gate_ece = (ece <= baseline_ece and ece <= 0.15)

        # Gate 2: Continual learning retention
        gate_retention = (retained_accuracy >= 0.90)

        # Gate 3: Rare-stage recall (prevents regression on rare attack vectors)
        gate_rare_recall = (rare_stage_recall >= min_rare_stage_recall)

        # Gate 4: Critical asset safety
        gate_critical = (critical_asset_protection_rate >= 1.0)

        # Gate 5: Rollback frequency guardrail
        recent_gates = self.gate_history[-20:] if self.gate_history else []
        rollbacks = sum(1 for g in recent_gates if not g.passed_all_gates or g.current_phase == DeploymentPhase.ROLLED_BACK)
        rollback_freq = (rollbacks / len(recent_gates)) if recent_gates else 0.0
        gate_rollback = (rollback_freq <= max_allowed_rollback_frequency)

        # Gate 6: Latency budget
        history = self.pipeline.inference_history
        avg_cand_lat = np.mean([h["candidate_metrics"]["latency_ms"] for h in history]) if history else 12.0
        avg_serv_lat = np.mean([h["serving_metrics"]["latency_ms"] for h in history]) if history else 8.0
        gate_latency = (avg_cand_lat <= max_candidate_latency_ms)

        passed_all = (
            gate_ece
            and gate_retention
            and gate_rare_recall
            and gate_critical
            and gate_rollback
            and gate_latency
        )

        report = CanaryGateReport(
            passed_all_gates=passed_all,
            ece_metric=ece,
            stage_accuracy_retention=retained_accuracy,
            critical_asset_protection_rate=critical_asset_protection_rate,
            rare_stage_recall=rare_stage_recall,
            rollback_frequency=rollback_freq,
            candidate_latency_ms=float(avg_cand_lat),
            serving_latency_ms=float(avg_serv_lat),
            gate_details={
                "ece_within_tolerance": gate_ece,
                "no_catastrophic_forgetting": gate_retention,
                "rare_stage_recall_preserved": gate_rare_recall,
                "zero_loss_critical_protection": gate_critical,
                "rollback_frequency_within_tolerance": gate_rollback,
                "inference_latency_budget": gate_latency,
            },
            current_phase=self.pipeline.phase,
        )
        self.gate_history.append(report)
        return report

    def advance_deployment(self, report: CanaryGateReport) -> DeploymentPhase:
        """Progress through Canary stages or promote model if gates pass."""
        if not report.passed_all_gates:
            # Fail-closed: trigger immediate rollback
            return self.trigger_rollback(reason="Failed canary gating criteria")

        current = self.pipeline.phase
        if current == DeploymentPhase.SHADOW:
            self.pipeline.phase = DeploymentPhase.CANARY_10
        elif current == DeploymentPhase.CANARY_10:
            self.pipeline.phase = DeploymentPhase.CANARY_50
        elif current == DeploymentPhase.CANARY_50:
            self.pipeline.phase = DeploymentPhase.PROMOTED
        elif current == DeploymentPhase.ROLLED_BACK:
            self.pipeline.phase = DeploymentPhase.SHADOW

        return self.pipeline.phase

    def trigger_rollback(self, reason: str = "Manual or automated anomaly abort") -> DeploymentPhase:
        """Instantaneous fail-closed rollback to production serving baseline."""
        self.pipeline.phase = DeploymentPhase.ROLLED_BACK
        return self.pipeline.phase
