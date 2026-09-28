"""
Forecast Engine

Clean K-step forecast contract layered around the existing Temporal World Model.
Combines the model's prediction with the deterministic risk engine and belief-state
reasoning to produce a single coherent forecast object.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.asset import Asset
from app.schemas.forecast import (
    ForecastDetail,
    ForecastStep,
    TargetCandidate,
    BeliefSummary,
    BeliefBranch,
)
from app.services.risk_engine import compute_risk, asset_risk


def _stage_state_label(stage: str) -> str:
    mapping = {
        "reconnaissance": "Reconnaissance",
        "initial_access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege_escalation": "Privilege Escalation",
        "defense_evasion": "Defense Evasion",
        "credential_access": "Credential Access",
        "discovery": "Discovery",
        "lateral_movement": "Lateral Movement",
        "collection": "Collection",
        "command_and_control": "Command & Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
        "unknown": "Unknown",
    }
    return mapping.get(stage, stage)


def _etl_ml_forecast(ml: Optional[dict]) -> Optional[dict]:
    """Normalize the world-model service output."""
    if not ml:
        return None
    return ml


async def build_forecast_detail(
    db: AsyncSession,
    incident_id: UUID,
    horizon: int = 4,
    ml: Optional[dict] = None,
) -> ForecastDetail:
    """Build the detailed forecast for an incident."""
    incident_result = await db.execute(
        select(Incident).where(Incident.id == incident_id).options(
            selectinload(Incident.assets).selectinload(Asset.services)
        )
    )
    incident = incident_result.scalar_one_or_none()
    if not incident:
        raise ValueError("Incident not found")

    # Incident assets (for target candidates + risk inputs)
    assets = list(incident.assets or [])
    asset_map = {str(a.id): a for a in assets}

    if ml is None:
        # Try the real world model; graceful fallback if unavailable.
        try:
            from app.services.world_model_service import try_world_model_forecast
            ml = try_world_model_forecast(horizon=horizon)
        except Exception:
            ml = None

    if not ml:
        # Deterministic fallback so the forecast API remains functional offline.
        stages = ["initial_access", "lateral_movement", "collection"]
        timeline = [
            {"window_offset": i + 1, "stage": s, "probability": 1.0 - 0.12 * i, "confidence": 0.7 - 0.05 * i, "eta_seconds": 60.0 * (i + 1)}
            for i, s in enumerate(stages[:horizon])
        ]
        ml = {
            "current_stage": stages[0],
            "current_confidence": 0.72,
            "timeline": timeline,
            "explanation": {"natural_language": "Offline fallback forecast."},
            "thinking": None,
            "recommended_action": "monitor",
            "recommended_actions": [],
            "model_version": "flow-wm-v3.0.0-fallback",
        }

    base_ml = _etl_ml_forecast(ml)
    model_version = base_ml["model_version"]
    current_stage = base_ml["current_stage"]

    predicted_stages: list = []
    probabilities: list = []
    steps: list = []
    eta_seconds: list = []
    confidence_vals: list = []
    risk_vals: list = []

    max_prob = float(base_ml.get("current_confidence", 0.5))
    for win in base_ml.get("timeline", [])[:horizon]:
        stage = win.get("stage", "unknown")
        prob = float(win.get("probability", 0.0))
        conf = float(win.get("confidence", prob))
        eta = float(win.get("eta_seconds", 0.0))
        predicted_stages.append(stage)
        eta_seconds.append(eta)
        confidence_vals.append(round(conf, 4))

        # target resolution from incident assets (best guess: database/server zone)
        target_id = win.get("target_asset_id")
        target_name = win.get("target_asset_name")

        # risk per step via deterministic engine
        exposure = 0.5
        criticality = "medium"
        target_asset = None
        if target_id and str(target_id) in asset_map:
            target_asset = asset_map[str(target_id)]
        elif assets:
            prios = sorted(
                assets,
                key=lambda a: (
                    0 if getattr(a, "asset_type", None) and "data" in str(getattr(a, "asset_type", None)).lower() else 1,
                    (a.criticality.value if hasattr(a.criticality, "value") else "medium"),
                ),
            )
            target_asset = prios[0]
        if target_asset is not None:
            r = asset_risk(target_asset, threat_probability=prob, confidence=conf)
            exposure = r["exposure_component"] / 100.0
            criticality = target_asset.criticality.value if hasattr(target_asset.criticality, "value") else "medium"
            risk_score = r["risk_score"]
            risk_level = r["risk_level"]
            if target_name is None:
                target_name = target_asset.hostname
            target_id = target_asset.id
        else:
            r = compute_risk(threat_probability=prob, confidence=conf)
            risk_score = r["risk_score"]
            risk_level = r["risk_level"]

        risk_vals.append(round(risk_score, 2))
        probabilities.append({stage: round(prob, 4)})
        steps.append(
            ForecastStep(
                offset=win.get("window_offset", len(steps) + 1),
                stage=stage,
                probability=round(prob, 4),
                confidence=round(conf, 4),
                eta_seconds=eta,
                target_asset_id=target_id,
                target_asset_name=target_name,
            )
        )
        max_prob = max(max_prob, prob)

    # Target candidates across steps
    candidates: dict = {}
    for step in steps:
        if step.target_asset_id and step.target_asset_name:
            key = str(step.target_asset_id)
            if key not in candidates:
                candidates[key] = {
                    "asset_id": step.target_asset_id,
                    "asset_name": step.target_asset_name,
                    "asset_type": (
                        target_asset.asset_type.value if target_asset and hasattr(target_asset.asset_type, "value") else "unknown"
                    ),
                    "probability": step.probability,
                }
            else:
                candidates[key]["probability"] = max(candidates[key]["probability"], step.probability)
    target_candidates = [
        TargetCandidate(**c) for c in sorted(candidates.values(), key=lambda x: x["probability"], reverse=True)
    ][:5]

    # Risk level (aggregate = max per-step risk)
    overall_risk = max(risk_vals) if risk_vals else 0.0
    from app.core.policy_config import risk_level_for_score
    risk_level = risk_level_for_score(overall_risk)

    # Belief summary from the model's thinking output
    belief = None
    thinking = base_ml.get("thinking")
    if thinking:
        branches = []
        branch_data = thinking.get("branches") or []
        branch_details = thinking.get("branch_details")
        branch_spec = branch_details if isinstance(branch_details, list) else None
        if isinstance(branch_data, int):
            # Model returns the branch *count* (plus optional per-branch rollout
            # detail); reconstruct representative branches from those details,
            # falling back to consensus + worst-case data.
            n_branches = branch_data
            consensus_target = thinking.get("consensus_target")
            consensus_stage = thinking.get("consensus_stage")
            agreement = float(thinking.get("consensus_agreement", 0.0))
            worst = thinking.get("worst_case") or {}
            if isinstance(worst, str):
                worst = {"terminal_stage": worst}
            elif not isinstance(worst, dict):
                worst = {}
            if branch_spec:
                for d in branch_spec[:n_branches]:
                    branches.append(
                        BeliefBranch(
                            branch=int(d.get("branch", len(branches) + 1)) + 1,
                            confidence=round(agreement, 4),
                            target_name=consensus_target,
                            stage=d.get("terminal_stage") or consensus_stage or current_stage,
                            risk=float(d.get("peak_infil_risk", 0.0)) * 100,
                        )
                    )
            else:
                for i in range(n_branches):
                    branches.append(
                        BeliefBranch(
                            branch=i + 1,
                            confidence=round(agreement, 4),
                            target_name=consensus_target,
                            stage=consensus_stage or current_stage,
                            risk=float(worst.get("peak_infil_risk", 0.0) * 100) if worst else overall_risk,
                        )
                    )
            # Augment with worst-case branch detail if present (legacy models
            # without per-branch details still get a distinct worst-case branch).
            worst_stage = worst.get("terminal_stage")
            worst_risk = worst.get("peak_infil_risk")
            if worst_stage and branches and not branch_spec:
                branches[0] = BeliefBranch(
                    branch=1,
                    confidence=round(max(agreement, 0.5), 4),
                    target_name=consensus_target,
                    stage=worst_stage,
                    risk=float(worst_risk or 0.0) * 100,
                )
        else:
            for i, b in enumerate(branch_data):
                branches.append(
                    BeliefBranch(
                        branch=i + 1,
                        confidence=float(b.get("confidence", thinking.get("consensus_agreement", 0.5))),
                        target_name=b.get("target") or thinking.get("consensus_target"),
                        stage=b.get("terminal_stage"),
                        risk=float(b.get("peak_risk") or overall_risk),
                    )
                )
        worst = thinking.get("worst_case")
        worst_label = None
        if isinstance(worst, dict):
            stage = worst.get("terminal_stage")
            worst_label = {
                "terminal_stage": stage if isinstance(stage, str) else current_stage,
                "peak_infil_risk": worst.get("peak_infil_risk", 0.0),
            }
        elif isinstance(worst, str):
            worst_label = {"terminal_stage": worst}
        belief = BeliefSummary(
            branches=branches[:5],
            consensus_target=thinking.get("consensus_target"),
            consensus_stage=thinking.get("consensus_stage") or current_stage,
            consensus_confidence=float(thinking.get("consensus_confidence", max_prob)),
            consensus_agreement=float(thinking.get("consensus_agreement", 0.0)),
            worst_case=worst_label,
        )

    return ForecastDetail(
        incident_id=incident_id,
        model_version=model_version,
        generated_at=datetime.utcnow(),
        current_state=f"{_stage_state_label(current_stage)} in progress",
        current_stage=current_stage,
        current_confidence=round(max_prob, 4),
        predicted_stages=predicted_stages,
        predicted_targets=target_candidates,
        probabilities=probabilities,
        forecast_horizon=len(steps),
        estimated_time=eta_seconds,
        confidence=confidence_vals,
        risk=risk_vals,
        risk_level=risk_level,
        steps=steps,
        belief=belief,
        recommended_action=base_ml.get("recommended_action", "monitor"),
        recommended_actions=base_ml.get("recommended_actions", []),
        explanation=base_ml.get("explanation"),
    )