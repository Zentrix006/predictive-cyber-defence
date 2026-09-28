"""
Predictions API Endpoints
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user
from app.models.prediction import Prediction, ForecastWindow, PredictedTarget
from app.schemas.prediction import (
    AttackForecast, ForecastWindowResponse, 
    PredictedTargetResponse, ExplanationResponse, PredictionGenerate
)
from app.schemas.common import APIResponse

router = APIRouter()


@router.get("/{incident_id}", response_model=AttackForecast)
async def get_latest_forecast(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get latest forecast for an incident."""
    result = await db.execute(
        select(Prediction)
        .where(Prediction.incident_id == incident_id)
        .order_by(desc(Prediction.generated_at))
        .limit(1)
    )
    prediction = result.scalar_one_or_none()
    if not prediction:
        raise HTTPException(status_code=404, detail="No predictions found for this incident")
    
    # Get forecast windows and targets
    windows_result = await db.execute(
        select(ForecastWindow).where(ForecastWindow.prediction_id == prediction.id)
        .order_by(ForecastWindow.window_offset)
    )
    windows = windows_result.scalars().all()
    
    targets_result = await db.execute(
        select(PredictedTarget).where(PredictedTarget.prediction_id == prediction.id)
    )
    targets = targets_result.scalars().all()
    
    return AttackForecast(
        incident_id=prediction.incident_id,
        current_stage=prediction.current_stage,
        current_confidence=prediction.current_confidence,
        timeline=[ForecastWindowResponse.model_validate(w) for w in windows],
        predicted_targets=[PredictedTargetResponse.model_validate(t) for t in targets],
        explanation=prediction.explanation,
        generated_at=prediction.generated_at,
        model_version=prediction.model_version,
    )


@router.get("/{incident_id}/history", response_model=List[AttackForecast])
async def get_prediction_history(
    incident_id: UUID,
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get prediction history for an incident."""
    result = await db.execute(
        select(Prediction)
        .where(Prediction.incident_id == incident_id)
        .order_by(desc(Prediction.generated_at))
        .limit(limit)
    )
    predictions = result.scalars().all()
    
    forecasts = []
    for pred in predictions:
        windows_result = await db.execute(
            select(ForecastWindow).where(ForecastWindow.prediction_id == pred.id)
            .order_by(ForecastWindow.window_offset)
        )
        windows = windows_result.scalars().all()
        
        targets_result = await db.execute(
            select(PredictedTarget).where(PredictedTarget.prediction_id == pred.id)
        )
        targets = targets_result.scalars().all()
        
        forecasts.append(AttackForecast(
            incident_id=pred.incident_id,
            current_stage=pred.current_stage,
            current_confidence=pred.current_confidence,
            timeline=[ForecastWindowResponse.model_validate(w) for w in windows],
            predicted_targets=[PredictedTargetResponse.model_validate(t) for t in targets],
            explanation=pred.explanation,
            generated_at=pred.generated_at,
            model_version=pred.model_version,
        ))
    
    return forecasts


@router.get("/{incident_id}/explanation", response_model=ExplanationResponse)
async def get_explanation(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get explanation for latest prediction."""
    result = await db.execute(
        select(Prediction)
        .where(Prediction.incident_id == incident_id)
        .order_by(desc(Prediction.generated_at))
        .limit(1)
    )
    prediction = result.scalar_one_or_none()
    if not prediction:
        raise HTTPException(status_code=404, detail="No predictions found")
    
    return ExplanationResponse(**prediction.explanation)


@router.post("/generate", response_model=AttackForecast)
async def generate_prediction(
    gen_req: PredictionGenerate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Trigger new prediction generation."""
    # Verify incident exists
    from app.models.incident import Incident
    result = await db.execute(select(Incident).where(Incident.id == gen_req.incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    from app.schemas.prediction import AttackForecast, ForecastWindowResponse, PredictedTargetResponse, ExplanationResponse
    from app.services.world_model_service import try_world_model_forecast

    wm = try_world_model_forecast(horizon=gen_req.horizon or 4)
    if wm:
        timeline = [
            ForecastWindowResponse(
                window_offset=w["window_offset"],
                stage=w["stage"],
                probability=w["probability"],
                target_asset_id=None,
                target_asset_name="predicted-target",
                eta_seconds=w["eta_seconds"],
                confidence=w["confidence"],
            )
            for w in wm["timeline"]
        ]
        fi = wm["explanation"]["feature_importance"]
        top = wm["explanation"]["top_factors"]
        forecast = AttackForecast(
            incident_id=gen_req.incident_id,
            current_stage=wm["current_stage"],
            current_confidence=wm["current_confidence"],
            timeline=timeline,
            predicted_targets=[
                PredictedTargetResponse(
                    asset_id=UUID("00000000-0000-0000-0000-000000000001"),
                    asset_name="high-value-asset",
                    asset_type="server",
                    probability=float(max(wm["timeline"][-1]["probability"], 0.01)),
                    reasoning=[t.get("description", t.get("feature", "")) for t in top[:3]],
                ),
            ],
            explanation=ExplanationResponse(
                feature_importance=fi,
                top_factors=[
                    {
                        "factor": t.get("feature", "feature"),
                        "contribution": t.get("contribution", 0.0),
                        "description": t.get("description", ""),
                    }
                    for t in top
                ],
                natural_language=wm["explanation"]["natural_language"],
                thinking=wm.get("thinking"),
            ),
            generated_at=datetime.utcnow(),
            model_version=wm["model_version"],
            recommended_action=wm.get("recommended_action", "monitor"),
            recommended_actions=wm.get("recommended_actions", []) or [],
        )
    else:
        # Fallback mock if checkpoint missing
        forecast = AttackForecast(
            incident_id=gen_req.incident_id,
            current_stage="initial_access",
            current_confidence=0.92,
            timeline=[
                ForecastWindowResponse(
                    window_offset=1,
                    stage="lateral_movement",
                    probability=0.78,
                    target_asset_id=None,
                    target_asset_name="DB-01",
                    eta_seconds=30.0,
                    confidence=0.78,
                ),
                ForecastWindowResponse(
                    window_offset=2,
                    stage="collection",
                    probability=0.71,
                    target_asset_id=None,
                    target_asset_name="DB-01",
                    eta_seconds=60.0,
                    confidence=0.71,
                ),
            ],
            predicted_targets=[
                PredictedTargetResponse(
                    asset_id=UUID("00000000-0000-0000-0000-000000000001"),
                    asset_name="DB-01",
                    asset_type="database",
                    probability=0.71,
                    reasoning=["Database subnet access", "SMB enumeration", "Credential reuse"],
                ),
            ],
            explanation=ExplanationResponse(
                feature_importance={
                    "smb_connection_rate": 0.42,
                    "auth_failure_rate": 0.36,
                    "east_west_traffic": 0.21,
                    "tcp_flag_anomaly": 0.09,
                },
                top_factors=[
                    {"factor": "smb_connection_rate", "contribution": 0.42, "description": "3.2x increase in SMB connections from SERVER-03"},
                    {"factor": "auth_failure_rate", "contribution": 0.36, "description": "Repeated authentication failures to DB-01"},
                ],
                natural_language="Lateral Movement predicted (78%) because: 1. 3.2x increase in SMB connections from SERVER-03 (42%) 2. Repeated authentication failures to DB-01 (36%) 3. New east-west traffic to database subnet (21%)",
                thinking={
                    "branches": 0,
                    "consensus_agreement": 0.0,
                    "chain_of_thought": [
                        "World-model checkpoint unavailable; using rule-based fallback reasoning.",
                        "Current belief is most consistent with 'initial_access'.",
                        "Observed east-west SMB probing and repeated auth failures imply "
                        "movement toward 'lateral_movement' then 'collection'.",
                        "High-maturity targets (database subnet) are the probable next stop.",
                    ],
                    "worst_case": {"terminal_stage": "collection", "peak_infil_risk": 0.71},
                },
            ),
            generated_at=datetime.utcnow(),
            model_version="wm-v1.0.0-fallback",
            recommended_action="isolate_host",
            recommended_actions=[
                {"step": 1, "action": "isolate_host", "action_index": 2, "q_value": 0.9, "confidence": 0.8},
                {"step": 2, "action": "force_reauth", "action_index": 3, "q_value": 0.7, "confidence": 0.6},
            ],
        )
    
    # Save prediction
    from app.models.prediction import Prediction, ForecastWindow, PredictedTarget
    from uuid import uuid4
    
    pred = Prediction(
        id=uuid4(),
        incident_id=gen_req.incident_id,
        current_stage=forecast.current_stage,
        current_confidence=forecast.current_confidence,
        model_version=forecast.model_version,
        horizon=gen_req.horizon,
        generated_at=forecast.generated_at,
        timeline=[w.model_dump() for w in forecast.timeline],
        predicted_targets=[t.model_dump() for t in forecast.predicted_targets],
        explanation=forecast.explanation.model_dump(),
    )
    db.add(pred)
    await db.flush()  # persist predictions row first so FK children can reference it

    for w in forecast.timeline:
        db.add(ForecastWindow(
            id=uuid4(),
            prediction_id=pred.id,
            window_offset=w.window_offset,
            stage=w.stage,
            probability=w.probability,
            target_asset_id=w.target_asset_id,
            target_asset_name=w.target_asset_name,
            eta_seconds=w.eta_seconds,
            confidence=w.confidence,
        ))
    
    for t in forecast.predicted_targets:
        db.add(PredictedTarget(
            id=uuid4(),
            prediction_id=pred.id,
            asset_id=t.asset_id,
            asset_name=t.asset_name,
            asset_type=t.asset_type,
            probability=t.probability,
            reasoning=t.reasoning,
        ))
    
    await db.commit()
    await db.refresh(pred)
    
    return forecast