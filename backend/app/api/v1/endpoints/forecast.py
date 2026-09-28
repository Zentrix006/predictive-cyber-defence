"""
Forecast Engine API — K-step forecast + belief-state reasoning for an incident.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.incident import Incident
from app.schemas.forecast import ForecastDetail, BeliefSummary
from app.services.forecast_service import build_forecast_detail
from app.services.audit_service import log_audit
import asyncio

router = APIRouter()


async def _ml_forecast(horizon: int) -> Optional[dict]:
    try:
        from app.services.world_model_service import try_world_model_forecast
        return try_world_model_forecast(horizon=horizon)
    except Exception:
        return None


@router.get("/{incident_id}", response_model=ForecastDetail)
async def get_forecast(
    incident_id: UUID,
    horizon: int = Query(4, ge=1, le=8),
    fresh: bool = Query(False, description="Re-run the world model instead of using cached prediction"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    ml = None
    if fresh:
        ml = await _ml_forecast(horizon)
    else:
        # stitch the latest stored prediction into the detail
        from sqlalchemy import select
        from app.models.prediction import Prediction
        latest = (await db.execute(
            select(Prediction).where(Prediction.incident_id == incident_id).order_by(Prediction.generated_at.desc()).limit(1)
        )).scalar_one_or_none()
        if latest:
            ml = {
                "current_stage": latest.current_stage.value if hasattr(latest.current_stage, "value") else str(latest.current_stage),
                "current_confidence": latest.current_confidence,
                "timeline": latest.timeline or [],
                "explanation": latest.explanation or {},
                "thinking": None,
                "recommended_action": "monitor",
                "recommended_actions": [],
                "model_version": latest.model_version,
            }
        else:
            ml = await _ml_forecast(horizon)

    try:
        detail = await build_forecast_detail(db, incident_id, horizon=horizon, ml=ml)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    await log_audit(db, actor=current_user.get("sub", "dev-user"), action="PREDICTION",
                    target_type="incident", target_id=incident_id,
                    summary=f"Forecast generated (horizon={horizon}) for incident",
                    details={"model_version": detail.model_version, "current_stage": detail.current_stage})
    await db.commit()
    return detail


@router.get("/{incident_id}/belief", response_model=BeliefSummary)
async def get_belief(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    ml = await _ml_forecast(4)
    if not ml:
        raise HTTPException(status_code=503, detail="World model unavailable")
    detail = await build_forecast_detail(db, incident_id, horizon=4, ml=ml)
    if not detail.belief:
        raise HTTPException(status_code=422, detail="No belief branches available for this incident")
    return detail.belief