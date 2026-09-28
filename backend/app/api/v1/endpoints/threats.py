"""
Threat Actor API — multi-trajectory tracking + attack-path convergence.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.threat import ThreatActor, ThreatTrajectory, ActorResponseState
from app.models.asset import Asset
from app.schemas.threat import (
    ThreatActorResponse,
    ThreatActorCreate,
    ThreatTrajectoryResponse,
    TrajectoryCreate,
    ConvergenceReport,
    ConvergingPath,
)
from app.services.risk_engine import compute_risk
from app.services.audit_service import log_audit

router = APIRouter()


def _next_display_id(existing: List[str]) -> str:
    n = len(existing) + 1
    while f"A-{n:03d}" in existing:
        n += 1
    return f"A-{n:03d}"


@router.get("", response_model=List[ThreatActorResponse])
async def list_threat_actors(
    incident_id: Optional[UUID] = Query(None),
    active_only: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(ThreatActor)
    if incident_id:
        query = query.where(ThreatActor.incident_id == incident_id)
    if active_only:
        query = query.where(ThreatActor.response_state.in_(
            [ActorResponseState.TRACKING, ActorResponseState.MONITORING,
             ActorResponseState.CONTAINING, ActorResponseState.DECEIVING]
        ))
    query = query.order_by(desc(ThreatActor.risk_score))
    rows = (await db.execute(query)).scalars().all()
    return [ThreatActorResponse.model_validate(r) for r in rows]


@router.post("", response_model=ThreatActorResponse, status_code=201)
async def create_threat_actor(
    body: ThreatActorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    existing = (await db.execute(select(ThreatActor.display_id))).scalars().all()
    actor = ThreatActor(
        display_id=body.display_id or _next_display_id(list(existing)),
        incident_id=body.incident_id,
        source_observations=[{"source": body.observed_source}],
        correlated_sources=[body.observed_source],
        current_asset_id=body.current_asset_id,
        current_asset_name=body.current_asset_name,
        current_stage=body.current_stage,
        confidence=body.confidence,
        risk_score=body.risk_score,
    )
    if body.current_asset_id:
        try:
            asset = await db.get(Asset, body.current_asset_id)
            if asset:
                actor.current_asset_name = actor.current_asset_name or asset.hostname
        except Exception:
            pass
    db.add(actor)
    await db.flush()
    db.add(ThreatTrajectory(
        actor_id=actor.id,
        incident_id=body.incident_id,
        observed_source=body.observed_source,
        src_ip=body.src_ip,
        current_asset_id=body.current_asset_id,
        current_asset_name=actor.current_asset_name,
        current_stage=body.current_stage,
        confidence=body.confidence,
        risk_score=body.risk_score,
        evidence=[{"type": "registration"}],
    ))
    await log_audit(db, actor=current_user.get("sub", "dev-user"), action="THREAT_TRACKING",
                    target_type="threat_actor", target_id=actor.id,
                    summary=f"Registered threat actor {actor.display_id} ({body.observed_source})")
    await db.commit()
    await db.refresh(actor)
    return ThreatActorResponse.model_validate(actor)


@router.get("/{actor_id}", response_model=ThreatActorResponse)
async def get_threat_actor(
    actor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    actor = await db.get(ThreatActor, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return ThreatActorResponse.model_validate(actor)


@router.post("/trajectories", response_model=ThreatTrajectoryResponse, status_code=201)
async def add_trajectory(
    body: TrajectoryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    actor = await db.get(ThreatActor, body.actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    step = ThreatTrajectory(**body.model_dump())
    db.add(step)
    await db.flush()
    # advance actor state
    actor.last_seen = datetime.utcnow()
    if body.current_asset_name:
        actor.current_asset_name = body.current_asset_name
    if body.current_stage:
        actor.current_stage = body.current_stage
    if body.predicted_stage:
        actor.predicted_stage = body.predicted_stage
    if body.predicted_target_name:
        actor.predicted_target_name = body.predicted_target_name
    if body.predicted_target_id:
        actor.predicted_target_id = body.predicted_target_id
    actor.confidence = body.confidence
    actor.risk_score = body.risk_score
    if body.observed_source not in actor.correlated_sources:
        actor.correlated_sources.append(body.observed_source)
    actor.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(step)
    return ThreatTrajectoryResponse.model_validate(step)


@router.get("/{actor_id}/trajectory", response_model=List[ThreatTrajectoryResponse])
async def get_actor_trajectory(
    actor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    rows = (await db.execute(
        select(ThreatTrajectory).where(ThreatTrajectory.actor_id == actor_id).order_by(ThreatTrajectory.timestamp)
    )).scalars().all()
    return [ThreatTrajectoryResponse.model_validate(r) for r in rows]


@router.get("/convergence/report", response_model=ConvergenceReport)
async def convergence_report(
    incident_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Detect multiple trajectories converging on the same asset."""
    query = select(ThreatActor)
    if incident_id:
        query = query.where(ThreatActor.incident_id == incident_id)
    actors = (await db.execute(query)).scalars().all()

    by_target: dict = {}
    for a in actors:
        key = str(a.predicted_target_id) if a.predicted_target_id else (a.predicted_target_name or "unknown")
        if key == "unknown":
            continue
        entry = by_target.setdefault(key, {"actors": [], "stages": [], "asset_id": a.predicted_target_id,
                                           "asset_name": a.predicted_target_name or key, "asset_type": "unknown"})
        entry["actors"].append(a.display_id)
        entry["stages"].append(a.predicted_stage.value if hasattr(a.predicted_stage, "value") else str(a.predicted_stage))

    paths: List[ConvergingPath] = []
    for key, entry in by_target.items():
        asset_id = entry["asset_id"]
        if asset_id:
            asset = await db.get(Asset, asset_id)
            if asset:
                entry["asset_type"] = asset.asset_type.value if hasattr(asset.asset_type, "value") else "unknown"
        actor_count = len(entry["actors"])
        risk = compute_risk(
            threat_probability=min(1.0, 0.4 + 0.1 * actor_count),
            confidence=0.8,
            asset_criticality="critical" if entry["asset_type"] == "database" else "high",
            converging_paths=actor_count,
        )
        paths.append(ConvergingPath(
            asset_id=entry["asset_id"] or UUID(int=0),
            asset_name=entry["asset_name"],
            asset_type=entry["asset_type"],
            actor_count=actor_count,
            actors=entry["actors"],
            combined_risk=risk["risk_score"],
            risk_level=risk["risk_level"],
            stages=entry["stages"],
        ))
    paths.sort(key=lambda p: p.combined_risk, reverse=True)
    message = ""
    if paths:
        top = paths[0]
        message = f"{top.actor_count} threat trajectories converging on {top.asset_name} (combined risk {top.combined_risk})."
    return ConvergenceReport(converging_paths=paths, message=message, timestamp=datetime.utcnow())