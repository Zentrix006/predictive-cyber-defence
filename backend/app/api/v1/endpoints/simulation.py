"""
Simulation API — controlled security-exercise environment.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.services.simulation_service import (
    SIMULATION_STATE,
    start_simulation,
    stop_simulation,
)

router = APIRouter()


class SimulationResp(dict):
    pass


@router.get("/status")
async def simulation_status(db: AsyncSession = Depends(get_db), current_user: dict = Depends(get_current_user)):
    from app.services.simulation_service import find_simulation_incident
    state = dict(SIMULATION_STATE)
    if not state.get("active"):
        existing = await find_simulation_incident(db)
        if existing:
            state["active"] = True
            state["incident_id"] = existing.id
            state["scenario"] = "multi-actor-intrusion"
            state["started_at"] = existing.created_at.isoformat()
    return SimulationResp(
        active=state.get("active", False),
        scenario=state.get("scenario"),
        incident_id=str(state["incident_id"]) if state.get("incident_id") else None,
        started_at=state.get("started_at"),
        marker=state.get("marker"),
    )


@router.post("/start", status_code=201)
async def start(db: AsyncSession = Depends(get_db), current_user: dict = Depends(get_current_user)):
    state = await simulation_status(db=db, current_user=current_user)
    if state["active"]:
        return state
    try:
        state = await start_simulation(db)
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return SimulationResp(**state, marker=SIMULATION_STATE.get("marker"))


@router.post("/stop")
async def stop(db: AsyncSession = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return await stop_simulation(db)