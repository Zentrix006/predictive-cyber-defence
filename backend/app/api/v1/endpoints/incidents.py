"""
Incidents API Endpoints
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user
from app.models.incident import Incident, IncidentStatus, IncidentSeverity, TimelineEvent
from app.models.asset import Asset
from app.schemas.incident import (
    IncidentResponse, IncidentCreate, IncidentUpdate, IncidentClose,
    TimelineEventResponse, PaginatedIncidents
)
from app.schemas.common import APIResponse

router = APIRouter()


@router.get("", response_model=PaginatedIncidents)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[List[IncidentStatus]] = Query(None),
    severity: Optional[List[IncidentSeverity]] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    assigned_to: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List incidents with filtering and pagination."""
    query = select(Incident)
    
    if status:
        query = query.where(Incident.status.in_(status))
    if severity:
        query = query.where(Incident.severity.in_(severity))
    if date_from:
        query = query.where(Incident.detected_at >= date_from)
    if date_to:
        query = query.where(Incident.detected_at <= date_to)
    if assigned_to:
        query = query.where(Incident.assigned_to == assigned_to)
    if search:
        query = query.where(
            or_(
                Incident.title.ilike(f"%{search}%"),
                Incident.description.ilike(f"%{search}%"),
            )
        )
    
    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)
    
    # Paginate - newest first
    query = query.order_by(desc(Incident.detected_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    return PaginatedIncidents(
        items=[IncidentResponse.model_validate(i) for i in incidents],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_in: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new incident."""
    data = incident_in.model_dump()
    assets_involved = data.pop("assets_involved", [])
    incident = Incident(
        **data,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    
    # Create initial timeline event
    event = TimelineEvent(
        incident_id=incident.id,
        timestamp=datetime.utcnow(),
        event_type="incident_created",
        title="Incident created",
        description=incident.description or "New incident created",
        severity=incident.severity,
        source="api",
        asset_ids=assets_involved,
    )
    db.add(event)
    await db.commit()
    
    return IncidentResponse.model_validate(incident)


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get incident details."""
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id).options(
            selectinload(Incident.assets),
            selectinload(Incident.predictions),
            selectinload(Incident.deception_deployments),
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentResponse.model_validate(incident)


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: UUID,
    incident_upd: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    update_data = incident_upd.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)
    incident.updated_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(incident)
    
    return IncidentResponse.model_validate(incident)


@router.post("/{incident_id}/close", response_model=APIResponse)
async def close_incident(
    incident_id: UUID,
    close_data: IncidentClose,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Close an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident.status = IncidentStatus.CLOSED
    incident.closed_at = datetime.utcnow()
    incident.closure_reason = close_data.reason
    incident.updated_at = datetime.utcnow()
    
    # Create closing timeline event
    event = TimelineEvent(
        incident_id=incident.id,
        timestamp=datetime.utcnow(),
        event_type="incident_closed",
        title="Incident closed",
        description=close_data.reason,
        severity=incident.severity,
        source="api",
    )
    db.add(event)
    
    await db.commit()
    
    return APIResponse(
        success=True,
        message="Incident closed",
        data={"incident_id": str(incident_id), "closed_at": incident.closed_at.isoformat()}
    )


@router.get("/{incident_id}/timeline", response_model=List[TimelineEventResponse])
async def get_incident_timeline(
    incident_id: UUID,
    event_types: Optional[List[str]] = Query(None),
    severity: Optional[List[IncidentSeverity]] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get incident timeline."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    query = select(TimelineEvent).where(TimelineEvent.incident_id == incident_id)
    
    if event_types:
        query = query.where(TimelineEvent.event_type.in_(event_types))
    if severity:
        query = query.where(TimelineEvent.severity.in_(severity))
    
    query = query.order_by(TimelineEvent.timestamp)
    result = await db.execute(query)
    events = result.scalars().all()
    
    return [TimelineEventResponse.model_validate(e) for e in events]