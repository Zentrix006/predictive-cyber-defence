"""
Forensics API Endpoints
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user
from app.models.forensics import (
    Evidence, FileEvent, PCAPFile, LogFile, EvidenceType
)
from app.models.incident import Incident
from app.schemas.forensics import (
    EvidenceResponse, PCAPFileResponse, LogFileResponse,
    FileEventResponse, EvidenceIndex, PaginatedEvidence
)
from app.schemas.common import APIResponse

router = APIRouter()


@router.get("/incidents/{incident_id}/evidence", response_model=EvidenceIndex)
async def get_evidence_index(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get evidence index for an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Count by type
    counts = {}
    for etype in EvidenceType:
        count = await db.scalar(
            select(func.count(Evidence.id)).where(
                Evidence.incident_id == incident_id,
                Evidence.evidence_type == etype
            )
        )
        counts[etype.value] = count or 0
    
    # Get recent evidence
    result = await db.execute(
        select(Evidence)
        .where(Evidence.incident_id == incident_id)
        .order_by(desc(Evidence.created_at))
        .limit(20)
    )
    evidence = result.scalars().all()
    
    return EvidenceIndex(
        incident_id=incident_id,
        evidence=[EvidenceResponse.model_validate(e) for e in evidence],
        counts=counts,
    )


@router.get("/incidents/{incident_id}/pcap", response_model=List[PCAPFileResponse])
async def list_pcap_files(
    incident_id: UUID,
    asset_id: Optional[UUID] = Query(None),
    time_range_start: Optional[datetime] = Query(None),
    time_range_end: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List PCAP files for an incident."""
    query = select(PCAPFile).where(PCAPFile.incident_id == incident_id)
    
    if asset_id:
        query = query.where(PCAPFile.source_asset_id == asset_id)
    if time_range_start:
        query = query.where(PCAPFile.start_time >= time_range_start)
    if time_range_end:
        query = query.where(PCAPFile.end_time <= time_range_end)
    
    query = query.order_by(desc(PCAPFile.start_time))
    result = await db.execute(query)
    files = result.scalars().all()
    return [PCAPFileResponse.model_validate(f) for f in files]


@router.get("/incidents/{incident_id}/logs", response_model=List[LogFileResponse])
async def list_log_files(
    incident_id: UUID,
    source: Optional[str] = Query(None),
    time_range_start: Optional[datetime] = Query(None),
    time_range_end: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List log files for an incident."""
    query = select(LogFile).where(LogFile.incident_id == incident_id)
    
    if source:
        query = query.where(LogFile.log_source == source)
    if time_range_start:
        query = query.where(LogFile.time_range_start >= time_range_start)
    if time_range_end:
        query = query.where(LogFile.time_range_end <= time_range_end)
    
    query = query.order_by(desc(LogFile.time_range_start))
    result = await db.execute(query)
    files = result.scalars().all()
    return [LogFileResponse.model_validate(f) for f in files]


@router.get("/incidents/{incident_id}/files", response_model=List[FileEventResponse])
async def list_file_events(
    incident_id: UUID,
    asset_id: Optional[UUID] = Query(None),
    action: Optional[str] = Query(None),
    time_range_start: Optional[datetime] = Query(None),
    time_range_end: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List file events for an incident."""
    from app.models.forensics import FileEvent, FileEventAction
    
    query = select(FileEvent).where(FileEvent.incident_id == incident_id)
    
    if asset_id:
        query = query.where(FileEvent.asset_id == asset_id)
    if action:
        query = query.where(FileEvent.action == FileEventAction(action))
    if time_range_start:
        query = query.where(FileEvent.timestamp >= time_range_start)
    if time_range_end:
        query = query.where(FileEvent.timestamp <= time_range_end)
    
    query = query.order_by(desc(FileEvent.timestamp))
    
    # Pagination
    count = await db.scalar(select(func.count()).select_from(query.subquery()))
    query = query.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(query)
    events = result.scalars().all()
    
    return [FileEventResponse.model_validate(e) for e in events]


@router.get("/incidents/{incident_id}/timeline")
async def get_full_timeline(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get correlated timeline for an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Get all timeline events
    from app.models.incident import TimelineEvent
    from app.models.forensics import FileEvent
    from app.models.deception import HoneypotInteraction
    
    timeline_events = await db.execute(
        select(TimelineEvent).where(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.timestamp)
    )
    
    file_events = await db.execute(
        select(FileEvent).where(FileEvent.incident_id == incident_id)
        .order_by(FileEvent.timestamp)
    )
    
    honeypot_interactions = await db.execute(
        select(HoneypotInteraction)
        .join(HoneypotInteraction.deployment)
        .where(HoneypotInteraction.deployment.has(incident_id=incident_id))
        .order_by(HoneypotInteraction.timestamp)
    )
    
    # Merge and sort all events
    all_events = []
    
    for e in timeline_events.scalars():
        all_events.append({
            "timestamp": e.timestamp.isoformat(),
            "type": "timeline",
            "event_type": e.event_type,
            "title": e.title,
            "description": e.description,
            "severity": e.severity.value,
            "source": e.source,
            "asset_ids": [str(a) for a in e.asset_ids],
            "metadata": e.metadata_,
        })
    
    for e in file_events.scalars():
        all_events.append({
            "timestamp": e.timestamp.isoformat(),
            "type": "file_event",
            "action": e.action.value,
            "file_path": e.file_path,
            "asset_id": str(e.asset_id),
            "process": e.process_name,
            "user": e.user,
        })
    
    for e in honeypot_interactions.scalars():
        all_events.append({
            "timestamp": e.timestamp.isoformat(),
            "type": "honeypot_interaction",
            "honeypot_type": e.honeypot_type.value,
            "action": e.action,
            "source_ip": e.source_ip,
            "details": e.details,
            "severity": e.severity.value,
            "mitre_techniques": e.mitre_techniques,
        })
    
    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"])
    
    return {"incident_id": str(incident_id), "events": all_events}