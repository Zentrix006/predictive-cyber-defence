"""
Incident Schemas
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.incident import IncidentStatus, IncidentSeverity, AttackStage


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    incident_id: UUID
    timestamp: datetime
    event_type: str
    title: str
    description: Optional[str] = None
    severity: IncidentSeverity
    source: str
    asset_ids: List[UUID] = []
    metadata: dict = {}
    prediction_id: Optional[UUID] = None


class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: IncidentSeverity
    source: str = "auto"
    source_reference: Optional[str] = None
    tags: List[str] = []


class IncidentCreate(IncidentBase):
    detected_at: datetime = datetime.utcnow()
    assets_involved: List[UUID] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[UUID] = None
    current_stage: Optional[AttackStage] = None
    threat_score: Optional[float] = None
    tags: Optional[List[str]] = None


class IncidentClose(BaseModel):
    reason: str


class IncidentResponse(IncidentBase):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    status: IncidentStatus
    detected_at: datetime
    assigned_to: Optional[UUID] = None
    current_stage: Optional[AttackStage] = None
    threat_score: float
    closed_at: Optional[datetime] = None
    closure_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PaginatedIncidents(BaseModel):
    items: List[IncidentResponse]
    total: int
    page: int
    page_size: int
    total_pages: int