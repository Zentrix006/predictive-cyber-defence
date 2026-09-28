"""
Config Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ConfigSnapshotCreate(BaseModel):
    incident_id: UUID
    label: str
    description: str
    snapshot_type: str  # pre_incident, containment, deception, post_incident
    configuration: Dict


class ConfigSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    incident_id: UUID
    label: str
    description: str
    snapshot_type: str
    configuration: Dict
    sha256_hash: str
    created_by: Optional[UUID] = None
    created_at: datetime
    applied_at: Optional[datetime] = None


class ConfigSnapshotApply(BaseModel):
    pass


class ConfigDiffResponse(BaseModel):
    from_snapshot_id: UUID
    to_snapshot_id: UUID
    added: Dict
    removed: Dict
    modified: Dict