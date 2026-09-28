"""
Forensics Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

from app.models.forensics import EvidenceType, FileEventAction


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    evidence_type: EvidenceType
    name: str
    description: Optional[str] = None
    source_asset_id: Optional[UUID] = None
    size_bytes: int
    sha256_hash: str
    collection_method: str
    collected_at: datetime = Field(validation_alias="created_at")


class PCAPFileResponse(EvidenceResponse):
    packet_count: int
    start_time: datetime
    end_time: datetime
    filters_applied: List[str] = []


class LogFileResponse(EvidenceResponse):
    log_source: str
    log_format: str
    line_count: int
    time_range_start: datetime
    time_range_end: datetime


class FileEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    incident_id: UUID
    asset_id: UUID
    file_path: str
    file_hash: Optional[str] = None
    action: FileEventAction
    timestamp: datetime
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    user: Optional[str] = None
    metadata: Dict = Field(default_factory=dict, validation_alias="metadata_")
    was_read: bool
    was_modified: bool
    was_copied: bool
    was_deleted: bool
    was_exfiltrated: bool
    exfiltration_destination: Optional[str] = None


class EvidenceIndex(BaseModel):
    incident_id: UUID
    evidence: List[EvidenceResponse]
    counts: Dict[str, int]


class PaginatedEvidence(BaseModel):
    items: List[EvidenceResponse]
    total: int
    page: int
    page_size: int
    total_pages: int