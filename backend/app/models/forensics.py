"""
Forensics Models
"""
import enum
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Integer, BigInteger
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID, ARRAY

from app.models.base import Base
from app.models.incident import IncidentSeverity


class EvidenceType(str, enum.Enum):
    PCAP = "pcap"
    LOG = "log"
    FILE_EVENT = "file_event"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    CONFIG_SNAPSHOT = "config_snapshot"
    NETWORK_FLOW = "network_flow"
    HONEYPOT_INTERACTION = "honeypot_interaction"


class Evidence(Base):
    __tablename__ = "evidence"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type: Mapped[EvidenceType] = mapped_column(Enum(EvidenceType), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_asset_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    collection_method: Mapped[str] = mapped_column(String(128), nullable=False)
    collected_by: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    is_verified: Mapped[bool] = mapped_column(nullable=False, default=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    metadata_: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    
    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="evidence")
    custody_events: Mapped[List["EvidenceCustodyEvent"]] = relationship(
        "EvidenceCustodyEvent", back_populates="evidence", cascade="all, delete-orphan", order_by="EvidenceCustodyEvent.timestamp"
    )


class FileEventAction(str, enum.Enum):
    DISCOVERED = "discovered"
    READ = "read"
    MODIFIED = "modified"
    COPIED = "copied"
    DELETED = "deleted"
    EXFILTRATED = "exfiltrated"
    ENCRYPTED = "encrypted"


class FileEvent(Base):
    __tablename__ = "file_events"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    action: Mapped[FileEventAction] = mapped_column(Enum(FileEventAction), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    metadata_: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Tracking fields
    was_read: Mapped[bool] = mapped_column(nullable=False, default=False)
    was_modified: Mapped[bool] = mapped_column(nullable=False, default=False)
    was_copied: Mapped[bool] = mapped_column(nullable=False, default=False)
    was_deleted: Mapped[bool] = mapped_column(nullable=False, default=False)
    was_exfiltrated: Mapped[bool] = mapped_column(nullable=False, default=False)
    exfiltration_destination: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    
    __table_args__ = (
        Index("ix_file_event_incident_timestamp", "incident_id", "timestamp"),
        Index("ix_file_event_asset_path", "asset_id", "file_path"),
    )


class PCAPFile(Evidence):
    __tablename__ = "pcap_files"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    filters_applied: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)


class LogFile(Evidence):
    __tablename__ = "log_files"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True)
    log_source: Mapped[str] = mapped_column(String(128), nullable=False)
    log_format: Mapped[str] = mapped_column(String(64), nullable=False)
    line_count: Mapped[int] = mapped_column(Integer, nullable=False)
    time_range_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    time_range_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceCustodyEvent(Base):
    """Chain-of-custody step for a piece of evidence (immutable-style audit trail)."""

    __tablename__ = "evidence_custody"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    evidence_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    event: Mapped[str] = mapped_column(String(256), nullable=False)  # collected, sealed, verified, transferred, accessed, exported
    custodian: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    new_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    details: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)

    evidence: Mapped["Evidence"] = relationship("Evidence", back_populates="custody_events")