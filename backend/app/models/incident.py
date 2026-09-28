"""
Incident Models
"""
import enum
from datetime import datetime
from typing import Optional, List
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Integer, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"


class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackStage(str, enum.Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


class Incident(Base):
    __tablename__ = "incidents"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), nullable=False, default=IncidentSeverity.MEDIUM, index=True)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), nullable=False, default=IncidentStatus.OPEN, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="auto")  # auto, manual, alert
    source_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    assigned_to: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    current_stage: Mapped[Optional[AttackStage]] = mapped_column(Enum(AttackStage), nullable=True)
    threat_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    closure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    metadata_: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assets: Mapped[List["Asset"]] = relationship("Asset", back_populates="incident")
    timeline_events: Mapped[List["TimelineEvent"]] = relationship("TimelineEvent", back_populates="incident", cascade="all, delete-orphan")
    predictions: Mapped[List["Prediction"]] = relationship("Prediction", back_populates="incident", cascade="all, delete-orphan")
    deception_deployments: Mapped[List["DeceptionDeployment"]] = relationship("DeceptionDeployment", back_populates="incident", cascade="all, delete-orphan")
    evidence: Mapped[List["Evidence"]] = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    config_snapshots: Mapped[List["ConfigSnapshot"]] = relationship("ConfigSnapshot", back_populates="incident", cascade="all, delete-orphan")
    threat_actors: Mapped[List["ThreatActor"]] = relationship("ThreatActor", back_populates="incident", cascade="all, delete-orphan")
    response_actions: Mapped[List["ResponseAction"]] = relationship("ResponseAction", back_populates="incident", cascade="all, delete-orphan")
    policy_decisions: Mapped[List["PolicyDecision"]] = relationship("PolicyDecision", back_populates="incident", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
    )


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), nullable=False, default=IncidentSeverity.MEDIUM)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_ids: Mapped[List[UUID]] = mapped_column(ARRAY(PGUUID(as_uuid=True)), nullable=False, default=list)
    metadata_: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    prediction_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    
    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline_events")
    
    __table_args__ = (
        Index("ix_timeline_incident_timestamp", "incident_id", "timestamp"),
    )