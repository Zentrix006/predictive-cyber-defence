"""
Demo database — schema-separated state on the same Postgres server as the
research system. All demo tables live in the `demo` schema and never touch
research data or models.
"""
import enum
from datetime import datetime
from typing import Optional, Dict, List
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.core.database import Base


def _values(e):
    """Persist lowercase enum .value (not the python member NAME) to Postgres."""
    return [m.value for m in e]


class AssetStatus(str, enum.Enum):
    HEALTHY = "healthy"
    REGISTERING = "registering"
    SUSPICIOUS = "suspicious"
    UNDER_ATTACK = "under_attack"
    COMPROMISED = "compromised"
    CONTAINED = "contained"
    DECOY = "deception"
    OFFLINE = "offline"


class AssetRole(str, enum.Enum):
    SERVER = "server"
    HOST = "host"
    CLIENT = "client"
    OTHER = "other"
    DECOY = "decoy"
    INFRA = "infrastructure"
    DATABASE = "database"
    WEB = "web"


class ParticipantRole(str, enum.Enum):
    ATTACKER = "attacker"
    SERVER = "server"
    HOST = "host"
    CLIENT = "client"
    OTHER = "other"
    OBSERVER = "observer"


class IncidentStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    CONTAINED = "contained"
    DECEPTION = "deception"
    RESOLVED = "resolved"


class DemoAsset(Base):
    __tablename__ = "demo_assets"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[AssetRole] = mapped_column(Enum(AssetRole, values_callable=_values, name="demo_asset_role", schema="demo"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), default="server")
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    zone: Mapped[str] = mapped_column(String(64), default="lan")
    status: Mapped[AssetStatus] = mapped_column(Enum(AssetStatus, values_callable=_values, name="demo_asset_status", schema="demo"), default=AssetStatus.HEALTHY)
    criticality: Mapped[str] = mapped_column(String(16), default="high")
    service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    is_physical: Mapped[bool] = mapped_column(Boolean, default=False)
    registered: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    page_endpoint: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    meta: Mapped[Dict] = mapped_column(JSONB, default=dict)


class Participant(Base):
    __tablename__ = "demo_participants"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    participant_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    role: Mapped[ParticipantRole] = mapped_column(Enum(ParticipantRole, values_callable=_values, name="demo_participant_role", schema="demo"), nullable=False)
    device_context: Mapped[Dict] = mapped_column(JSONB, default=dict)
    token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class DemoIncident(Base):
    __tablename__ = "demo_incidents"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    scenario: Mapped[str] = mapped_column(String(64), default="basic")
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus, values_callable=_values, name="demo_incident_status", schema="demo"), default=IncidentStatus.ACTIVE)
    stage: Mapped[str] = mapped_column(String(64), default="reconnaissance")
    simulation_level: Mapped[int] = mapped_column(Integer, default=1)
    origin_asset_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    predicted_target_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    predicted_target_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    contained_asset_ids: Mapped[List[str]] = mapped_column(JSONB, default=list)
    deception_activated: Mapped[bool] = mapped_column(Boolean, default=False)
    decoy_asset_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    attacker: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    meta: Mapped[Dict] = mapped_column(JSONB, default=dict)


class Challenge(Base):
    __tablename__ = "demo_challenges"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer_schema: Mapped[Dict] = mapped_column(JSONB, default=dict)
    provided_answer: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    result_level: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class DemoEvent(Base):
    __tablename__ = "demo_events"
    __table_args__ = (
        Index("ix_demo_events_ts", "timestamp"),
        {"schema": "demo"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    event_id: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    incident_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    simulation: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(32), default="system")
    payload: Mapped[Dict] = mapped_column(JSONB, default=dict)


class PredictionRecord(Base):
    __tablename__ = "demo_predictions"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    model_version: Mapped[str] = mapped_column(String(64), default="flow-wm-v3.0.0")
    horizon: Mapped[int] = mapped_column(Integer, default=4)
    current_stage: Mapped[str] = mapped_column(String(64))
    predicted_stages: Mapped[List[str]] = mapped_column(JSONB, default=list)
    predicted_target: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    predicted_target_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    lead_time_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    belief: Mapped[Dict] = mapped_column(JSONB, nullable=True)
    explanation: Mapped[Dict] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class DecoyInteraction(Base):
    __tablename__ = "demo_decoy_interactions"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    session_ref: Mapped[str] = mapped_column(String(32), nullable=False)
    decoy_asset_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_context: Mapped[Dict] = mapped_column(JSONB, default=dict)
    events: Mapped[List[Dict]] = mapped_column(JSONB, default=list)
    answers: Mapped[List[Dict]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class EvidenceRecord(Base):
    __tablename__ = "demo_evidence"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    evidence_id: Mapped[str] = mapped_column(String(32), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="system")
    payload: Mapped[Dict] = mapped_column(JSONB, default=dict)
    simulation: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class ThreatActor(Base):
    """Per-adversary snapshot (multi-actor tracking).

    Actor identity derives from the participant that started an incident
    (incident.attacker -> threat "actor"). The snapshot is refreshed on every
    stage progression; the trajectory itself is derived from incident rows /
    prediction records on read.
    """
    __tablename__ = "threat_actors"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    actor_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    source_ips: Mapped[List[str]] = mapped_column(JSONB, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="active")
    current_asset: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    current_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    predicted_target: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    predicted_target_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    meta: Mapped[Dict] = mapped_column(JSONB, default=dict)


class ThreatTrajectory(Base):
    """Light snapshot of an actor's path (derived trace lives in the API)."""
    __tablename__ = "threat_trajectories"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    trajectory_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    asset_sequence: Mapped[List[str]] = mapped_column(JSONB, default=list)
    stage_sequence: Mapped[List[str]] = mapped_column(JSONB, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ActorCorrelation(Base):
    """Records when distinct actor sessions are linked (e.g. convergence)."""
    __tablename__ = "actor_correlations"
    __table_args__ = {"schema": "demo"}

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    correlation_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    actor_ids: Mapped[List[str]] = mapped_column(JSONB, default=list)
    incident_ids: Mapped[List[str]] = mapped_column(JSONB, default=list)
    method: Mapped[str] = mapped_column(String(64), default="convergence")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    target: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    events: Mapped[List[Dict]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)