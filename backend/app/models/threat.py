"""
Threat Actor and Attack Trajectory Models

Multi-actor tracking: an IP address is treated as an observed source, NOT a unique
attacker identity. Multiple observed sources may be correlated into one trajectory
when evidence supports it.
"""
import enum
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base
from app.models.incident import AttackStage


class ActorResponseState(str, enum.Enum):
    TRACKING = "tracking"
    MONITORING = "monitoring"
    CONTAINING = "containing"
    DECEIVING = "deceiving"
    QUARANTINED = "quarantined"
    RESOLVED = "resolved"


class ThreatActor(Base):
    """A correlated threat-actor candidate tracked across the network."""

    __tablename__ = "threat_actors"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    display_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # A-001
    incident_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    source_observations: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)
    correlated_sources: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)

    current_asset_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    current_asset_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    current_stage: Mapped[Optional[AttackStage]] = mapped_column(Enum(AttackStage), nullable=True)
    predicted_stage: Mapped[Optional[AttackStage]] = mapped_column(Enum(AttackStage), nullable=True)
    predicted_target_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    predicted_target_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    response_state: Mapped[ActorResponseState] = mapped_column(
        Enum(ActorResponseState), nullable=False, default=ActorResponseState.TRACKING
    )
    deception_state: Mapped[str] = mapped_column(String(64), nullable=False, default="none")  # none, luring, engaged

    metadata_: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="threat_actors")
    trajectories: Mapped[List["ThreatTrajectory"]] = relationship(
        "ThreatTrajectory", back_populates="actor", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_threat_actor_incident", "incident_id", "first_seen"),
    )


class ThreatTrajectory(Base):
    """One observed step along a threat-actor's journey through the network."""

    __tablename__ = "threat_trajectories"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    actor_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), index=True, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)

    observed_source: Mapped[str] = mapped_column(String(255), nullable=False)  # IP / hostname / correlation key
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    current_asset_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    current_asset_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    current_stage: Mapped[AttackStage] = mapped_column(Enum(AttackStage), nullable=False)
    predicted_stage: Mapped[Optional[AttackStage]] = mapped_column(Enum(AttackStage), nullable=True)
    predicted_target_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    predicted_target_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)

    actor: Mapped["ThreatActor"] = relationship("ThreatActor", back_populates="trajectories")

    __table_args__ = (
        Index("ix_trajectory_actor_timestamp", "actor_id", "timestamp"),
    )