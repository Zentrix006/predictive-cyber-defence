"""
Deception Models
"""
import enum
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID, ARRAY

from app.models.base import Base
from app.models.incident import IncidentSeverity


class HoneypotType(str, enum.Enum):
    WEB = "web"
    SSH = "ssh"
    DATABASE = "database"
    SMB = "smb"
    FTP = "ftp"
    IOT = "iot"
    CUSTOM = "custom"


class DeploymentStatus(str, enum.Enum):
    PENDING = "pending"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    TEARING_DOWN = "tearing_down"
    COMPLETED = "completed"
    FAILED = "failed"


class HoneypotStatus(str, enum.Enum):
    DORMANT = "dormant"
    ACTIVATING = "activating"
    ACTIVE = "active"
    COMPROMISED = "compromised"
    COLLECTING = "collecting"
    RESETTING = "resetting"
    OFFLINE = "offline"


class HoneypotTemplate(Base):
    __tablename__ = "honeypot_templates"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    honeypot_type: Mapped[HoneypotType] = mapped_column(Enum(HoneypotType), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    docker_image: Mapped[str] = mapped_column(String(512), nullable=False)
    ports: Mapped[List[int]] = mapped_column(ARRAY(Integer), nullable=False, default=list)
    environment: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    volumes: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    resource_limits: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    decoy_files: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    credentials: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class DeceptionDeployment(Base):
    __tablename__ = "deception_deployments"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    honeypot_types: Mapped[List[HoneypotType]] = mapped_column(ARRAY(Enum(HoneypotType)), nullable=False, default=list)
    target_assets: Mapped[List[UUID]] = mapped_column(ARRAY(PGUUID(as_uuid=True)), nullable=False, default=list)
    predicted_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[DeploymentStatus] = mapped_column(Enum(DeploymentStatus), nullable=False, default=DeploymentStatus.PENDING, index=True)
    container_ids: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    network_config: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    torn_down_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    interactions_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="deception_deployments")
    interactions: Mapped[List["HoneypotInteraction"]] = relationship("HoneypotInteraction", back_populates="deployment", cascade="all, delete-orphan")


class HoneypotInstance(Base):
    """Pre-staged deception inventory asset (the honeypot pool)."""

    __tablename__ = "honeypot_instances"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    honeypot_type: Mapped[HoneypotType] = mapped_column(Enum(HoneypotType), nullable=False)
    os: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[HoneypotStatus] = mapped_column(Enum(HoneypotStatus), nullable=False, default=HoneypotStatus.DORMANT, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    location: Mapped[str] = mapped_column(String(64), nullable=False, default="honeynet")
    ports: Mapped[List[int]] = mapped_column(ARRAY(Integer), nullable=False, default=list)
    services: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    telemetry_sources: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    risk_profile: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    metadata_: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    deployment_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class HoneypotInteraction(Base):
    __tablename__ = "honeypot_interactions"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    deployment_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("deception_deployments.id", ondelete="CASCADE"), nullable=False, index=True)
    honeypot_type: Mapped[HoneypotType] = mapped_column(Enum(HoneypotType), nullable=False)
    container_id: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # connection, auth_attempt, command, file_access
    details: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), nullable=False, default=IncidentSeverity.LOW)
    mitre_techniques: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    
    # Relationships
    deployment: Mapped["DeceptionDeployment"] = relationship("DeceptionDeployment", back_populates="interactions")
    
    __table_args__ = (
        Index("ix_interaction_deployment_timestamp", "deployment_id", "timestamp"),
        Index("ix_interaction_source_ip", "source_ip"),
    )