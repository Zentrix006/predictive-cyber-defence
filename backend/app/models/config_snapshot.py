"""
Config Snapshot Models
"""
from datetime import datetime
from typing import Optional, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, ForeignKey, Index, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base


class ConfigSnapshot(Base):
    __tablename__ = "config_snapshots"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    snapshot_type: Mapped[str] = mapped_column(String(64), nullable=False)  # pre_incident, containment, deception, post_incident
    configuration: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_by: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="config_snapshots")
    
    __table_args__ = (
        Index("ix_config_snapshot_incident_created", "incident_id", "created_at"),
    )


class ConfigDiff(Base):
    __tablename__ = "config_diffs"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    from_snapshot_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("config_snapshots.id"), nullable=False)
    to_snapshot_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("config_snapshots.id"), nullable=False)
    added: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    removed: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    modified: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)