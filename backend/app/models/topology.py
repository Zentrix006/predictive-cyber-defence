"""
Topology Models
"""
from datetime import datetime
from typing import List, Dict, Optional
from uuid import UUID, uuid4

from sqlalchemy import String, ForeignKey, Index, Float, DateTime, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base


class TopologySnapshot(Base):
    __tablename__ = "topology_snapshots"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    
    # Serialized topology
    nodes: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)
    edges: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)
    prediction_edges: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)
    
    __table_args__ = (
        Index("ix_topology_incident_timestamp", "incident_id", "timestamp"),
    )