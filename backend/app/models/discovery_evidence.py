"""
Discovery Evidence and Device Identity Models (Phase 1)
Append-only evidence records, verified device identities, topology edges, and snapshots.
"""
from datetime import datetime, timezone
import enum
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4

from sqlalchemy import String, Text, ForeignKey, Index, DateTime, Float, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base


class DeviceLifecycleStatus(str, enum.Enum):
    PROVISIONAL = "provisional"
    VERIFIED = "verified"
    REJECTED = "rejected"
    MERGED = "merged"
    RETIRED = "retired"


class EdgeRelationshipType(str, enum.Enum):
    SWITCHED = "switched"
    ROUTED = "routed"
    TRUNK = "trunk"
    ACCESS = "access"
    WIRELESS = "wireless"
    INFERRED_FLOW = "inferred_flow"


class EdgeLifecycleStatus(str, enum.Enum):
    ACTIVE = "active"
    STALE = "stale"
    RETIRED = "retired"


class DeviceIdentity(Base):
    """
    Stable verified enterprise device identity with full evidence provenance.
    """
    __tablename__ = "device_identities"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    primary_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    primary_mac: Mapped[Optional[str]] = mapped_column(String(17), nullable=True, index=True)
    ips: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)
    macs: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    dhcp_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Hardware & Platform Facts (Null if unverified, never guessed)
    vendor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    firmware_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    device_role: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    
    management_interface: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    vlan_memberships: Mapped[List[int]] = mapped_column(JSONB, nullable=False, default=list)
    site_zone: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    criticality: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=DeviceLifecycleStatus.PROVISIONAL.value)
    
    # Secret references only — no plain text credentials allowed
    secret_vault_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    observations: Mapped[List["DiscoveryObservation"]] = relationship(
        "DiscoveryObservation", back_populates="device", cascade="all, delete-orphan"
    )
    snapshots: Mapped[List["DeviceSnapshot"]] = relationship(
        "DeviceSnapshot", back_populates="device", cascade="all, delete-orphan"
    )
    outbound_edges: Mapped[List["TopologyEdge"]] = relationship(
        "TopologyEdge", foreign_keys="TopologyEdge.source_device_id", back_populates="source_device"
    )
    inbound_edges: Mapped[List["TopologyEdge"]] = relationship(
        "TopologyEdge", foreign_keys="TopologyEdge.destination_device_id", back_populates="destination_device"
    )

    __table_args__ = (
        Index("ix_device_identity_status_role", "status", "device_role"),
        Index("ix_device_identity_vendor_model", "vendor", "model"),
    )


class DiscoveryObservation(Base):
    """
    Append-only raw evidence record representing a discrete discovery telemetry event.
    """
    __tablename__ = "discovery_observations"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_identities.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # arp, dhcp, mdns, snmp, lldp, cdp, ssh, netflow
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    collector: Mapped[str] = mapped_column(String(128), nullable=False)  # eth0, probe-dmz-1, snmp-poller
    raw_evidence_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    normalized_fields: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    auth_method: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    operator_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Relationships
    device: Mapped[Optional["DeviceIdentity"]] = relationship("DeviceIdentity", back_populates="observations")

    __table_args__ = (
        Index("ix_discovery_obs_source_timestamp", "source", "timestamp"),
    )


class DeviceSnapshot(Base):
    """
    Point-in-time configuration and state snapshot for a device.
    """
    __tablename__ = "device_snapshots"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    interfaces: Mapped[List[Dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    link_state: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    vlans_and_trunks: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    routing_table: Mapped[List[Dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    neighbours: Mapped[List[Dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    acl_metadata: Mapped[List[Dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    enabled_services: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)
    configuration_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    source_observation_ids: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)

    # Relationships
    device: Mapped["DeviceIdentity"] = relationship("DeviceIdentity", back_populates="snapshots")

    __table_args__ = (
        Index("ix_device_snapshot_device_time", "device_id", "collected_at"),
    )


class TopologyEdge(Base):
    """
    Verified, evidence-backed relationship edge between two devices.
    """
    __tablename__ = "topology_edges"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source_device_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    destination_device_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False, default=EdgeRelationshipType.SWITCHED.value)
    source_interface: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    destination_interface: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    vlan_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    evidence_source: Mapped[str] = mapped_column(String(64), nullable=False)  # lldp, cdp, fdb, routing_table, flow_telemetry
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=EdgeLifecycleStatus.ACTIVE.value)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_confirmed: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    source_device: Mapped["DeviceIdentity"] = relationship(
        "DeviceIdentity", foreign_keys=[source_device_id], back_populates="outbound_edges"
    )
    destination_device: Mapped["DeviceIdentity"] = relationship(
        "DeviceIdentity", foreign_keys=[destination_device_id], back_populates="inbound_edges"
    )

    __table_args__ = (
        Index("ix_topology_edge_endpoints", "source_device_id", "destination_device_id", "relationship_type"),
    )
