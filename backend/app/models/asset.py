"""
Asset Model
"""
import enum
from datetime import datetime
from typing import Optional, List
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base


class AssetStatus(str, enum.Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    CONTAINED = "contained"
    DECEPTION = "deception"
    OFFLINE = "offline"


class AssetType(str, enum.Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    IOT_DEVICE = "iot_device"
    HONEYPOT = "honeypot"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    DOMAIN_CONTROLLER = "domain_controller"
    UNKNOWN = "unknown"


class ZoneType(str, enum.Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    SERVER_ZONE = "server_zone"
    USER_ZONE = "user_zone"
    IOT_ZONE = "iot_zone"
    MANAGEMENT = "management"
    QUARANTINE = "quarantine"
    HONEYNET = "honeynet"


class CriticalityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IsolationLevel(str, enum.Enum):
    NONE = "none"
    QUARANTINE_VLAN = "quarantine_vlan"
    FULL_ISOLATION = "full_isolation"
    NETWORK_SEGMENT = "network_segment"


class Asset(Base):
    __tablename__ = "assets"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False, default=AssetType.UNKNOWN)
    zone: Mapped[ZoneType] = mapped_column(Enum(ZoneType), nullable=False, default=ZoneType.USER_ZONE)
    criticality: Mapped[CriticalityLevel] = mapped_column(Enum(CriticalityLevel), nullable=False, default=CriticalityLevel.MEDIUM)
    os: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Evidence-backed vendor hint.  It is nullable because passive discovery
    # must preserve unknown vendors instead of guessing them.
    vendor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    vlan: Mapped[Optional[int]] = mapped_column(nullable=True)
    
    # Status
    status: Mapped[AssetStatus] = mapped_column(Enum(AssetStatus), nullable=False, default=AssetStatus.NORMAL, index=True)
    threat_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    incident_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True, index=True)
    containment_level: Mapped[IsolationLevel] = mapped_column(Enum(IsolationLevel), nullable=False, default=IsolationLevel.NONE)
    deception_deployment_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    
    # Metadata
    tags: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)
    metadata_: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="assets")
    interfaces: Mapped[List["NetworkInterface"]] = relationship(
        "NetworkInterface", back_populates="asset", cascade="all, delete-orphan"
    )
    services: Mapped[List["NetworkService"]] = relationship(
        "NetworkService", back_populates="asset", cascade="all, delete-orphan"
    )
    user_accounts: Mapped[List["UserAccount"]] = relationship(
        "UserAccount", back_populates="asset", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="asset", cascade="all, delete-orphan"
    )
    
    __table_args__ = (
        Index("ix_assets_hostname_ip", "hostname", "ip_address"),
        Index("ix_assets_zone_status", "zone", "status"),
    )


class NetworkInterface(Base):
    __tablename__ = "network_interfaces"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_addresses: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    vlan: Mapped[Optional[int]] = mapped_column(nullable=True)
    speed_mbps: Mapped[Optional[int]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    
    asset: Mapped["Asset"] = relationship("Asset", back_populates="interfaces")
