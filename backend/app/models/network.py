"""
Network State Model

Structured representation of the live network state layered around assets:
services, user accounts, authentication events and vulnerabilities.
"""
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base


class NetworkService(Base):
    """A service listening on an asset."""

    __tablename__ = "network_services"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="tcp")
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")  # running, stopped, unknown
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="services")

    __table_args__ = (
        Index("ix_network_service_asset_port", "asset_id", "port"),
    )


class UserAccount(Base):
    """A user account observed on an asset."""

    __tablename__ = "user_accounts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="local")  # local, domain, service
    is_privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")  # active, expired, disabled, suspicious
    metadata_: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="user_accounts")

    __table_args__ = (
        Index("ix_user_account_asset_username", "asset_id", "username"),
    )


class AuthEvent(Base):
    """A single authentication event observed on an asset."""

    __tablename__ = "auth_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auth_method: Mapped[str] = mapped_column(String(64), nullable=False, default="password")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="login")  # login, login_failure, sudo, verify
    metadata_: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_auth_event_asset_timestamp", "asset_id", "timestamp"),
    )


class Vulnerability(Base):
    """A vulnerability observed on an asset."""

    __tablename__ = "vulnerabilities"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")  # low, medium, high, critical
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")  # open, mitigated, patched, false_positive
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    metadata_: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vulnerability_asset_cve", "asset_id", "cve_id"),
    )