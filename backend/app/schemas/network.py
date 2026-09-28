"""
Network State Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class NetworkServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    name: str
    port: Optional[int] = None
    protocol: str
    version: Optional[str] = None
    status: str
    first_seen: datetime
    last_seen: datetime


class NetworkServiceCreate(BaseModel):
    asset_id: UUID
    name: str
    port: Optional[int] = None
    protocol: str = "tcp"
    version: Optional[str] = None
    status: str = "running"


class UserAccountResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    username: str
    hostname: Optional[str] = None
    source: str
    is_privileged: bool
    last_login: Optional[datetime] = None
    status: str
    first_seen: datetime
    last_seen: datetime


class UserAccountCreate(BaseModel):
    asset_id: UUID
    username: str
    hostname: Optional[str] = None
    source: str = "local"
    is_privileged: bool = False
    last_login: Optional[datetime] = None
    status: str = "active"


class AuthEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: Optional[UUID] = None
    timestamp: datetime
    username: str
    src_ip: Optional[str] = None
    success: bool
    auth_method: str
    event_type: str


class AuthEventCreate(BaseModel):
    asset_id: Optional[UUID] = None
    username: str
    src_ip: Optional[str] = None
    success: bool = False
    auth_method: str = "password"
    event_type: str = "login"


class VulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = None
    status: str
    discovered_at: datetime
    updated_at: datetime


class VulnerabilityCreate(BaseModel):
    asset_id: UUID
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cvss_score: Optional[float] = None
    status: str = "open"


class NetworkStateResponse(BaseModel):
    """Aggregated live network state."""

    asset_count: int
    services: List[NetworkServiceResponse]
    users: List[UserAccountResponse]
    auth_events: List[AuthEventResponse]
    vulnerabilities: List[VulnerabilityResponse]
    suspicious_assets: List[dict]
    distressed_assets: List[dict]
    timestamp: datetime


class NetworkMetrics(BaseModel):
    assets: int
    services: int
    users: int
    auth_events: int
    vulnerabilities: int
    critical_vulnerabilities: int
    suspicious_assets: int
    compromised_assets: int