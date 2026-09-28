"""
Asset Schemas
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.asset import AssetStatus, AssetType, ZoneType, CriticalityLevel, IsolationLevel


class NetworkInterfaceBase(BaseModel):
    name: str
    ip_addresses: List[str] = []
    mac_address: Optional[str] = None
    vlan: Optional[int] = None
    speed_mbps: Optional[int] = None


class NetworkInterfaceResponse(NetworkInterfaceBase):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID


class AssetBase(BaseModel):
    hostname: str
    ip_address: str
    asset_type: AssetType
    zone: ZoneType
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    os: Optional[str] = None
    os_version: Optional[str] = None
    tags: List[str] = []
    metadata: dict = {}


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[AssetType] = None
    zone: Optional[ZoneType] = None
    criticality: Optional[CriticalityLevel] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[dict] = None


class AssetResponse(AssetBase):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    status: AssetStatus
    threat_score: float
    last_seen: Optional[datetime] = None
    incident_id: Optional[UUID] = None
    containment_level: IsolationLevel
    deception_deployment_id: Optional[UUID] = None
    interfaces: List[NetworkInterfaceResponse] = []
    created_at: datetime
    updated_at: datetime


class AssetStatusResponse(BaseModel):
    asset_id: UUID
    status: AssetStatus
    threat_score: float
    active_connections: int
    suspicious_flows: int
    blocked_flows: int
    auth_failures_5min: int
    cpu_usage: float
    memory_usage: float
    updated_at: datetime


class PaginatedAssets(BaseModel):
    items: List[AssetResponse]
    total: int
    page: int
    page_size: int
    total_pages: int