"""
Deception Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.deception import HoneypotType, DeploymentStatus, HoneypotStatus


class HoneypotInstanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    honeypot_type: HoneypotType
    os: Optional[str] = None
    version: Optional[str] = None
    status: HoneypotStatus
    ip_address: Optional[str] = None
    location: str = "honeynet"
    ports: List[int] = []
    services: List[str] = []
    telemetry_sources: Dict = {}
    risk_profile: Dict = {}
    metadata_: Dict = {}
    deployment_id: Optional[UUID] = None
    interactions_count: int = 0
    detection_count: int = 0


class HoneypotTemplateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    name: str
    honeypot_type: HoneypotType
    description: str
    docker_image: str
    ports: List[int]
    environment: Dict = {}
    volumes: List[str] = []
    resource_limits: Dict = {}
    decoy_files: List[str] = []
    credentials: List[Dict] = []
    is_active: bool
    created_at: datetime
    updated_at: datetime


class DeceptionDeploymentCreate(BaseModel):
    incident_id: UUID
    name: str
    honeypot_types: List[HoneypotType]
    target_assets: List[UUID]
    predicted_stage: str
    network_config: Optional[Dict] = None


class DeceptionDeploymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    incident_id: UUID
    name: str
    honeypot_types: List[HoneypotType]
    target_assets: List[UUID]
    predicted_stage: str
    status: DeploymentStatus
    container_ids: List[str] = []
    network_config: Dict = {}
    deployed_at: Optional[datetime] = None
    torn_down_at: Optional[datetime] = None
    interactions_count: int


class HoneypotInteractionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    deployment_id: UUID
    honeypot_type: HoneypotType
    container_id: str
    timestamp: datetime
    source_ip: str
    source_port: int
    destination_port: int
    protocol: str
    action: str
    details: Dict = {}
    severity: str
    mitre_techniques: List[str] = []


class PaginatedDeployments(BaseModel):
    items: List[DeceptionDeploymentResponse]
    total: int
    page: int
    page_size: int
    total_pages: int