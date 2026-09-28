"""
Topology Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.asset import AssetStatus, AssetType, ZoneType, CriticalityLevel


class TopologyNode(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    label: str
    asset_id: UUID
    asset_type: AssetType
    zone: ZoneType
    status: AssetStatus
    threat_score: float
    criticality: CriticalityLevel
    position: Optional[Dict[str, float]] = None
    metadata: Dict = {}


class TopologyEdge(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    source: str
    target: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    bytes_transferred: int = 0
    packet_count: int = 0
    is_predicted: bool = False
    prediction_probability: Optional[float] = None
    first_seen: datetime
    last_seen: datetime


class PredictionEdge(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    source: str
    target: str
    probability: float
    predicted_stage: str
    eta_seconds: float
    created_at: datetime


class NetworkTopology(BaseModel):
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
    prediction_edges: List[PredictionEdge] = []
    timestamp: datetime
    incident_id: Optional[UUID] = None