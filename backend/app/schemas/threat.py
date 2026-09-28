"""
Threat Actor Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.incident import AttackStage
from app.models.threat import ActorResponseState


class ThreatTrajectoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_id: UUID
    incident_id: Optional[UUID] = None
    timestamp: datetime
    observed_source: str
    src_ip: Optional[str] = None
    current_asset_id: Optional[UUID] = None
    current_asset_name: Optional[str] = None
    current_stage: AttackStage
    predicted_stage: Optional[AttackStage] = None
    predicted_target_id: Optional[UUID] = None
    predicted_target_name: Optional[str] = None
    confidence: float
    risk_score: float
    evidence: List[Dict] = []


class ThreatActorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    display_id: str
    incident_id: Optional[UUID] = None
    first_seen: datetime
    last_seen: datetime
    source_observations: List[Dict] = []
    correlated_sources: List[str] = []
    current_asset_id: Optional[UUID] = None
    current_asset_name: Optional[str] = None
    current_stage: Optional[AttackStage] = None
    predicted_stage: Optional[AttackStage] = None
    predicted_target_id: Optional[UUID] = None
    predicted_target_name: Optional[str] = None
    confidence: float
    risk_score: float
    response_state: ActorResponseState
    deception_state: str
    created_at: datetime
    updated_at: datetime


class ThreatActorCreate(BaseModel):
    display_id: Optional[str] = None
    incident_id: Optional[UUID] = None
    observed_source: str
    src_ip: Optional[str] = None
    current_asset_id: Optional[UUID] = None
    current_asset_name: Optional[str] = None
    current_stage: AttackStage = AttackStage.RECONNAISSANCE
    confidence: float = 0.5
    risk_score: float = 0.0


class TrajectoryCreate(BaseModel):
    actor_id: UUID
    incident_id: Optional[UUID] = None
    observed_source: str
    src_ip: Optional[str] = None
    current_asset_id: Optional[UUID] = None
    current_asset_name: Optional[str] = None
    current_stage: AttackStage
    predicted_stage: Optional[AttackStage] = None
    predicted_target_id: Optional[UUID] = None
    predicted_target_name: Optional[str] = None
    confidence: float = 0.5
    risk_score: float = 0.0
    evidence: List[Dict] = []


class ConvergingPath(BaseModel):
    asset_id: UUID
    asset_name: str
    asset_type: str
    actor_count: int
    actors: List[str]
    combined_risk: float
    risk_level: str
    stages: List[str]


class ConvergenceReport(BaseModel):
    converging_paths: List[ConvergingPath]
    message: str = ""
    timestamp: datetime