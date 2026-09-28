"""
Response / Policy / Audit Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.response import ResponseActionType, ActionStatus


class ResponseActionCreate(BaseModel):
    incident_id: UUID
    actor_id: Optional[UUID] = None
    action_type: ResponseActionType
    requested_by: str = "system"
    requires_human_approval: bool = False
    asset_ids: List[UUID] = []
    details: Dict = {}


class ResponseActionApprove(BaseModel):
    approved_by: str
    approve: bool = True


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    actor_id: Optional[UUID] = None
    action_type: ResponseActionType
    status: ActionStatus
    request_timestamp: datetime
    approved_timestamp: Optional[datetime] = None
    executed_timestamp: Optional[datetime] = None
    verified_timestamp: Optional[datetime] = None
    rolled_back_at: Optional[datetime] = None
    requested_by: str
    approved_by: Optional[str] = None
    requires_human_approval: bool
    asset_ids: List[UUID] = []
    before_snapshot_id: Optional[UUID] = None
    after_snapshot_id: Optional[UUID] = None
    rollback_action_id: Optional[UUID] = None
    simulation: bool
    details: Dict = {}
    result: Dict = {}


class PolicyDecisionCreate(BaseModel):
    incident_id: UUID
    prediction_id: Optional[UUID] = None
    risk_score: float = 0.0
    risk_level: Optional[str] = None
    confidence: float = 0.0
    recommended_action: Optional[ResponseActionType] = None
    rationale: Optional[str] = None
    rule_id: Optional[str] = None
    requires_human_approval: Optional[bool] = None


class PolicyDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    prediction_id: Optional[UUID] = None
    timestamp: datetime
    risk_score: float
    risk_level: str
    confidence: float
    recommended_action: ResponseActionType
    rationale: Optional[str] = None
    rule_id: str
    requires_human_approval: bool
    approved: bool
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


class RiskRequest(BaseModel):
    threat_probability: float = 0.5
    confidence: float = 0.5
    asset_criticality: str = "medium"
    exposure: float = 0.5
    predicted_impact: float = 0.5
    converging_paths: int = 1
    active_actors: int = 1


class RiskResult(BaseModel):
    risk_score: float
    risk_level: str
    probability_component: float
    criticality_component: float
    exposure_component: float
    impact_component: float
    convergence_multiplier: float
    converging_paths: int


class ContainmentPreview(BaseModel):
    action_type: ResponseActionType
    assets: List[dict]
    isolation_level: str
    predicted_impact: dict
    rollback_available: bool
    simulation: bool
    briefing: str


class ContainmentExecute(BaseModel):
    incident_id: UUID
    action_type: ResponseActionType = ResponseActionType.CONTAIN
    asset_ids: List[UUID]
    approved_by: Optional[str] = None
    requires_human_approval: bool = True


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    actor: str
    action: str
    target_type: Optional[str] = None
    target_id: Optional[UUID] = None
    summary: str
    details: Dict = {}
    ip_address: Optional[str] = None