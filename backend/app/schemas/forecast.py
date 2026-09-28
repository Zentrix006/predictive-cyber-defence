"""
Forecast Detail Schemas

The clean forecast contract requested for the Forecast Engine: current state,
K-step predicted stages, predicted targets, probabilities, horizon, ETA,
confidence, risk and lead time.
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.incident import AttackStage


class ForecastStep(BaseModel):
    offset: int
    stage: str
    probability: float
    confidence: float
    eta_seconds: float
    target_asset_id: Optional[UUID] = None
    target_asset_name: Optional[str] = None


class TargetCandidate(BaseModel):
    asset_id: UUID
    asset_name: str
    asset_type: str
    probability: float


class BeliefBranch(BaseModel):
    branch: int
    confidence: float
    target_name: Optional[str] = None
    stage: Optional[str] = None
    risk: float


class BeliefSummary(BaseModel):
    branches: List[BeliefBranch]
    consensus_target: Optional[str] = None
    consensus_stage: Optional[str] = None
    consensus_confidence: float
    consensus_agreement: float
    worst_case: Optional[Dict] = None


class ForecastDetail(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    incident_id: UUID
    model_version: str
    generated_at: datetime

    current_state: str
    current_stage: str
    current_confidence: float

    predicted_stages: List[str]
    predicted_targets: List[TargetCandidate]
    probabilities: List[Dict[str, float]]
    forecast_horizon: int
    estimated_time: List[float]
    confidence: List[float]
    risk: List[float]
    risk_level: str

    steps: List[ForecastStep]
    belief: Optional[BeliefSummary] = None
    recommended_action: str = "monitor"
    recommended_actions: List[Dict] = []
    lead_time_estimate: Optional[float] = None
    explanation: Optional[Dict] = None