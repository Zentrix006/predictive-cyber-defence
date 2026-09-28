"""
Prediction Schemas
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.incident import AttackStage


class ForecastWindowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    window_offset: int
    stage: AttackStage
    probability: float
    target_asset_id: Optional[UUID] = None
    target_asset_name: Optional[str] = None
    eta_seconds: float
    confidence: float


class PredictedTargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    asset_id: UUID
    asset_name: str
    asset_type: str
    probability: float
    reasoning: List[str]


class FactorContribution(BaseModel):
    factor: str
    contribution: float
    description: str


class ExplanationResponse(BaseModel):
    feature_importance: Dict[str, float]
    top_factors: List[FactorContribution]
    natural_language: str
    attention_visualization: Optional[Dict[str, Any]] = None
    thinking: Optional[Dict[str, Any]] = None


class AttackForecast(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    incident_id: UUID
    current_stage: AttackStage
    current_confidence: float
    timeline: List[ForecastWindowResponse]
    predicted_targets: List[PredictedTargetResponse]
    explanation: ExplanationResponse
    generated_at: datetime
    model_version: str
    recommended_action: str = "monitor"
    recommended_actions: List[Dict[str, Any]] = []


class PredictionGenerate(BaseModel):
    incident_id: UUID
    horizon: int = 4


class ExplanationResponseModel(BaseModel):
    feature_importance: Dict[str, float]
    top_factors: List[FactorContribution]
    natural_language: str
    attention_visualization: Optional[Dict[str, Any]] = None