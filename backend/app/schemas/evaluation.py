"""
Model Lab Evaluation Schemas
"""
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.incident import AttackStage


class ForecastEvaluationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: UUID
    incident_id: Optional[UUID] = None
    model_version: str
    created_at: datetime
    metrics: Dict = {}
    lead_time: Dict = {}
    calibration: Dict = {}
    confusion_matrix: Dict = {}


class ModelComparisonRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: UUID
    kind: str
    model_version: str
    created_at: datetime
    results: Dict = {}


class LeadTimeMetrics(BaseModel):
    mean_seconds: float
    median_seconds: float
    min_seconds: float
    max_seconds: float
    p50_seconds: float
    p75_seconds: float
    p95_seconds: float
    count: int


class StageForecastSample(BaseModel):
    stage: str
    stage_index: int
    predicted_at: datetime
    observed_at: Optional[datetime] = None
    lead_time_seconds: Optional[float] = None
    correct: bool


class WorldModelMetrics(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    model_version: str
    stage_accuracy: Optional[float] = None
    infiltration_accuracy: Optional[float] = None
    val_loss: Optional[float] = None
    macro_precision: Optional[float] = None
    macro_recall: Optional[float] = None
    macro_f1: Optional[float] = None
    datasets: List[str] = []
    use_rl: bool = True
    rl_actions: int = 8
    n_branches: int = 5
    checkpoint_history: Dict = {}


class AblationResult(BaseModel):
    system: str
    removed: str
    stage_accuracy: Optional[float] = None
    samples: int = 0
    note: Optional[str] = None


class ComparisonBaseline(BaseModel):
    label: str
    accuracy: Optional[float] = None
    macro_f1: Optional[float] = None
    samples: Optional[int] = None
    type: Optional[str] = None
    error: Optional[str] = None
    stage_accuracy: Optional[float] = None
    infiltration_accuracy: Optional[float] = None


class ModelComparisonResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    run_type: str
    model_version: Optional[str] = None
    created_at: Optional[datetime] = None
    baselines: List[ComparisonBaseline] = []
    world_model: Optional[ComparisonBaseline] = None
    systems: List[AblationResult] = []
    methodology: Optional[str] = None
    error: Optional[str] = None
    result_json: Dict = {}