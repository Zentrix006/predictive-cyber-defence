"""Versioned graph-window contract used between canonical extraction and training.

The window is intentionally separate from raw events: it records the exact
history/future boundary and telemetry quality so missing data cannot silently
be learned as benign behaviour.
"""
from datetime import datetime
from typing import Dict, List, Optional, Literal
from pydantic import BaseModel, Field, model_validator

WINDOW_SCHEMA_VERSION = "telemetry-window-v1"

class TelemetryQuality(BaseModel):
    packet_coverage: float = Field(ge=0, le=1)
    flow_coverage: float = Field(ge=0, le=1)
    identity_coverage: float = Field(ge=0, le=1)
    topology_coverage: float = Field(ge=0, le=1)
    clock_sync_quality: float = Field(default=1, ge=0, le=1)
    dropped_event_count: int = Field(default=0, ge=0)
    parser_warning_count: int = Field(default=0, ge=0)
    source_agreement: float = Field(default=1, ge=0, le=1)

class WindowLabel(BaseModel):
    malicious: Optional[bool] = None
    mitre_stage: Optional[str] = None
    attack_family: Optional[str] = None
    label_confidence: float = Field(default=0, ge=0, le=1)
    provenance: str = "unknown"
    is_partial: bool = False
    is_unknown: bool = True

class GraphWindow(BaseModel):
    schema_version: str = WINDOW_SCHEMA_VERSION
    campaign_id: str
    site_id: str
    capture_id: str
    window_id: str
    start_utc: datetime
    end_utc: datetime
    history_window_ids: List[str] = Field(default_factory=list)
    future_window_ids: List[str] = Field(default_factory=list)
    node_ids: List[str] = Field(default_factory=list)
    edge_ids: List[str] = Field(default_factory=list)
    node_features: Dict[str, List[float]] = Field(default_factory=dict)
    edge_features: Dict[str, List[float]] = Field(default_factory=dict)
    node_missing_mask: Dict[str, List[bool]] = Field(default_factory=dict)
    edge_missing_mask: Dict[str, List[bool]] = Field(default_factory=dict)
    label: WindowLabel = Field(default_factory=WindowLabel)
    quality: TelemetryQuality
    preprocessing_config_hash: str

    @model_validator(mode="after")
    def validate_interval(self) -> "GraphWindow":
        if self.end_utc <= self.start_utc:
            raise ValueError("window end must be after window start")
        if self.window_id in self.history_window_ids or self.window_id in self.future_window_ids:
            raise ValueError("current window cannot also be a history/future target")
        return self

class DatasetQualityReport(BaseModel):
    schema_version: str = WINDOW_SCHEMA_VERSION
    dataset_version: str
    partition: Literal["train", "development", "calibration", "test-known", "test-novel"]
    campaigns: int = Field(ge=0)
    captures: int = Field(ge=0)
    windows: int = Field(ge=0)
    stage_support: Dict[str, int] = Field(default_factory=dict)
    attack_family_support: Dict[str, int] = Field(default_factory=dict)
    missingness: Dict[str, float] = Field(default_factory=dict)
    label_confidence_mean: float = Field(default=0, ge=0, le=1)
    overlap_detected: bool = False
    warnings: List[str] = Field(default_factory=list)
    passed: bool = False

    @model_validator(mode="after")
    def cannot_pass_with_overlap(self) -> "DatasetQualityReport":
        if self.overlap_detected:
            self.passed = False
        return self
