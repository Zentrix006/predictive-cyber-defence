"""
Model Evaluation Models

Stores forecast-validation metrics (lead time, calibration, top-k accuracy) and
baseline/ablation comparison runs for the Model Lab.
"""
from datetime import datetime
from typing import Optional, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, ForeignKey, Index, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base


class ForecastEvaluation(Base):
    """Metrics from validating forecasts against observed transitions."""

    __tablename__ = "forecast_evaluations"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), index=True, nullable=True)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    metrics: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)  # accuracy, precision, recall, f1, macro_f1
    lead_time: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)  # mean, median, min, max, percentiles
    calibration: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)  # ECE, bins
    confusion_matrix: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)


class ModelComparisonRun(Base):
    """A baseline or ablation comparison run shown in the Model Lab."""

    __tablename__ = "model_comparison_runs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # baseline | ablation
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    results: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)  # list of {label, metrics}