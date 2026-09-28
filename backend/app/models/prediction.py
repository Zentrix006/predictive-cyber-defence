"""
Prediction Models
"""
import enum
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

from app.models.base import Base
from app.models.incident import AttackStage


class Prediction(Base):
    __tablename__ = "predictions"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    current_stage: Mapped[AttackStage] = mapped_column(Enum(AttackStage), nullable=False)
    current_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    horizon: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    
    # Serialized forecast data
    timeline: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)
    predicted_targets: Mapped[List[Dict]] = mapped_column(JSONB, nullable=False, default=list)
    explanation: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="predictions")


class ForecastWindow(Base):
    """Individual forecast window - can be queried separately"""
    __tablename__ = "forecast_windows"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    prediction_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("predictions.id", ondelete="CASCADE"), nullable=False, index=True)
    window_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    stage: Mapped[AttackStage] = mapped_column(Enum(AttackStage), nullable=False)
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    target_asset_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    target_asset_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    eta_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)


class PredictedTarget(Base):
    __tablename__ = "predicted_targets"
    
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    prediction_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("predictions.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    asset_name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    reasoning: Mapped[List[str]] = mapped_column(JSONB, nullable=False, default=list)