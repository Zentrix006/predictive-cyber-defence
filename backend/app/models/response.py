"""
Response, Policy Decision and Audit Models

Every defensive action is recorded with before/after configuration references and
rollback support. Nothing executes silently - each action is auditable.
"""
import enum
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Enum, ForeignKey, Index, Float, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID, ARRAY

from app.models.base import Base


class ResponseActionType(str, enum.Enum):
    OBSERVE = "observe"
    MONITOR = "monitor"
    PREPARE_DECEPTION = "prepare_deception"
    CONTAIN = "contain"
    CONTAIN_AND_DECEIVE = "contain_and_deceive"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    ISOLATE_HOST = "isolate_host"
    RATE_LIMIT = "rate_limit"
    TERMINATE_SESSION = "terminate_session"
    FORCE_REAUTH = "force_reauth"
    ESCALATE = "escalate"
    ROLLBACK = "rollback"


class ActionStatus(str, enum.Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    EXECUTING = "executing"
    EXECUTED = "executed"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    action_type: Mapped[ResponseActionType] = mapped_column(Enum(ResponseActionType), nullable=False)
    status: Mapped[ActionStatus] = mapped_column(Enum(ActionStatus), nullable=False, default=ActionStatus.PROPOSED)

    request_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    approved_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    requested_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    requires_human_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    asset_ids: Mapped[List[UUID]] = mapped_column(ARRAY(PGUUID(as_uuid=True)), nullable=False, default=list)

    before_snapshot_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    after_snapshot_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    rollback_action_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    simulation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    details: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    result: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="response_actions")

    __table_args__ = (
        Index("ix_response_action_incident_status", "incident_id", "status"),
    )


class PolicyDecision(Base):
    """A deterministic policy-level decision produced by the policy engine."""

    __tablename__ = "policy_decisions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    prediction_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    recommended_action: Mapped[ResponseActionType] = mapped_column(Enum(ResponseActionType), nullable=False)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, default="no-policy")

    requires_human_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="policy_decisions")


class AuditEvent(Base):
    """Immutable-style audit trail of every significant system action."""

    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # LOGIN, MODEL_RUN, PREDICTION, ...
    target_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    details: Mapped[Dict] = mapped_column(JSONB, nullable=False, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    __table_args__ = (
        Index("ix_audit_action_timestamp", "action", "timestamp"),
    )