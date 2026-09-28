"""
Defence API — risk, policy decisions, response actions, containment + rollback.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.incident import Incident
from app.models.asset import Asset
from app.models.response import (
    ResponseAction,
    ResponseActionType,
    ActionStatus,
    PolicyDecision,
)
from app.schemas.response import (
    RiskRequest,
    RiskResult,
    PolicyDecisionResponse,
    PolicyDecisionCreate,
    ResponseActionResponse,
    ResponseActionCreate,
    ResponseActionApprove,
    ContainmentPreview,
    ContainmentExecute,
)
from app.services.risk_engine import compute_risk, asset_risk
from app.services.policy_engine import evaluate_policy
from app.services.response_orchestrator import (
    preview_containment,
    execute_action,
    rollback_action,
    add_timeline,
)
from app.services.audit_service import log_audit

router = APIRouter()


@router.post("/risk", response_model=RiskResult)
async def compute_risk_endpoint(body: RiskRequest, current_user: dict = Depends(get_current_user)):
    return RiskResult(**compute_risk(
        threat_probability=body.threat_probability,
        confidence=body.confidence,
        asset_criticality=body.asset_criticality,
        exposure=body.exposure,
        predicted_impact=body.predicted_impact,
        converging_paths=body.converging_paths,
        active_actors=body.active_actors,
    ))


@router.get("/risk/assets", response_model=List[dict])
async def asset_risk_overview(
    incident_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(Asset).options(selectinload(Asset.services))
    if incident_id:
        query = query.where(Asset.incident_id == incident_id)
    assets = (await db.execute(query)).scalars().all()
    out = []
    for a in assets:
        r = asset_risk(a, threat_probability=a.threat_score, confidence=0.8)
        out.append({
            "asset_id": str(a.id),
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "status": a.status.value if hasattr(a.status, "value") else a.status,
            "criticality": a.criticality.value if hasattr(a.criticality, "value") else a.criticality,
            "exposure": round(r["exposure_component"] / 100, 3),
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
        })
    out.sort(key=lambda x: x["risk_score"], reverse=True)
    return out


@router.post("/policy/decision", response_model=PolicyDecisionResponse, status_code=201)
async def make_policy_decision(
    body: PolicyDecisionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    incident = await db.get(Incident, body.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    decision = evaluate_policy(
        risk_score=body.risk_score,
        confidence=body.confidence,
        asset_criticality="critical",
        predicted_target_critical=True,
        deception_available=True,
    )
    row = PolicyDecision(
        incident_id=body.incident_id,
        prediction_id=body.prediction_id,
        risk_score=body.risk_score,
        risk_level=decision.risk_level,
        confidence=body.confidence,
        recommended_action=decision.action,
        rationale=decision.rationale,
        rule_id=decision.rule_id,
        requires_human_approval=decision.requires_human_approval,
    )
    db.add(row)
    await db.flush()
    await add_timeline(
        db, body.incident_id, "policy_decision",
        f"Policy decision: {decision.action.value}",
        decision.rationale or "", severity="high" if decision.requires_human_approval else "medium",
        source="policy-engine",
    )
    await log_audit(db, actor=current_user.get("sub", "dev-user"), action="POLICY_DECISION",
                    target_type="incident", target_id=body.incident_id,
                    summary=f"Policy decision {decision.action.value} (rule {decision.rule_id})",
                    details={"risk_score": body.risk_score, "requires_human_approval": decision.requires_human_approval})
    await db.commit()
    await db.refresh(row)
    return PolicyDecisionResponse.model_validate(row)


@router.get("/policy/decisions", response_model=List[PolicyDecisionResponse])
async def list_policy_decisions(
    incident_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(PolicyDecision).order_by(desc(PolicyDecision.timestamp)).limit(100)
    if incident_id:
        query = query.where(PolicyDecision.incident_id == incident_id)
    rows = (await db.execute(query)).scalars().all()
    return [PolicyDecisionResponse.model_validate(r) for r in rows]


@router.post("/actions", response_model=ResponseActionResponse, status_code=201)
async def request_action(
    body: ResponseActionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if not await db.get(Incident, body.incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    action = ResponseAction(**body.model_dump())
    db.add(action)
    await db.flush()
    await log_audit(db, actor=body.requested_by, action="RESPONSE_REQUEST",
                    target_type="response_action", target_id=action.id,
                    summary=f"Requested action {body.action_type.value}",
                    details={"requires_human_approval": action.requires_human_approval})
    await db.commit()
    await db.refresh(action)
    return ResponseActionResponse.model_validate(action)


@router.get("/actions", response_model=List[ResponseActionResponse])
async def list_actions(
    incident_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(ResponseAction).order_by(desc(ResponseAction.request_timestamp)).limit(100)
    if incident_id:
        query = query.where(ResponseAction.incident_id == incident_id)
    rows = (await db.execute(query)).scalars().all()
    return [ResponseActionResponse.model_validate(r) for r in rows]


@router.post("/actions/{action_id}/approve", response_model=ResponseActionResponse)
async def approve_action(
    action_id: UUID,
    body: ResponseActionApprove,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    action = await db.get(ResponseAction, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if not body.approve:
        await log_audit(db, actor=body.approved_by, action="APPROVAL",
                        target_type="response_action", target_id=action_id,
                        summary=f"REJECTED action {action.action_type.value}", details={"approved": False})
        await db.commit()
        return ResponseActionResponse.model_validate(action)
    action.approved_by = body.approved_by
    action.approved_timestamp = datetime.utcnow()
    action.status = ActionStatus.APPROVED
    await log_audit(db, actor=body.approved_by, action="APPROVAL",
                    target_type="response_action", target_id=action_id,
                    summary=f"Approved action {action.action_type.value}", details={"approved": True})
    await db.commit()
    await db.refresh(action)
    return ResponseActionResponse.model_validate(action)


@router.post("/actions/{action_id}/execute", response_model=ResponseActionResponse)
async def execute_response_action(
    action_id: UUID,
    actor: str = "system",
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    action = await db.get(ResponseAction, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    action = await execute_action(db, action, actor=current_user.get("sub", actor))
    await db.commit()
    await db.refresh(action)
    return ResponseActionResponse.model_validate(action)


@router.post("/actions/{action_id}/rollback", response_model=ResponseActionResponse)
async def rollback_response_action(
    action_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    action = await db.get(ResponseAction, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    action = await rollback_action(db, action, actor=current_user.get("sub", "system"))
    await db.commit()
    await db.refresh(action)
    return ResponseActionResponse.model_validate(action)


@router.post("/containment/preview", response_model=ContainmentPreview)
async def containment_preview(
    body: ContainmentExecute,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return ContainmentPreview(**await preview_containment(db, body.incident_id, body.asset_ids, body.action_type))


@router.post("/containment/execute", response_model=ResponseActionResponse, status_code=201)
async def containment_execute(
    body: ContainmentExecute,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    incident = await db.get(Incident, body.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    action = ResponseAction(
        incident_id=body.incident_id,
        action_type=body.action_type,
        status=ActionStatus.PROPOSED,
        requested_by=current_user.get("sub", "system"),
        approved_by=body.approved_by,
        approved_timestamp=datetime.utcnow() if body.approved_by else None,
        requires_human_approval=body.requires_human_approval,
        asset_ids=body.asset_ids,
        simulation=True,
        details={"mode": "simulation"},
    )
    db.add(action)
    await db.flush()
    action = await execute_action(db, action, actor=current_user.get("sub", "system"))
    await db.commit()
    await db.refresh(action)
    return ResponseActionResponse.model_validate(action)