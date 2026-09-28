"""
Deception API Endpoints
"""
from typing import Any, Dict, List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user
from app.models.deception import (
    DeceptionDeployment, HoneypotInteraction, HoneypotTemplate, HoneypotInstance,
    DeploymentStatus, HoneypotType, HoneypotStatus
)
from app.schemas.deception import (
    DeceptionDeploymentResponse, DeceptionDeploymentCreate,
    HoneypotInteractionResponse, HoneypotTemplateResponse,
    PaginatedDeployments, HoneypotInstanceResponse
)
from app.schemas.common import APIResponse
from app.services.deception_selector import select_honeypots
from app.services.audit_service import log_audit

router = APIRouter()


@router.get("/instances", response_model=List[HoneypotInstanceResponse])
async def list_honeypot_instances(
    status: Optional[HoneypotStatus] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(HoneypotInstance)
    if status:
        query = query.where(HoneypotInstance.status == status)
    rows = (await db.execute(query.order_by(HoneypotInstance.created_at.desc()))).scalars().all()
    out = []
    for item in rows:
        d = HoneypotInstanceResponse.model_validate(item)
        d.interactions_count = 0
        out.append(d)
    return out


@router.post("/instances/{instance_id}/activate", response_model=HoneypotInstanceResponse)
async def activate_honeypot(
    instance_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    instance = await db.get(HoneypotInstance, instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Honeypot instance not found")
    if instance.status != HoneypotStatus.DORMANT:
        raise HTTPException(status_code=409, detail=f"Cannot activate from status {instance.status.value}")
    instance.status = HoneypotStatus.ACTIVE
    instance.updated_at = datetime.utcnow()
    await log_audit(db, actor=current_user.get("sub", "dev-user"), action="DECEPTION_ACTIVATE",
                    target_type="honeypot_instance", target_id=instance.id,
                    summary=f"Activated honeypot {instance.name}")
    await db.commit()
    await db.refresh(instance)
    return HoneypotInstanceResponse.model_validate(instance)


@router.get("/selector", response_model=dict)
async def honeypot_selector(
    incident_id: Optional[UUID] = Query(None),
    stage: str = Query("credential_access"),
    asset_id: Optional[UUID] = Query(None),
    limit: int = Query(5, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Recommend honeypots for a predicted stage/target (defence plan integration)."""
    rows = (await db.execute(
        select(HoneypotInstance).where(HoneypotInstance.status == HoneypotStatus.DORMANT)
    )).scalars().all()
    ranked = select_honeypots(rows, predicted_stage=stage, limit=limit)
    return {
        "stage": stage,
        "incident_id": str(incident_id) if incident_id else None,
        "recommendations": [
            {
                "id": r["honeypot_id"],
                "name": r["name"],
                "honeypot_type": r["type"],
                "score": round(r["score"], 3),
                "available": r["available"],
                "rationale": f"Honeypot {r['type']} matches predicted {stage} stage and target profile.",
            }
            for r in ranked
        ],
    }


@router.post("/deploy", response_model=DeceptionDeploymentResponse, status_code=201)
async def deploy_honeynet(
    deployment_in: DeceptionDeploymentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Deploy honeynet for an incident."""
    from app.models.incident import Incident
    from uuid import uuid4
    
    # Verify incident
    result = await db.execute(select(Incident).where(Incident.id == deployment_in.incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Create deployment
    deployment = DeceptionDeployment(
        id=uuid4(),
        incident_id=deployment_in.incident_id,
        name=deployment_in.name,
        honeypot_types=deployment_in.honeypot_types,
        target_assets=deployment_in.target_assets,
        predicted_stage=deployment_in.predicted_stage,
        status=DeploymentStatus.DEPLOYING,
        network_config=deployment_in.network_config or {},
    )
    db.add(deployment)
    await db.commit()
    await db.refresh(deployment)
    
    # TODO: Trigger actual honeypot deployment via deception engine
    # This would call the ML engine or a separate service
    
    return DeceptionDeploymentResponse.model_validate(deployment)


@router.get("/deployments", response_model=PaginatedDeployments)
async def list_deployments(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    incident_id: Optional[UUID] = Query(None),
    status: Optional[List[str]] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List deception deployments."""
    query = select(DeceptionDeployment)
    
    if incident_id:
        query = query.where(DeceptionDeployment.incident_id == incident_id)
    if status:
        query = query.where(DeceptionDeployment.status.in_(status))
    
    query = query.order_by(desc(DeceptionDeployment.deployed_at))
    
    from sqlalchemy import func
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)
    
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    deployments = result.scalars().all()
    
    return PaginatedDeployments(
        items=[DeceptionDeploymentResponse.model_validate(d) for d in deployments],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/deployments/{deployment_id}", response_model=DeceptionDeploymentResponse)
async def get_deployment(
    deployment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get deployment details."""
    result = await db.execute(
        select(DeceptionDeployment)
        .where(DeceptionDeployment.id == deployment_id)
        .options(selectinload(DeceptionDeployment.interactions))
    )
    deployment = result.scalar_one_or_none()
    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return DeceptionDeploymentResponse.model_validate(deployment)


@router.get("/deployments/{deployment_id}/interactions", response_model=List[HoneypotInteractionResponse])
async def get_interactions(
    deployment_id: UUID,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get honeypot interactions."""
    result = await db.execute(
        select(HoneypotInteraction)
        .where(HoneypotInteraction.deployment_id == deployment_id)
        .order_by(desc(HoneypotInteraction.timestamp))
        .limit(limit)
    )
    interactions = result.scalars().all()
    return [HoneypotInteractionResponse.model_validate(i) for i in interactions]


@router.post("/deployments/{deployment_id}/teardown", response_model=APIResponse)
async def teardown_deployment(
    deployment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Teardown a deception deployment."""
    result = await db.execute(
        select(DeceptionDeployment).where(DeceptionDeployment.id == deployment_id)
    )
    deployment = result.scalar_one_or_none()
    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")
    
    deployment.status = DeploymentStatus.TEARING_DOWN
    deployment.torn_down_at = datetime.utcnow()
    
    # TODO: Call deception engine to teardown containers
    
    await db.commit()
    
    return APIResponse(
        success=True,
        message="Deployment teardown initiated",
        data={"deployment_id": str(deployment_id)}
    )


@router.get("/templates", response_model=List[HoneypotTemplateResponse])
async def list_templates(
    honeypot_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List available honeypot templates."""
    from app.models.deception import HoneypotTemplate
    
    query = select(HoneypotTemplate).where(HoneypotTemplate.is_active == True)
    if honeypot_type:
        query = query.where(HoneypotTemplate.honeypot_type == honeypot_type)
    
    result = await db.execute(query)
    templates = result.scalars().all()
    return [HoneypotTemplateResponse.model_validate(t) for t in templates]


# --- Epistemic Deception & Autonomous TTP Extraction (Phase 5 & 7) ---

from pydantic import BaseModel, Field
from app.services.epistemic_deception import EpistemicDeceptionOrchestrator

_EPISTEMIC_ORCHESTRATOR = EpistemicDeceptionOrchestrator()


class EpistemicProvisionRequest(BaseModel):
    attacker_ip: str = Field(..., pattern=r"^\d{1,3}(\.\d{1,3}){3}$")
    target_port: int = Field(445, ge=1, le=65535)
    target_protocol: str = Field("TCP")
    platform: str = Field("linux_nftables")


class EpistemicIngestRequest(BaseModel):
    sandbox_id: str = Field(..., min_length=3)
    commands: List[str] = Field(default_factory=list)
    payload_hex: Optional[str] = None


@router.get("/epistemic/sandboxes", response_model=Dict[str, Any])
async def list_epistemic_sandboxes():
    """Retrieve all active dynamic deception sandboxes and their captured TTPs."""
    sandboxes = [s.to_dict() for s in _EPISTEMIC_ORCHESTRATOR.active_sandboxes.values()]
    return {
        "count": len(sandboxes),
        "sandboxes": sandboxes,
        "replay_buffer_size": len(_EPISTEMIC_ORCHESTRATOR.replay_buffer),
    }


@router.post("/epistemic/provision", response_model=Dict[str, Any], status_code=201)
async def provision_epistemic_sandbox(body: EpistemicProvisionRequest):
    """Dynamically provision a high-interaction decoy sandbox and compile transparent flow diversion."""
    instance = _EPISTEMIC_ORCHESTRATOR.provision_sandbox(
        attacker_ip=body.attacker_ip,
        target_port=body.target_port,
        target_protocol=body.target_protocol,
        platform=body.platform,
    )
    return {
        "status": "deployed",
        "sandbox": instance.to_dict(),
        "diversion_rule": instance.diversion_rule,
    }


@router.post("/epistemic/ingest", response_model=Dict[str, Any])
async def ingest_epistemic_interaction(body: EpistemicIngestRequest):
    """Ingest captured adversary interaction, extract MITRE TTPs, and feed to replay memory."""
    payload_bytes = None
    if body.payload_hex:
        try:
            payload_bytes = bytes.fromhex(body.payload_hex)
        except ValueError:
            payload_bytes = body.payload_hex.encode("utf-8")
    try:
        result = _EPISTEMIC_ORCHESTRATOR.ingest_attacker_interaction(
            sandbox_id=body.sandbox_id,
            commands=body.commands,
            payload_data=payload_bytes,
        )
        return result
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))