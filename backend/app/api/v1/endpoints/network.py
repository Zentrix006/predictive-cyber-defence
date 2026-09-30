"""
Network State API — services, users, auth events, vulnerabilities.
"""
from typing import Any, Dict, List, Optional
import json
from pathlib import Path
from features.streaming_telemetry import MultiSensorTelemetryNormalizer
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.network import NetworkService, UserAccount, AuthEvent, Vulnerability
from app.models.asset import Asset, AssetStatus
from app.schemas.network import (
    NetworkStateResponse,
    NetworkMetrics,
    NetworkServiceResponse,
    NetworkServiceCreate,
    UserAccountResponse,
    UserAccountCreate,
    AuthEventResponse,
    AuthEventCreate,
    VulnerabilityResponse,
    VulnerabilityCreate,
)
from app.services.audit_service import log_audit
from app.services.device_command_plan import build_intent_plan, list_profiles
from app.core.config import get_settings
from app.services.live_telemetry import live_telemetry_service

router = APIRouter()
settings = get_settings()
telemetry_normalizer = MultiSensorTelemetryNormalizer()


class IntentPlanRequest(BaseModel):
    platform: str
    intent: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


@router.get("/live-telemetry", response_model=dict)
async def live_telemetry(
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    """Return a bounded read-only view of the latest Zeek JSON flow records.

    The mounted directory is written by the lab sensor and mounted read-only
    into the API. This endpoint intentionally does not execute training or
    mutate evidence. Disabled-collector fallback records are explicitly
    unverified and must not be treated as production inventory evidence.
    """
    # Prefer the supervised collector when enabled. The bounded file-reader
    # fallback remains available for offline lab deployments.
    if live_telemetry_service.enabled:
        status = live_telemetry_service.status()
        records = live_telemetry_service.recent(limit)
        return {
            "available": bool(records),
            "records": records,
            "source": "live-telemetry-collector",
            "count": len(records),
            "status": status,
        }

    root = Path(settings.LIVE_TELEMETRY_DIR).resolve()
    if not root.exists():
        return {"available": False, "records": [], "source": str(root)}
    files = sorted(root.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    records: list[dict] = []
    for path in files[:8]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()[-limit:]
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            item["_source_file"] = path.name
            item["_provenance"] = {
                "profile": "lab",
                "source_id": "zeek_file_fallback",
                "source_allowlisted": False,
                "scope_match": None,
                "trusted_for_graph": False,
                "reason": "disabled-collector file fallback is inspection-only",
            }
            try:
                flow = telemetry_normalizer.normalize(item)
                item["normalized_flow"] = {
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "forward_packets": flow.forward_packets,
                    "reverse_packets": flow.reverse_packets,
                    "forward_bytes": flow.forward_bytes,
                    "reverse_bytes": flow.reverse_bytes,
                    "duration_seconds": flow.duration_seconds,
                    "timestamp": flow.timestamp,
                    "sensor_source": flow.sensor_source,
                    "feature_vector": flow.to_feature_vector().tolist(),
                }
            except (TypeError, ValueError, KeyError):
                item["normalized_flow"] = None
            records.append(item)
    records = records[-limit:]
    return {
        "available": bool(records), "records": records, "source": "mounted-file-fallback",
        "count": len(records),
        "provenance": {"profile": "lab", "trusted_for_graph": False, "inventory_promotion": False},
    }


@router.get("/device-profiles", response_model=List[dict])
async def device_profiles(current_user: dict = Depends(get_current_user)):
    """Return supported, versioned device capabilities for the planner."""
    return list_profiles()


@router.post("/intent/plan", response_model=dict)
async def intent_plan(body: IntentPlanRequest, current_user: dict = Depends(get_current_user)):
    """Compile a validated intent into a dry-run device plan.

    This endpoint intentionally does not connect to a device or execute
    commands. Application requires a device adapter, snapshot, policy check,
    and explicit execution workflow.
    """
    try:
        plan = build_intent_plan(platform=body.platform, intent=body.intent, parameters=body.parameters)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    plan["requested_by"] = current_user.get("sub", "unknown")
    return plan


@router.get("/metrics", response_model=NetworkMetrics)
async def network_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    assets = await db.scalar(select(func.count()).select_from(Asset))
    services = await db.scalar(select(func.count()).select_from(NetworkService))
    users = await db.scalar(select(func.count()).select_from(UserAccount))
    auths = await db.scalar(select(func.count()).select_from(AuthEvent))
    vulns = await db.scalar(select(func.count()).select_from(Vulnerability))
    crit_vulns = await db.scalar(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == "critical")
    )
    suspicious = await db.scalar(
        select(func.count()).select_from(Asset).where(Asset.status == AssetStatus.SUSPICIOUS)
    )
    compromised = await db.scalar(
        select(func.count()).select_from(Asset).where(Asset.status == AssetStatus.COMPROMISED)
    )
    return NetworkMetrics(
        assets=assets or 0,
        services=services or 0,
        users=users or 0,
        auth_events=auths or 0,
        vulnerabilities=vulns or 0,
        critical_vulnerabilities=crit_vulns or 0,
        suspicious_assets=suspicious or 0,
        compromised_assets=compromised or 0,
    )


@router.get("/state", response_model=NetworkStateResponse)
async def network_state(
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    services = (await db.execute(select(NetworkService).order_by(NetworkService.last_seen.desc()).limit(limit))).scalars().all()
    users = (await db.execute(select(UserAccount).order_by(UserAccount.last_seen.desc()).limit(limit))).scalars().all()
    auths = (await db.execute(select(AuthEvent).order_by(desc(AuthEvent.timestamp)).limit(limit))).scalars().all()
    vulns = (await db.execute(select(Vulnerability).order_by(desc(Vulnerability.discovered_at)).limit(limit))).scalars().all()
    asset_rows = (await db.execute(select(Asset))).scalars().all()

    suspicious = [
        {"id": str(a.id), "hostname": a.hostname, "status": a.status.value if hasattr(a.status, "value") else a.status,
         "threat_score": a.threat_score}
        for a in asset_rows if a.status in (AssetStatus.SUSPICIOUS, AssetStatus.COMPROMISED)
    ]
    from datetime import datetime
    return NetworkStateResponse(
        asset_count=len(asset_rows),
        services=[NetworkServiceResponse.model_validate(s) for s in services],
        users=[UserAccountResponse.model_validate(u) for u in users],
        auth_events=[AuthEventResponse.model_validate(x) for x in auths],
        vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in vulns],
        suspicious_assets=suspicious,
        distressed_assets=[a for a in suspicious],
        timestamp=datetime.utcnow(),
    )


@router.post("/services", response_model=NetworkServiceResponse, status_code=201)
async def create_service(
    body: NetworkServiceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    exists = await db.get(Asset, body.asset_id)
    if not exists:
        raise HTTPException(status_code=404, detail="Asset not found")
    obj = NetworkService(**body.model_dump())
    db.add(obj)
    await log_audit(db, actor=current_user.get("sub", "dev-user"), action="NETWORK_STATE",
                    target_type="network_service", summary=f"Registered service {body.name} on {body.asset_id}")
    await db.commit()
    await db.refresh(obj)
    return NetworkServiceResponse.model_validate(obj)


@router.get("/services", response_model=List[NetworkServiceResponse])
async def list_services(
    asset_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(NetworkService)
    if asset_id:
        query = query.where(NetworkService.asset_id == asset_id)
    query = query.order_by(desc(NetworkService.last_seen)).limit(200)
    rows = (await db.execute(query)).scalars().all()
    return [NetworkServiceResponse.model_validate(r) for r in rows]


@router.post("/users", response_model=UserAccountResponse, status_code=201)
async def create_user(
    body: UserAccountCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if not await db.get(Asset, body.asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    obj = UserAccount(**body.model_dump())
    db.add(obj)
    await log_audit(db, actor=current_user.get("sub", "dev-user"), action="NETWORK_STATE",
                    target_type="user_account", summary=f"Registered user {body.username}")
    await db.commit()
    await db.refresh(obj)
    return UserAccountResponse.model_validate(obj)


@router.get("/users", response_model=List[UserAccountResponse])
async def list_users(
    asset_id: Optional[UUID] = Query(None),
    privileged: Optional[bool] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(UserAccount)
    if asset_id:
        query = query.where(UserAccount.asset_id == asset_id)
    if privileged is not None:
        query = query.where(UserAccount.is_privileged == privileged)
    if status:
        query = query.where(UserAccount.status == status)
    query = query.order_by(desc(UserAccount.last_seen)).limit(200)
    rows = (await db.execute(query)).scalars().all()
    return [UserAccountResponse.model_validate(r) for r in rows]


@router.post("/auth-events", response_model=AuthEventResponse, status_code=201)
async def create_auth_event(
    body: AuthEventCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    obj = AuthEvent(**body.model_dump())
    db.add(obj)
    await db.commit()
    await db.refresh(obj)
    return AuthEventResponse.model_validate(obj)


@router.get("/auth-events", response_model=List[AuthEventResponse])
async def list_auth_events(
    asset_id: Optional[UUID] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(AuthEvent)
    if asset_id:
        query = query.where(AuthEvent.asset_id == asset_id)
    query = query.order_by(desc(AuthEvent.timestamp)).limit(limit)
    rows = (await db.execute(query)).scalars().all()
    return [AuthEventResponse.model_validate(r) for r in rows]


@router.post("/vulnerabilities", response_model=VulnerabilityResponse, status_code=201)
async def create_vulnerability(
    body: VulnerabilityCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if not await db.get(Asset, body.asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    obj = Vulnerability(**body.model_dump())
    db.add(obj)
    await log_audit(db, actor=current_user.get("sub", "dev-user"), action="NETWORK_STATE",
                    target_type="vulnerability", summary=f"Registered vulnerability {body.cve_id or body.title}")
    await db.commit()
    await db.refresh(obj)
    return VulnerabilityResponse.model_validate(obj)


@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    asset_id: Optional[UUID] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = select(Vulnerability)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    query = query.order_by(desc(Vulnerability.cvss_score)).limit(200)
    rows = (await db.execute(query)).scalars().all()
    return [VulnerabilityResponse.model_validate(r) for r in rows]
