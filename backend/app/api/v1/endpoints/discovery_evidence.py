"""
Discovery Evidence and Device Identity API Endpoints (Phase 1)
Append-only evidence ingestion, device inventory, operator verification, and topology edges.
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.discovery_evidence import (
    DeviceIdentity,
    DiscoveryObservation,
    DeviceSnapshot,
    TopologyEdge,
    DeviceLifecycleStatus,
)
from app.models.syntax_template import VendorSyntaxTemplate
from app.schemas.discovery_evidence import (
    DiscoveryObservationCreate,
    DiscoveryObservationResponse,
    DeviceIdentityResponse,
    DeviceVerificationAction,
    DeviceSnapshotCreate,
    DeviceSnapshotResponse,
    TopologyEdgeCreate,
    TopologyEdgeResponse,
    VendorTelemetryIngestRequest,
    VerificationQueueItem,
)
from app.services.evidence_service import EvidenceService
from app.services.confidence_fusion import ConfidenceFusionEngine, DiscoveredSignal
from app.services.vendor_parsers import CiscoIosXeParser, JuniperJunosParser, AristaEosParser
from app.services.passive_network_observer import PassiveNetworkObserver
from app.services.discovery_profiler import DiscoverySyntaxProfiler

router = APIRouter(prefix="/evidence", tags=["discovery-evidence"])


@router.post("/syntax-templates/profile")
async def profile_syntax_source(
    vendor: str = Query(..., min_length=1, max_length=128),
    os_version: str = Query(..., min_length=1, max_length=128),
    source_url: str = Query(..., min_length=12, max_length=2048),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Acquire allowlisted vendor documentation into candidate templates."""
    roles = set(current_user.get("roles", [])) if isinstance(current_user, dict) else set()
    if isinstance(current_user, dict) and current_user.get("role"):
        roles.add(str(current_user["role"]))
    if not roles.intersection({"admin", "operator"}):
        raise HTTPException(status_code=403, detail="Operator profiling is required")
    try:
        result = await DiscoverySyntaxProfiler.profile_from_source(db, vendor.strip(), os_version.strip(), source_url.strip())
        await db.commit()
        return result
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=502, detail=f"Documentation profiling failed: {exc}")


@router.get("/syntax-templates")
async def list_syntax_templates(
    status: Optional[str] = Query(None, pattern="^(candidate|verified|rejected)$"),
    vendor: Optional[str] = Query(None, max_length=128),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List profiled command templates and their provenance state."""
    query = select(VendorSyntaxTemplate).order_by(VendorSyntaxTemplate.updated_at.desc())
    if status:
        query = query.where(VendorSyntaxTemplate.status == status)
    if vendor:
        query = query.where(VendorSyntaxTemplate.vendor.ilike(vendor.strip()))
    result = await db.execute(query.limit(200))
    return [
        {
            "id": row.id,
            "vendor": row.vendor,
            "os_version": row.os_version,
            "abstract_intent": row.abstract_intent,
            "status": row.status,
            "confidence": row.confidence,
            "generated_by": row.generated_by,
            "source_url": row.source_url,
            "source_hash": row.source_hash,
            "evidence_ref": row.evidence_ref,
            "updated_at": row.updated_at,
        }
        for row in result.scalars().all()
    ]


@router.post("/syntax-templates/{template_id}/verify")
async def verify_syntax_template(
    template_id: int,
    source_url: str = Query(..., min_length=8, max_length=2048),
    source_hash: str = Query(..., min_length=64, max_length=64),
    notes: Optional[str] = Query(None, max_length=1000),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Promote OSINT syntax only after an operator supplies source evidence.

    Candidate/fixture templates cannot be executed merely because profiling
    completed. Verification records provenance and the operator identity; the
    normal automation planner/canary still controls execution.
    """
    roles = set(current_user.get("roles", [])) if isinstance(current_user, dict) else set()
    if isinstance(current_user, dict) and current_user.get("role"):
        roles.add(str(current_user["role"]))
    if not roles.intersection({"admin", "operator"}):
        raise HTTPException(status_code=403, detail="Operator verification is required")
    if not all(c in "0123456789abcdefABCDEF" for c in source_hash):
        raise HTTPException(status_code=400, detail="source_hash must be hexadecimal SHA-256")
    result = await db.execute(select(VendorSyntaxTemplate).where(VendorSyntaxTemplate.id == template_id))
    template = result.scalars().first()
    if not template:
        raise HTTPException(status_code=404, detail="Syntax template not found")
    template.source_url = source_url
    template.source_hash = source_hash.lower()
    template.status = "verified"
    template.generated_by = f"operator:{current_user.get('sub', 'operator')}"
    template.evidence_ref = notes or template.evidence_ref
    template.confidence = max(float(template.confidence or 0.0), 0.90)
    await db.commit()
    return {
        "id": template.id,
        "status": template.status,
        "vendor": template.vendor,
        "os_version": template.os_version,
        "abstract_intent": template.abstract_intent,
        "verified_by": template.generated_by,
        "source_url": template.source_url,
        "source_hash": template.source_hash,
    }


@router.post("/observations", response_model=DiscoveryObservationResponse, status_code=201)
async def record_observation(
    obs_in: DiscoveryObservationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Append an immutable discovery observation record.
    Automatically resolves or correlates with a DeviceIdentity and updates fused confidence.
    """
    try:
        obs = await EvidenceService.record_observation(db, obs_in)
        await db.commit()
        await db.refresh(obs)
        return obs
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to record observation: {str(e)}")


@router.get("/observations", response_model=List[DiscoveryObservationResponse])
async def list_observations(
    device_id: Optional[UUID] = None,
    source: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Query append-only discovery observations with optional device and protocol filters.
    """
    q = select(DiscoveryObservation)
    if device_id:
        q = q.where(DiscoveryObservation.device_id == device_id)
    if source:
        q = q.where(DiscoveryObservation.source == source.lower().strip())
    q = q.order_by(desc(DiscoveryObservation.timestamp)).offset(offset).limit(limit)

    res = await db.execute(q)
    return res.scalars().all()


@router.get("/devices", response_model=List[DeviceIdentityResponse])
async def list_devices(
    status: Optional[str] = None,
    vendor: Optional[str] = None,
    role: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    List discovered and verified device identities.
    """
    q = select(DeviceIdentity)
    if status:
        q = q.where(DeviceIdentity.status == status.lower().strip())
    if vendor:
        q = q.where(DeviceIdentity.vendor == vendor)
    if role:
        q = q.where(DeviceIdentity.device_role == role.lower().strip())
    q = q.order_by(desc(DeviceIdentity.last_seen)).offset(offset).limit(limit)

    res = await db.execute(q)
    return res.scalars().all()


@router.get("/devices/{device_id}", response_model=DeviceIdentityResponse)
async def get_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve specific device identity by UUID.
    """
    q = select(DeviceIdentity).where(DeviceIdentity.id == device_id)
    res = await db.execute(q)
    device = res.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return device


@router.post("/devices/{device_id}/verify", response_model=DeviceIdentityResponse)
async def verify_device(
    device_id: UUID,
    action: DeviceVerificationAction,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Operator verification workflow: approve, reject, or merge a provisional device.
    """
    try:
        updated = await EvidenceService.verify_device_identity(db, device_id, action)
        await db.commit()
        await db.refresh(updated)
        return updated
    except ValueError as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.get("/devices/queue", response_model=List[VerificationQueueItem])
async def list_verification_queue(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Operator Verification Queue (Mode B — Verify).
    Lists provisional devices awaiting operator approval or flagged with discrepancies.
    """
    q = (
        select(DeviceIdentity)
        .where(DeviceIdentity.status == DeviceLifecycleStatus.PROVISIONAL.value)
        .order_by(desc(DeviceIdentity.last_seen))
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(q)
    devices = res.scalars().all()

    queue_items: List[VerificationQueueItem] = []
    for d in devices:
        q_obs = select(DiscoveryObservation).where(DiscoveryObservation.device_id == d.id)
        res_obs = await db.execute(q_obs)
        obs_list = res_obs.scalars().all()

        signals = [
            DiscoveredSignal(
                source=o.source,
                confidence=o.confidence,
                ip=o.normalized_fields.get("ip"),
                mac=o.normalized_fields.get("mac"),
                hostname=o.normalized_fields.get("hostname"),
                vendor=o.normalized_fields.get("vendor"),
                model=o.normalized_fields.get("model"),
                role=o.normalized_fields.get("role"),
            )
            for o in obs_list
        ]
        fusion = ConfidenceFusionEngine.fuse_signals(signals)

        queue_items.append(
            VerificationQueueItem(
                device=DeviceIdentityResponse.model_validate(d),
                observation_count=len(obs_list),
                sources=sorted(list({o.source for o in obs_list})),
                is_discrepant=fusion.is_discrepant,
                discrepancy_reasons=fusion.discrepancy_reasons,
                recommended_action=fusion.recommended_action,
            )
        )
    return queue_items


@router.post("/devices/{device_id}/approve", response_model=DeviceIdentityResponse)
async def approve_device(
    device_id: UUID,
    notes: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Operator fast-approve endpoint promoting device to verified status.
    """
    action = DeviceVerificationAction(
        action="approve",
        verified_by=current_user.get("username", "operator") if isinstance(current_user, dict) else "operator",
        notes=notes,
    )
    updated = await EvidenceService.verify_device_identity(db, device_id, action)
    await DiscoverySyntaxProfiler.profile_verified_device(
        db, updated.vendor, updated.os_version
    )
    await db.commit()
    await db.refresh(updated)
    return updated


@router.post("/devices/{device_id}/reject", response_model=DeviceIdentityResponse)
async def reject_device(
    device_id: UUID,
    notes: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Operator reject endpoint marking device as rejected.
    """
    action = DeviceVerificationAction(
        action="reject",
        verified_by=current_user.get("username", "operator") if isinstance(current_user, dict) else "operator",
        notes=notes,
    )
    updated = await EvidenceService.verify_device_identity(db, device_id, action)
    await db.commit()
    await db.refresh(updated)
    return updated


@router.post("/devices/passive-local")
async def discover_passive_local(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Safe Mode A (Observe Only): inspects local kernel ARP cache and route tables,
    cross-corroborates OUI and reverse DNS, and ingests provisional records with zero active probing.
    """
    try:
        discovered = await PassiveNetworkObserver.ingest_passive_neighbors(db)
        return {
            "status": "success",
            "count": len(discovered),
            "discovered_devices": discovered,
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Passive observation failed: {str(e)}")


@router.post("/telemetry/vendor-cli")
async def ingest_vendor_cli(
    req: VendorTelemetryIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Parse multi-vendor CLI outputs (Cisco IOS-XE, Juniper Junos, Arista EOS)
    and record append-only evidence observations and snapshots.
    """
    vendor = req.vendor.lower().strip()
    cmd = req.command_type.lower().strip()
    text = req.raw_cli_output

    parsed_data: Dict[str, Any] = {}
    if vendor == "cisco":
        if cmd == "show_version":
            facts = CiscoIosXeParser.parse_show_version(text)
            parsed_data = {"model": facts.model, "os_version": facts.os_version, "serial": facts.serial_number, "hostname": facts.hostname}
        elif cmd == "show_neighbors":
            nbrs = CiscoIosXeParser.parse_show_cdp_neighbors(text)
            parsed_data = {"neighbors": [n.__dict__ for n in nbrs]}
        elif cmd == "show_vlan":
            vlans = CiscoIosXeParser.parse_show_vlan(text)
            parsed_data = {"vlans": [v.__dict__ for v in vlans]}
        elif cmd == "show_route":
            routes = CiscoIosXeParser.parse_show_ip_route(text)
            parsed_data = {"routes": [r.__dict__ for r in routes]}
    elif vendor == "juniper":
        if cmd == "show_version":
            facts = JuniperJunosParser.parse_show_version(text)
            parsed_data = {"model": facts.model, "os_version": facts.os_version, "hostname": facts.hostname}
        elif cmd == "show_neighbors":
            nbrs = JuniperJunosParser.parse_show_lldp_neighbors(text)
            parsed_data = {"neighbors": [n.__dict__ for n in nbrs]}
        elif cmd == "show_vlan":
            vlans = JuniperJunosParser.parse_show_vlans(text)
            parsed_data = {"vlans": [v.__dict__ for v in vlans]}
        elif cmd == "show_route":
            routes = JuniperJunosParser.parse_show_route(text)
            parsed_data = {"routes": [r.__dict__ for r in routes]}
    elif vendor == "arista":
        if cmd == "show_version":
            facts = AristaEosParser.parse_show_version(text)
            parsed_data = {"model": facts.model, "os_version": facts.os_version, "serial": facts.serial_number, "mac": facts.mac_address}
        elif cmd == "show_neighbors":
            nbrs = AristaEosParser.parse_show_lldp_neighbors(text)
            parsed_data = {"neighbors": [n.__dict__ for n in nbrs]}
        elif cmd == "show_vlan":
            vlans = AristaEosParser.parse_show_vlan(text)
            parsed_data = {"vlans": [v.__dict__ for v in vlans]}
        elif cmd == "show_route":
            routes = AristaEosParser.parse_show_ip_route(text)
            parsed_data = {"routes": [r.__dict__ for r in routes]}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported vendor: {vendor}")

    obs_in = DiscoveryObservationCreate(
        source=f"cli_{vendor}_{cmd}",
        collector="vendor_cli_adapter",
        raw_evidence_ref=f"cli_{vendor}_{cmd}",
        normalized_fields={
            "vendor": vendor,
            "ip": req.target_ip,
            "mac": req.target_mac,
            **parsed_data,
        },
        confidence=0.95,
        operator_id=req.operator_id,
    )
    obs = await EvidenceService.record_observation(db, obs_in)
    await db.commit()
    await db.refresh(obs)
    return {
        "status": "success",
        "observation_id": str(obs.id),
        "device_id": str(obs.device_id) if obs.device_id else None,
        "parsed_data": parsed_data,
    }



@router.post("/snapshots", response_model=DeviceSnapshotResponse, status_code=201)
async def capture_snapshot(
    snapshot_in: DeviceSnapshotCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Capture point-in-time device state and interface snapshot.
    """
    try:
        snapshot = await EvidenceService.capture_device_snapshot(db, snapshot_in)
        await db.commit()
        await db.refresh(snapshot)
        return snapshot
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to capture snapshot: {str(e)}")


@router.get("/snapshots/{device_id}", response_model=List[DeviceSnapshotResponse])
async def list_device_snapshots(
    device_id: UUID,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    List point-in-time snapshots for a device.
    """
    q = (
        select(DeviceSnapshot)
        .where(DeviceSnapshot.device_id == device_id)
        .order_by(desc(DeviceSnapshot.collected_at))
        .limit(limit)
    )
    res = await db.execute(q)
    return res.scalars().all()


@router.post("/topology-edges", response_model=TopologyEdgeResponse, status_code=201)
async def reconcile_edge(
    edge_in: TopologyEdgeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Reconcile or register an evidence-backed topology edge.
    """
    try:
        edge = await EvidenceService.reconcile_topology_edge(db, edge_in)
        await db.commit()
        await db.refresh(edge)
        return edge
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to reconcile edge: {str(e)}")


@router.get("/topology-edges", response_model=List[TopologyEdgeResponse])
async def list_topology_edges(
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    List evidence-backed topology edges.
    """
    q = select(TopologyEdge)
    if status:
        q = q.where(TopologyEdge.status == status.lower().strip())
    q = q.order_by(desc(TopologyEdge.last_confirmed)).limit(limit)
    res = await db.execute(q)
    return res.scalars().all()


@router.post("/reconcile-stale")
async def retire_stale(
    device_ttl_hours: int = Query(72, ge=1),
    edge_ttl_hours: int = Query(48, ge=1),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Run retirement maintenance cycle marking inactive devices and edges as retired/stale.
    """
    result = await EvidenceService.retire_stale_records(db, device_ttl_hours, edge_ttl_hours)
    await db.commit()
    return result
