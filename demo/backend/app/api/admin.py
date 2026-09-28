"""
Admin API: presenter-accessible controls (PIN-protected) for the live range:
start/reset incident, change scenario, inject telemetry, activate deception,
rollback state, list participants, clear demo logs.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from sqlalchemy import select, desc, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.models.demo import (
    DemoIncident, IncidentStatus, Participant, DemoEvent,
    PredictionRecord, DecoyInteraction, EvidenceRecord, Challenge,
    AssetRole, AssetStatus,
)
from app.services import simulation_engine as engine
from app.services.event_bus import bus

router = APIRouter()


def _check_pin(pin: Optional[str]) -> None:
    if not pin or pin != settings.DEMO_ADMIN_PIN:
        raise HTTPException(status_code=403, detail="Invalid admin PIN")


@router.post("/admin/start")
async def admin_start(db: AsyncSession = Depends(get_db),
                      x_demo_admin_pin: Optional[str] = Header(None)):
    _check_pin(x_demo_admin_pin)
    connected = await engine.connected_devices(db)
    await db.flush()
    return {"state": "ready", "devices": len(connected),
            "message": "No assets are pre-created — devices appear as they register and heartbeat."}


@router.post("/admin/reset")
async def admin_reset(clear_logs: bool = False, db: AsyncSession = Depends(get_db),
                      x_demo_admin_pin: Optional[str] = Header(None)):
    _check_pin(x_demo_admin_pin)
    result = await engine.reset_demo(db, clear_all=clear_logs)
    await db.flush()
    await bus.emit("admin_action", {"action": "reset", "state": "clean"}, source="admin")
    return result


@router.post("/admin/deception")
async def admin_deception(incident_id: Optional[str] = Query(None),
                          db: AsyncSession = Depends(get_db),
                          x_demo_admin_pin: Optional[str] = Header(None)):
    """Force-activate deception at the world model's predicted target.

    A decoy is only ever staged after the model has produced a prediction —
    never before one exists. Accepts an incident_id for multi-actor demos;
    falls back to the most recent active incident.
    """
    _check_pin(x_demo_admin_pin)
    incident = await engine.get_incident(db, incident_id) if incident_id else None
    if incident is None and not incident_id:
        incident = await engine.get_active_incident(db)
    if not incident:
        raise HTTPException(status_code=409, detail="No active incident")
    if not incident.predicted_target_id:
        raise HTTPException(
            status_code=409,
            detail="No prediction yet — a decoy can only be staged after the "
                   "world model predicts the next target")
    decoy = await engine.ensure_decoy_for_incident(db, incident)
    await db.flush()
    await bus.emit("deception_activated",
                   {"admin": True, "decoy": decoy.asset_id,
                    "predicted": incident.predicted_target_id},
                   source="admin", incident_id=incident.incident_id)
    return {"decoy": decoy.asset_id, "incident": incident.incident_id,
            "predicted_target": incident.predicted_target_id}


@router.post("/admin/rollback")
async def admin_rollback(incident_id: Optional[str] = Query(None),
                         db: AsyncSession = Depends(get_db),
                         x_demo_admin_pin: Optional[str] = Header(None)):
    """Roll an incident back to the previous stage (presenter teaching aid)."""
    _check_pin(x_demo_admin_pin)
    incident = await engine.get_incident(db, incident_id) if incident_id else None
    if incident is None and not incident_id:
        incident = await engine.get_active_incident(db)
    if not incident:
        raise HTTPException(status_code=409, detail="No active incident")
    order = ["reconnaissance", "discovery", "initial_access", "execution",
             "lateral_movement", "collection", "exfiltration", "impact"]
    idx = order.index(incident.stage) if incident.stage in order else 1
    incident.stage = order[max(0, idx - 1)]
    incident.simulation_level = max(1, incident.simulation_level - 1)
    if incident.status == IncidentStatus.DECEPTION:
        incident.status = IncidentStatus.ACTIVE
    await db.flush()
    await bus.emit("admin_action", {"action": "rollback", "stage": incident.stage},
                   source="admin", incident_id=incident.incident_id)
    return {"stage": incident.stage, "level": incident.simulation_level}


@router.get("/admin/participants")
async def admin_participants(db: AsyncSession = Depends(get_db),
                             x_demo_admin_pin: Optional[str] = Header(None)):
    _check_pin(x_demo_admin_pin)
    rows = (await db.execute(select(Participant).order_by(desc(Participant.created_at)))).scalars().all()
    return [
        {"participant_id": p.participant_id, "role": p.role.value,
         "status": p.status, "browser": p.device_context.get("browser"),
         "platform": p.device_context.get("platform"),
         "joined": p.created_at.isoformat(sep=" ", timespec="seconds")}
        for p in rows
    ]


@router.get("/admin/devices")
async def admin_devices(db: AsyncSession = Depends(get_db),
                        x_demo_admin_pin: Optional[str] = Header(None),
                        include_offline: bool = Query(False),
                        include_decoys: bool = Query(False)):
    """Registered physical devices for the presenter roster.

    Defaults to *online* physical devices only — stale offline join-history and
    synthetic honeypot/decoy nodes are excluded so the admin list stays usable
    during a live demo. Pass include_offline=true / include_decoys=true to widen.
    """
    _check_pin(x_demo_admin_pin)
    rows = await engine.list_assets(db)
    devices = []
    for a in rows:
        if a.role == AssetRole.DECOY and not include_decoys:
            continue
        if a.role == AssetRole.INFRA:
            continue
        if a.is_physical and not a.registered and a.role != AssetRole.DECOY:
            continue
        if a.status == AssetStatus.OFFLINE and not include_offline:
            continue
        devices.append({
            "asset_id": a.asset_id, "hostname": a.hostname, "role": a.role.value,
            "asset_type": a.asset_type, "ip": a.ip, "zone": a.zone,
            "status": a.status.value, "registered": a.registered,
            "page_endpoint": a.page_endpoint,
            "contained": a.status == AssetStatus.CONTAINED,
            "maintenance": engine._maintenance_info(a) if (a.meta or {}).get("maintenance") else None,
            "last_seen": a.last_seen.isoformat(sep=" ", timespec="seconds")
                if a.last_seen else None,
        })
    offline_total = sum(
        1 for a in rows
        if a.role != AssetRole.DECOY and a.role != AssetRole.INFRA
        and a.is_physical and a.registered and a.status == AssetStatus.OFFLINE
    )
    return {
        "devices": devices,
        "online": len(devices) if not include_offline else sum(
            1 for d in devices if d["status"] != AssetStatus.OFFLINE.value),
        "offline_total": offline_total,
        "include_offline": include_offline,
    }


@router.post("/admin/clear")
async def admin_clear(db: AsyncSession = Depends(get_db),
                      x_demo_admin_pin: Optional[str] = Header(None)):
    """Clear a run completely while preserving registered physical devices."""
    _check_pin(x_demo_admin_pin)
    # Deleting event rows alone left decoys and compromised assets in the
    # topology, so the next demo started from an inconsistent state. The reset
    # routine also removes incident-owned decoys and restores physical devices.
    result = await engine.reset_demo(db, clear_all=True, record_reset_event=False)
    await db.flush()
    await bus.emit("admin_action", {"action": "clear"}, source="admin")
    return {"cleared": True, **result}


@router.post("/admin/restore")
async def admin_restore(asset_id: str = Query(...),
                        incident_id: Optional[str] = Query(None),
                        force: bool = Query(False),
                        db: AsyncSession = Depends(get_db),
                        x_demo_admin_pin: Optional[str] = Header(None)):
    """Clean-and-restore a contained server from its last malware-free copy.

    Gated by maintenance: restore is only allowed once the server's diagnostics
    have passed (or with force=True for a presenter override). On restore the
    node is wiped, re-provisioned from the last clean snapshot, and re-snapshots
    a FRESH clean copy — the domain never drops a real serving replica.
    """
    _check_pin(x_demo_admin_pin)
    try:
        result = await engine.restore_server_from_backup(db, asset_id, incident_id,
                                                         force=force)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    await db.flush()
    await bus.emit("admin_action", {"action": "restore",
                                    "asset": asset_id,
                                    "snapshot": result.get("snapshot"),
                                    "force": force},
                   source="admin")
    return result


@router.post("/admin/maintenance/{asset_id}/diagnose")
async def admin_maintenance_diagnose(asset_id: str,
                                     db: AsyncSession = Depends(get_db),
                                     x_demo_admin_pin: Optional[str] = Header(None)):
    """Presenter help: (re)kick the diagnostics job for a contained server."""
    _check_pin(x_demo_admin_pin)
    asset = await engine.get_asset(db, asset_id.upper())
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not on the range")
    incident = await engine.get_active_incident(db)
    result = await engine._start_maintenance(db, asset, incident)
    await db.flush()
    await bus.emit("admin_action", {"action": "maintenance_diagnose",
                                    "asset": asset_id},
                   source="admin")
    return {"asset": asset_id, "job": result.get("job"), "status": "diagnosing"}


@router.post("/admin/maintenance/{asset_id}/release")
async def admin_maintenance_release(asset_id: str,
                                    db: AsyncSession = Depends(get_db),
                                    x_demo_admin_pin: Optional[str] = Header(None)):
    """Presenter override: mark maintenance recoverable (restore enabled)."""
    _check_pin(x_demo_admin_pin)
    asset = await engine.get_asset(db, asset_id.upper())
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not on the range")
    _m = dict((asset.meta or {}).get("maintenance") or {})
    _m.update(job="recoverable", recoverable=True,
              release_override=True,
              note="Presenter released this server from maintenance.")
    asset.meta = {**(asset.meta or {}), "maintenance": _m}
    await db.flush()
    await bus.emit("admin_action", {"action": "maintenance_release",
                                    "asset": asset_id},
                   source="admin")
    return {"asset": asset_id, "job": "recoverable", "restore_available": True}


@router.post("/admin/export-training")
async def admin_export_training(db: AsyncSession = Depends(get_db),
                                x_demo_admin_pin: Optional[str] = Header(None)):
    """Append every attack sample from the current run to the training set.

    Written outside the repo so demo runs stay removable while the attack data
    accumulates for the later model retrain (predictions, intel, telemetry,
    decoy sessions, challenge answers, actor correlations).
    """
    _check_pin(x_demo_admin_pin)
    result = await engine.export_training_samples(db)
    await bus.emit("admin_action", {"action": "export_training",
                                    "exported": result["exported"],
                                    "path": result["path"]}, source="admin")
    return result


@router.get("/admin/training")
async def admin_training_info(x_demo_admin_pin: Optional[str] = Header(None)):
    """Where the training samples live and how many are on file."""
    from pathlib import Path
    from app.core.config import settings
    _check_pin(x_demo_admin_pin)
    path = Path(settings.TRAINING_EXPORT_PATH)
    records = 0
    if path.exists():
        records = sum(1 for _ in path.open("r", encoding="utf-8"))
    return {"path": str(path), "exists": path.exists(), "records": records}


@router.post("/admin/ai/schema-scan")
async def schema_scan(background_tasks: BackgroundTasks,
                      x_demo_admin_pin: Optional[str] = Header(None)):
    """Fetch approved public JSON schema contracts into a review queue."""
    _check_pin(x_demo_admin_pin)
    from app.services.schema_intelligence import scan_schemas, status
    if status().get("status") == "running":
        return status()
    background_tasks.add_task(scan_schemas)
    await bus.emit("ai_schema_scan", {"status": "started", "source_count": 2}, source="admin")
    return {"status": "started", "message": "Fetching allow-listed public schema contracts; serving weights are unchanged."}


@router.post("/admin/ai/prepare-training")
async def prepare_training(db: AsyncSession = Depends(get_db),
                           x_demo_admin_pin: Optional[str] = Header(None)):
    """Create a candidate manifest from demo telemetry and reviewed schema metadata."""
    _check_pin(x_demo_admin_pin)
    result = await engine.export_training_samples(db)
    from app.services.schema_intelligence import prepare_training_manifest
    manifest = prepare_training_manifest(result["exported"])
    await bus.emit("ai_training_manifest", {"status": manifest["status"], "records": result["exported"]}, source="admin")
    return manifest


@router.post("/admin/ai/train")
async def train_ai(db: AsyncSession = Depends(get_db),
                   x_demo_admin_pin: Optional[str] = Header(None)):
    """Export the current demo telemetry and launch an isolated candidate retrain.

    The training command uses `--device auto`, so CUDA is preferred when
    available and CPU is used as the fallback automatically.
    """
    _check_pin(x_demo_admin_pin)
    from app.services import schema_intelligence
    from app.services.ai_training import build_training_plan, start_training

    exported = await engine.export_training_samples(db)
    schema_state = schema_intelligence.status()
    manifest = schema_intelligence.prepare_training_manifest(exported["exported"])

    from app.services.world_model_adapter import model_version, feature_dim
    plan = build_training_plan(
        exported["exported"],
        current_metrics={
            "model_version": model_version(),
            "stage_accuracy": None,
            "infiltration_accuracy": None,
            "macro_f1": None,
            "val_loss": None,
        },
        schema_scan=schema_state,
    )
    plan.update(
        manifest=manifest,
        current_model={
            "version": model_version(),
            "feature_dim": feature_dim(),
            "candidate_model_version": "flow-wm-v3.1-candidate",
        },
        epochs=8,
        max_rows=max(12000, min(60000, exported["exported"] * 150)),
    )
    state = start_training(plan)
    await bus.emit(
        "ai_training_started",
        {
            "status": state["status"],
            "records": exported["exported"],
            "device": state.get("device_preference", "auto"),
            "eta_minutes": state.get("eta_minutes"),
        },
        source="admin",
    )
    return state


@router.get("/admin/health")
async def admin_health(db: AsyncSession = Depends(get_db),
                       x_demo_admin_pin: Optional[str] = Header(None)):
    _check_pin(x_demo_admin_pin)
    from app.services.world_model_adapter import model_ready, model_version, feature_dim
    return {
        "demo_db": True,
        "world_model": model_ready(),
        "model_version": model_version(),
        "feature_dim": feature_dim(),
        "incidents": (await db.execute(select(func.count()).select_from(DemoIncident))).scalar_one(),
        "events": (await db.execute(select(func.count()).select_from(DemoEvent))).scalar_one(),
    }
