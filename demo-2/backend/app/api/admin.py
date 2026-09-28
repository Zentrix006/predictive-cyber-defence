"""
Admin API: presenter-accessible controls (PIN-protected) for the live range:
start/reset incident, change scenario, inject telemetry, activate deception,
rollback state, list participants, clear demo logs.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from sqlalchemy import select, desc, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.models.demo import (
    DemoIncident, IncidentStatus, Participant, DemoEvent,
    PredictionRecord, DecoyInteraction, EvidenceRecord, Challenge,
    AssetRole, AssetStatus, DemoAsset, ThreatActor,
)
from app.services import simulation_engine as engine
from app.services.event_bus import bus

router = APIRouter()


def _check_pin(pin: Optional[str]) -> None:
    """Elevated demo range: presenter actions are intentionally PIN-free.

    Demo-2 is an isolated simulation-only cyber-range with no real secrets in
    its endpoints, so every admin action is always permitted. (The main
    platform and the older demo/ stack keep their own PIN checks.) The header
    is still accepted for compatibility with older presenter clients.
    """
    return None


@router.post("/admin/start")
async def admin_start(db: AsyncSession = Depends(get_db),
                      x_demo_admin_pin: Optional[str] = Header(None)):
    _check_pin(x_demo_admin_pin)
    connected = await engine.connected_devices(db)
    await db.flush()
    return {"state": "ready", "devices": len(connected),
            "message": "No assets are pre-created — devices appear as they register and heartbeat."}


@router.post("/admin/scenario/inject")
async def admin_scenario_inject(
    body: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    x_demo_admin_pin: Optional[str] = Header(None)
):
    """
    Directly inject an active presentation scenario into the demo range,
    synchronizing incidents, actors, topology nodes, predictions, and Honeynet decoys
    across all demo-2 workspaces (Command Center, Attack Forecast, Threat Actors, Deception, Forensics).
    """
    _check_pin(x_demo_admin_pin)
    scenario_id = body.get("scenario_id", "ransomware")
    now = datetime.utcnow()

    # Define scenario properties
    if scenario_id == "dns_exfil":
        inc_id = "INC-DNS-EXFIL"
        actor_name = "APT-COVERT-DNS"
        stage = "collection"
        origin_id = "WORKSTATION-77"
        origin_ip = "192.168.1.77"
        target_id = "DNS-DMZ"
        target_name = "DNS Server (DMZ)"
        target_ip = "192.168.1.53"
        decoy_id = "HONEYNET-DNS-SINKHOLE"
        decoy_ip = "10.0.9.53"
        action = "DECEPTION_DIVERT"
        risk_score = 92.5
        risk_reduction = 92.5
        surprisal = 0.612
        predicted_stages = ["exfiltration", "command_and_control"]
        kernel_rule = "nft add rule inet filter forward ip saddr 192.168.1.77 udp dport 53 dnat to 10.0.9.53"
    elif scenario_id == "ddos_syn":
        inc_id = "INC-DDOS-SYN"
        actor_name = "DISTRIBUTED-BOTNET"
        stage = "discovery"
        origin_id = "ROUTER-WAN-EDGE"
        origin_ip = "192.168.1.1"
        target_id = "WEB-CLUSTER"
        target_name = "Web-Cluster (Prod)"
        target_ip = "192.168.1.20"
        decoy_id = "HONEYNET-TARPIT"
        decoy_ip = "10.0.9.99"
        action = "RATE_LIMIT"
        risk_score = 78.0
        risk_reduction = 76.8
        surprisal = 0.285
        predicted_stages = ["denial_of_service", "impact"]
        kernel_rule = "nft add rule inet filter input ip saddr 192.168.1.0/24 tcp dport 80 limit rate over 50/second drop"
    else:  # ransomware
        inc_id = "INC-RANSOMWARE"
        actor_name = "APT-FIN7-MIMIKATZ"
        stage = "lateral_movement"
        origin_id = "DMZ-PIVOT-01"
        origin_ip = "192.168.1.105"
        target_id = "DC-PROD"
        target_name = "DC-PROD (Enterprise DC)"
        target_ip = "192.168.1.10"
        decoy_id = "HONEYNET-DIONAEA"
        decoy_ip = "10.0.9.10"
        action = "DECEPTION_DIVERT"
        risk_score = 88.0
        risk_reduction = 84.0
        surprisal = 0.420
        predicted_stages = ["credential_access", "privilege_escalation", "impact"]
        kernel_rule = "nft add rule inet nat prerouting ip saddr 192.168.1.105 dport 445 dnat to 10.0.9.10"

    # 1. Origin asset
    origin_asset = (await db.execute(select(DemoAsset).where(DemoAsset.asset_id == origin_id))).scalar_one_or_none()
    if not origin_asset:
        origin_asset = DemoAsset(
            asset_id=origin_id,
            hostname=origin_id,
            role=AssetRole.SERVER,
            ip=origin_ip,
            zone="user_zone" if "WORK" in origin_id else "dmz",
            status=AssetStatus.UNDER_ATTACK,
            is_physical=False,
            registered=True,
            last_seen=now,
        )
        db.add(origin_asset)
    else:
        origin_asset.status = AssetStatus.UNDER_ATTACK
        origin_asset.last_seen = now

    # 2. Target asset
    target_asset = (await db.execute(select(DemoAsset).where(DemoAsset.asset_id == target_id))).scalar_one_or_none()
    if not target_asset:
        target_asset = DemoAsset(
            asset_id=target_id,
            hostname=target_name,
            role=AssetRole.SERVER,
            ip=target_ip,
            zone="server_zone",
            status=AssetStatus.HEALTHY,
            is_physical=False,
            registered=True,
            last_seen=now,
        )
        db.add(target_asset)
    else:
        target_asset.status = AssetStatus.HEALTHY
        target_asset.last_seen = now

    # 3. Decoy Honeynet asset
    decoy_asset = (await db.execute(select(DemoAsset).where(DemoAsset.asset_id == decoy_id))).scalar_one_or_none()
    if not decoy_asset:
        decoy_asset = DemoAsset(
            asset_id=decoy_id,
            hostname=decoy_id,
            role=AssetRole.DECOY,
            ip=decoy_ip,
            zone="honeynet",
            status=AssetStatus.DECOY,
            service="dionaea" if "DIONAEA" in decoy_id else "dns_sinkhole",
            is_physical=False,
            registered=True,
            last_seen=now,
        )
        db.add(decoy_asset)
    else:
        decoy_asset.status = AssetStatus.DECOY
        decoy_asset.last_seen = now

    # 4. Upsert DemoIncident
    inc = (await db.execute(select(DemoIncident).where(DemoIncident.incident_id == inc_id))).scalar_one_or_none()
    if not inc:
        inc = DemoIncident(
            incident_id=inc_id,
            scenario=scenario_id,
            status=IncidentStatus.DECEPTION,
            stage=stage,
            simulation_level=3,
            origin_asset_id=origin_id,
            predicted_target_id=target_id,
            predicted_target_name=target_name,
            deception_activated=True,
            decoy_asset_id=decoy_id,
            attacker=actor_name,
            meta={"pivot_count": 2, "scenario_id": scenario_id},
        )
        db.add(inc)
    else:
        inc.status = IncidentStatus.DECEPTION
        inc.stage = stage
        inc.origin_asset_id = origin_id
        inc.predicted_target_id = target_id
        inc.predicted_target_name = target_name
        inc.deception_activated = True
        inc.decoy_asset_id = decoy_id
        inc.attacker = actor_name
        inc.meta = {"pivot_count": 2, "scenario_id": scenario_id}

    # 5. Insert PredictionRecord
    pred = PredictionRecord(
        incident_id=inc_id,
        actor_id=actor_name,
        model_version="flow-wm-v3.0.0",
        horizon=4,
        current_stage=stage,
        predicted_stages=predicted_stages,
        predicted_target=target_name,
        predicted_target_id=target_id,
        confidence=0.91,
        risk_score=risk_score,
        risk_level="critical" if risk_score > 80 else "high",
        lead_time_seconds=18.4,
        belief={
            "branches": [
                {"branch": 1, "terminal_stage": "impact", "peak_infil_risk": 98.0, "recommended_action": "MONITOR"},
                {"branch": 2, "terminal_stage": "lateral_movement", "peak_infil_risk": 64.0, "recommended_action": "RATE_LIMIT"},
                {"branch": 3, "terminal_stage": "credential_access", "peak_infil_risk": 42.0, "recommended_action": "ISOLATE_HOST"},
                {"branch": 4, "terminal_stage": "exfiltration", "peak_infil_risk": 22.0, "recommended_action": "CONTAIN_AND_DECEIVE"},
                {"branch": 5, "terminal_stage": "deception_trapped", "peak_infil_risk": 14.0, "recommended_action": action},
            ],
            "worst_case": {"branch": 1, "terminal_stage": "impact", "peak_infil_risk": 98.0},
            "consensus_stage": stage,
            "consensus_confidence": 0.91,
            "model_decision": {
                "action": action,
                "action_type": action,
                "risk_reduction_pct": risk_reduction,
                "jepa_surprisal": surprisal,
                "is_novel_behavior": True,
                "decision_confidence": 0.91,
                "target_stage": stage,
                "branches_evaluated": 5,
                "rollback_armed": True,
                "vendor_diff": kernel_rule,
            }
        },
        explanation={
            "summary": f"G-FLOWWM simulated 5 counterfactual futures for {actor_name}. {action} autonomously selected with +{risk_reduction}% risk reduction.",
            "top_features": [
                {"name": "shannon_entropy", "importance": 0.42},
                {"name": "latent_surprisal", "importance": 0.38},
                {"name": "supernode_flow_burst", "importance": 0.20},
            ]
        }
    )
    db.add(pred)

    # 6. Insert Comprehensive Evidence Records
    evidence_items = [
        EvidenceRecord(
            evidence_id=f"EV-{scenario_id}-1",
            incident_id=inc_id,
            evidence_type="network_pcap",
            source="network_tap",
            payload={
                "name": f"{scenario_id}_recon_lateral_capture.pcap",
                "evidence_type": "network_pcap",
                "description": f"High-entropy PCAP trace containing Kerberos ticket requests and lateral movement probes from {origin_ip}.",
                "size_bytes": 418290,
                "sha256_hash": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
                "collection_method": "automated_tap",
                "packet_count": 1420,
            },
            simulation=True,
        ),
        EvidenceRecord(
            evidence_id=f"EV-{scenario_id}-2",
            incident_id=inc_id,
            evidence_type="honeynet_telemetry",
            source="honeynet_agent",
            payload={
                "name": f"{scenario_id}_honeynet_sandbox_steer.json",
                "evidence_type": "honeynet_telemetry",
                "description": f"Atomic nftables kernel redirection event. Adversary diverted to isolated honeypot sandbox ({decoy_id}) before reaching {target_id}.",
                "size_bytes": 18450,
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "collection_method": "honeynet_agent",
                "decoy_id": decoy_id,
                "trapped_ip": origin_ip,
            },
            simulation=True,
        ),
        EvidenceRecord(
            evidence_id=f"EV-{scenario_id}-3",
            incident_id=inc_id,
            evidence_type="policy_enforcement",
            source="kernel_nftables",
            payload={
                "name": f"{scenario_id}_kernel_nftables_rule.log",
                "evidence_type": "policy_enforcement",
                "description": f"Kernel policy commit: {kernel_rule}. Action: {action} with +{risk_reduction}% risk reduction.",
                "size_bytes": 4120,
                "sha256_hash": "d41d8cd98f00b204e9800998ecf8427e9a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c",
                "collection_method": "kernel_nftables",
                "rule": kernel_rule,
                "action": action,
                "risk_reduction": risk_reduction,
            },
            simulation=True,
        ),
        EvidenceRecord(
            evidence_id=f"EV-{scenario_id}-4",
            incident_id=inc_id,
            evidence_type="memory_forensics",
            source="edr_sensor",
            payload={
                "name": f"{scenario_id}_quarantined_payload.bin",
                "evidence_type": "memory_forensics",
                "description": f"Quarantined execution payload harvested by Honeynet sandbox from {actor_name}.",
                "size_bytes": 1048576,
                "sha256_hash": "c5a0b7289d0b64d1f5e8f41539e083c6d6a578912e9a3a14e912ab92c2b3e4f5",
                "collection_method": "edr_sensor",
                "process_name": "suricata" if scenario_id == "dns_exfil" else "impacket-psexec",
            },
            simulation=True,
        ),
    ]
    for ev in evidence_items:
        db.add(ev)

    # 6b. Insert Chronological DemoEvents for Live Timeline Stream
    step_events = [
        ("reconnaissance", f"Adversary Reconnaissance: Port sweep across enterprise DMZ ({origin_ip})", "reconnaissance", origin_id, "critical"),
        ("lateral_movement", f"Adversary Lateral Movement: Vector detected toward {target_name} via {origin_id}", stage, origin_id, "critical"),
        ("model_forecast", f"G-FLOWWM Anticipation: Predicted pivot to {target_name} (Confidence: 91%, Surprisal: {surprisal} nats)", "prediction", actor_name, "high"),
        ("mitigation_committed", f"Kernel Enforcement: Autonomic {action} rule committed (+{risk_reduction}% risk reduction)", "containment", decoy_id, "high"),
        ("decoy_trapped", f"Adversary Honeynet Trapped: Inbound threat sinkholed into {decoy_id}. Zero impact on {target_id}.", "deception", decoy_id, "high"),
    ]
    for idx, (kind, title, stg, asset, sev) in enumerate(step_events):
        event_time = now - timedelta(seconds=(len(step_events) - idx) * 4)
        evt = DemoEvent(
            event_id=uuid.uuid4().hex[:12],
            kind=kind,
            timestamp=event_time,
            incident_id=inc_id,
            simulation=True,
            source="G-FLOWWM" if "model" in kind else "kernel_nftables" if "mitigation" in kind else "attacker_stream",
            payload={
                "title": title,
                "description": title,
                "stage": stg,
                "severity": sev,
                "actor": actor_name,
                "actor_id": actor_name,
                "asset_id": asset,
                "scenario_id": scenario_id,
            }
        )
        db.add(evt)

    await db.flush()

    # 7. Broadcast across event bus
    forecast_payload = {
        "incident_id": inc_id,
        "current_stage": stage,
        "current_confidence": 0.91,
        "recommended_action": action,
        "predicted_stages": predicted_stages,
        "predicted_targets": [{"asset_id": target_id, "asset_name": target_name, "confidence": 0.91}],
        "model_decision": pred.belief["model_decision"],
        "belief": pred.belief,
    }
    await bus.emit("incident_created", {"incident_id": inc_id, "stage": stage, "attacker": actor_name}, source="simulation")
    await bus.emit("forecast_updated", forecast_payload, source="simulation")
    await bus.emit("model_decision_executed", {"incident_id": inc_id, "model_decision": pred.belief["model_decision"], "forecast": forecast_payload}, source="simulation")
    await bus.emit("deception_activated", {"incident_id": inc_id, "decoy": decoy_id, "predicted": target_id}, source="simulation")

    return {
        "status": "injected",
        "scenario": scenario_id,
        "incident_id": inc_id,
        "actor": actor_name,
        "action": action,
        "target": target_name,
        "decoy": decoy_id,
        "risk_reduction": risk_reduction,
    }


@router.post("/admin/reset")
async def admin_reset(clear_logs: bool = False, db: AsyncSession = Depends(get_db),
                      x_demo_admin_pin: Optional[str] = Header(None)):
    _check_pin(x_demo_admin_pin)
    result = await engine.reset_demo(db, clear_all=clear_logs)
    await db.flush()
    await bus.emit("admin_action", {"action": "reset", "state": "clean"}, source="admin")
    return result


@router.post("/admin/clear-debris")
async def admin_clear_debris(db: AsyncSession = Depends(get_db),
                             x_demo_admin_pin: Optional[str] = Header(None)):
    """Clear post-attack debris while preserving devices and evidence.

    This is the presenter-facing cleanup after an attacker has been trapped or
    ejected: remove temporary deception nodes, resolve live incidents, restore
    physical devices to healthy, and keep the forensic ledger intact.
    """
    _check_pin(x_demo_admin_pin)
    result = await engine.reset_demo(db, clear_all=False)
    await db.flush()
    await bus.emit("admin_action", {
        "action": "clear_debris",
        "state": "clean",
        "evidence": "preserved",
    }, source="admin")
    return {"cleared": True, "evidence": "preserved", **result}


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


@router.get("/admin/attacker-intelligence/{actor_id}")
async def attacker_intelligence(actor_id: str, db: AsyncSession = Depends(get_db),
                                x_demo_admin_pin: Optional[str] = Header(None)):
    """Presenter-only local identity and action history for one demo actor."""
    _check_pin(x_demo_admin_pin)
    incident = (await db.execute(
        select(DemoIncident).where(DemoIncident.attacker == actor_id)
        .order_by(desc(DemoIncident.started_at)).limit(1)
    )).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Attacker record not found")
    events = (await db.execute(
        select(DemoEvent).where(DemoEvent.incident_id == incident.incident_id)
        .order_by(DemoEvent.timestamp).limit(200)
    )).scalars().all()
    return {
        "actor": actor_id,
        "incident_id": incident.incident_id,
        "state": incident.status.value,
        "stage": incident.stage,
        "identity": (incident.meta or {}).get("attacker_identity", {}),
        "activity": [{"at": event.timestamp.isoformat(timespec="seconds"),
                      "kind": event.kind, "payload": event.payload}
                     for event in events],
    }


# Evidence kinds that matter when telling an attacker's story to the audience.
CRUCIAL_EVIDENCE_KINDS = (
    "attack_initiated", "attacker_intel", "attacker_captured", "bait_deployed",
    "deception", "containment", "prediction", "restore_plan", "attacker_telemetry",
    "attacker_identity_observed", "attacker_pivoted", "service_error_404",
    "honeypot_http_hit",
)


@router.get("/admin/attacker-dossier/{actor_id}")
async def attacker_dossier(actor_id: str, db: AsyncSession = Depends(get_db),
                           x_demo_admin_pin: Optional[str] = Header(None)):
    """Crucial-evidence dossier for one attacker, across ALL their engagements.

    Built to survive archiving: it works from the evidence ledger and prediction
    records (which are retained forever), not from live state, so a presenter can
    open a captured attacker's dossier after the device has left the range.
    """
    _check_pin(x_demo_admin_pin)
    incidents = (await db.execute(
        select(DemoIncident).where(DemoIncident.attacker == actor_id)
        .order_by(desc(DemoIncident.started_at)).limit(50)
    )).scalars().all()
    if not incidents:
        raise HTTPException(status_code=404, detail="Attacker record not found")

    dossier: List[Dict[str, Any]] = []
    for inc in incidents:
        evidence_rows = (await db.execute(
            select(EvidenceRecord)
            .where(EvidenceRecord.incident_id == inc.incident_id)
            .order_by(EvidenceRecord.created_at)
            .limit(300)
        )).scalars().all()
        crucial = [e for e in evidence_rows if e.evidence_type in CRUCIAL_EVIDENCE_KINDS]
        decoy_evidence = [e for e in crucial if e.evidence_type in
                          ("attacker_captured", "attacker_telemetry")]
        predictions = (await db.execute(
            select(PredictionRecord)
            .where(PredictionRecord.incident_id == inc.incident_id)
            .order_by(desc(PredictionRecord.created_at)).limit(5)
        )).scalars().all()
        archive = (inc.meta or {}).get("archive") or {}
        dossier.append({
            "incident_id": inc.incident_id,
            "started_at": inc.started_at.isoformat(timespec="seconds"),
            "status": inc.status.value,
            "stage": inc.stage,
            "origin": inc.origin_asset_id,
            "predicted_target": inc.predicted_target_name,
            "decoy": inc.decoy_asset_id,
            "trapped": bool((inc.meta or {}).get("trapped")),
            "archived": bool(archive),
            "archive_reason": archive.get("reason"),
            # Timeline of the story: start -> handshakes -> pivot -> capture.
            "timeline": [{
                "evidence_id": e.evidence_id,
                "type": e.evidence_type,
                "source": e.source,
                "at": e.created_at.isoformat(timespec="seconds"),
                "payload": e.payload,
            } for e in crucial],
            "handshakes": sum(1 for e in crucial if e.evidence_type == "attacker_intel"),
            "honeypot_touches": len(decoy_evidence),
            "predictions": [{
                "model": p.model_version,
                "stages": p.predicted_stages,
                "target": p.predicted_target,
                "confidence": p.confidence,
                "risk_level": p.risk_level,
                "at": p.created_at.isoformat(timespec="seconds"),
            } for p in predictions],
        })

    latest = incidents[0]
    return {
        "actor": actor_id,
        "identity": (latest.meta or {}).get("attacker_identity", {}),
        "engagements": dossier,
        "totals": {
            "engagements": len(dossier),
            "crucial_evidence": sum(len(e["timeline"]) for e in dossier),
            "handshakes": sum(e["handshakes"] for e in dossier),
            "honeypot_touches": sum(e["honeypot_touches"] for e in dossier),
            "captured": sum(1 for e in dossier if e["trapped"]),
        },
    }


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


@router.post("/admin/devices/purge")
async def admin_devices_purge(db: AsyncSession = Depends(get_db),
                              x_demo_admin_pin: Optional[str] = Header(None)):
    """Remove every registered device row (sample/test devices included).

    Reset deliberately keeps device registrations so a demo can restart with
    the same audience; this endpoint is the harder eraser used between demo
    days. It removes ALL physical device rows plus every synthetic decoy, and
    closes any live incident. Heartbeating browser tabs re-register themselves
    on their next beat, so genuinely-present devices come straight back.
    """
    _check_pin(x_demo_admin_pin)
    removed = await engine.purge_devices(db)
    await db.flush()
    await bus.emit("admin_action", {"action": "devices_purged",
                                    "removed": removed}, source="admin")
    return {"purged": True, "removed": removed}


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
