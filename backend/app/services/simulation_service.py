"""
Safe Simulation Mode

Builds a clearly-labelled demonstration scenario so the UI can showcase the full
OBSERVE -> PREDICT -> DECIDE -> CONTAIN -> DECEIVE -> COLLECT -> LEARN loop.

SIMULATION mode NEVER touches external systems, and every row created is tagged
with `simulation: True` so it is unmistakably demo data.
"""
from datetime import datetime, timedelta
from typing import Dict, List
from uuid import UUID, uuid4

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset, AssetType, AssetStatus, ZoneType, CriticalityLevel, IsolationLevel
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, AttackStage, TimelineEvent
from app.models.network import NetworkService, UserAccount, AuthEvent, Vulnerability
from app.models.threat import ThreatActor, ThreatTrajectory, ActorResponseState
from app.models.deception import HoneypotInstance, HoneypotType, HoneypotStatus
from app.models.forensics import Evidence, EvidenceType, FileEvent, FileEventAction, EvidenceCustodyEvent
from app.models.config_snapshot import ConfigSnapshot
from app.models.response import PolicyDecision, ResponseAction, ResponseActionType, ActionStatus
from app.models.prediction import Prediction, ForecastWindow, PredictedTarget
from app.services.audit_service import log_audit

# Module-level simulation registry (survives restart as a flag; data rows carry
# simulation metadata for discovery).
SIMULATION_STATE: Dict[str, object] = {"active": False, "incident_id": None, "scenario": "multi-actor-intrusion", "started_at": None}
SIMULATION_TAG = "simulation"


async def is_simulation_active() -> bool:
    return SIMULATION_STATE.get("active", False)


async def find_simulation_incident(db: AsyncSession):
    """Find a simulation incident in the DB (survives backend restarts)."""
    result = await db.execute(
        select(Incident).where(Incident.metadata_["simulation"].astext == "true").limit(1)
    )
    return result.scalar_one_or_none()


def _sim_assets() -> List[dict]:
    """Defines the simulated network topology."""
    return [
        {"hostname": "EDGE-FW-01", "ip": "10.0.0.1", "type": AssetType.FIREWALL, "zone": ZoneType.DMZ, "crit": CriticalityLevel.HIGH, "os": "pfsense"},
        {"hostname": "CORE-SW-01", "ip": "10.0.0.2", "type": AssetType.SWITCH, "zone": ZoneType.SERVER_ZONE, "crit": CriticalityLevel.HIGH, "os": "ios-xe"},
        {"hostname": "WEB-01", "ip": "10.0.1.10", "type": AssetType.WEB_SERVER, "zone": ZoneType.DMZ, "crit": CriticalityLevel.HIGH, "os": "linux", "status": AssetStatus.SUSPICIOUS},
        {"hostname": "APP-01", "ip": "10.0.2.11", "type": AssetType.SERVER, "zone": ZoneType.SERVER_ZONE, "crit": CriticalityLevel.HIGH, "os": "linux"},
        {"hostname": "APP-02", "ip": "10.0.2.12", "type": AssetType.SERVER, "zone": ZoneType.SERVER_ZONE, "crit": CriticalityLevel.MEDIUM, "os": "linux"},
        {"hostname": "APP-03", "ip": "10.0.2.13", "type": AssetType.SERVER, "zone": ZoneType.SERVER_ZONE, "crit": CriticalityLevel.HIGH, "os": "linux", "status": AssetStatus.COMPROMISED},
        {"hostname": "DB-02", "ip": "10.0.3.20", "type": AssetType.DATABASE, "zone": ZoneType.SERVER_ZONE, "crit": CriticalityLevel.CRITICAL, "os": "linux"},
        {"hostname": "VPN-GW-01", "ip": "10.0.4.30", "type": AssetType.ROUTER, "zone": ZoneType.DMZ, "crit": CriticalityLevel.HIGH, "os": "linux"},
        {"hostname": "WS-01", "ip": "10.0.5.40", "type": AssetType.WORKSTATION, "zone": ZoneType.USER_ZONE, "crit": CriticalityLevel.MEDIUM, "os": "windows"},
    ]


def _sim_honeypots() -> List[dict]:
    return [
        {"name": "HNY-SSH-01", "type": HoneypotType.SSH, "os": "linux", "status": HoneypotStatus.DORMANT, "ip": "10.0.9.10", "ports": [22], "services": ["ssh"]},
        {"name": "HNY-WEB-01", "type": HoneypotType.WEB, "os": "linux", "status": HoneypotStatus.DORMANT, "ip": "10.0.9.11", "ports": [80, 443], "services": ["http", "https"]},
        {"name": "HNY-DB-01", "type": HoneypotType.DATABASE, "os": "linux", "status": HoneypotStatus.DORMANT, "ip": "10.0.9.12", "ports": [3306], "services": ["mysql"]},
        {"name": "HNY-SMB-01", "type": HoneypotType.SMB, "os": "windows", "status": HoneypotStatus.DORMANT, "ip": "10.0.9.13", "ports": [445], "services": ["smb"]},
        {"name": "HNY-IOT-01", "type": HoneypotType.IOT, "os": "linux", "status": HoneypotStatus.DORMANT, "ip": "10.0.9.14", "ports": [1883], "services": ["mqtt"]},
    ]


async def start_simulation(db: AsyncSession) -> Dict:
    """Create the simulated scenario. Returns a summary (never fake production data)."""
    existing = await find_simulation_incident(db)
    if existing:
        SIMULATION_STATE["active"] = True
        SIMULATION_STATE["incident_id"] = existing.id
        SIMULATION_STATE["scenario"] = "multi-actor-intrusion"
        SIMULATION_STATE["started_at"] = existing.created_at
        raise RuntimeError("Simulation already running; stop it first to re-seed.")

    now = datetime.utcnow()

    incident = Incident(
        title="SIMULATION: Multi-actor intrusion scenario",
        description="Clearly-labelled SIMULATION DATA demonstrating the predictive defence loop.",
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.OPEN,
        current_stage=AttackStage.LATERAL_MOVEMENT,
        threat_score=0.82,
        tags=[SIMULATION_TAG, "demo"],
        metadata_={"simulation": True, "demo": True},
        detected_at=now - timedelta(minutes=4),
    )
    db.add(incident)
    await db.flush()

    # --- assets -----------------------------------------------------------
    asset_ids: Dict[str, str] = {}
    for a in _sim_assets():
        obj = Asset(
            hostname=a["hostname"],
            ip_address=a["ip"],
            asset_type=a["type"],
            zone=a["zone"],
            criticality=a["crit"],
            os=a["os"],
            status=a.get("status", AssetStatus.NORMAL),
            threat_score=0.9 if a.get("status") == AssetStatus.COMPROMISED else (
                0.55 if a.get("status") == AssetStatus.SUSPICIOUS else 0.05
            ),
            incident_id=incident.id,
            tags=[SIMULATION_TAG],
            metadata_={"simulation": True},
            last_seen=now,
        )
        db.add(obj)
        await db.flush()
        asset_ids[a["hostname"]] = str(obj.id)

    # services / users / vulnerabilities / auth events ------------------------
    services = [
        (asset_ids["WEB-01"], "http", 80, "nginx/1.24"),
        (asset_ids["WEB-01"], "https", 443, "nginx/1.24"),
        (asset_ids["APP-03"], "ssh", 22, "openssh"),
        (asset_ids["APP-03"], "rpc", 135, None),
        (asset_ids["DB-02"], "mysql", 3306, "mysql-8.0"),
        (asset_ids["VPN-GW-01"], "ike", 500, None),
        (asset_ids["VPN-GW-01"], "ssh", 22, "openssh"),
    ]
    for host, name, port, version in services:
        db.add(NetworkService(asset_id=UUID(host), name=name, port=port, version=version, first_seen=now, last_seen=now))

    db.add(UserAccount(asset_id=UUID(asset_ids["APP-03"]), username="svc_webapp", is_privileged=True, last_login=now - timedelta(minutes=2)))
    db.add(UserAccount(asset_id=UUID(asset_ids["APP-03"]), username="root", is_privileged=True, last_login=now - timedelta(minutes=8)))
    db.add(UserAccount(asset_id=UUID(asset_ids["DB-02"]), username="db_read", is_privileged=False, last_login=now - timedelta(minutes=3)))

    now_ts = now
    for i in range(6):
        db.add(AuthEvent(asset_id=UUID(asset_ids["APP-03"]), username="svc_webapp", src_ip="185.220.101.5",
                         success=(i % 3 != 0), auth_method="password", timestamp=now_ts - timedelta(minutes=6 - i)))
    db.add(AuthEvent(asset_id=UUID(asset_ids["VPN-GW-01"]), username="admin", src_ip="64.62.197.10", success=False,
                     auth_method="password", timestamp=now_ts - timedelta(minutes=3)))

    db.add(Vulnerability(asset_id=UUID(asset_ids["APP-03"]), cve_id="CVE-2021-44228", title="Log4Shell RCE",
                         severity="critical", cvss_score=10.0, status="open", discovered_at=now - timedelta(days=3)))
    db.add(Vulnerability(asset_id=UUID(asset_ids["WEB-01"]), cve_id="CVE-2023-44487", title="HTTP/2 rapid reset",
                         severity="high", cvss_score=7.5, status="open", discovered_at=now - timedelta(days=10)))

    # --- threat actors -------------------------------------------------------
    actor_specs = [
        ("A-001", "185.220.101.5", asset_ids["APP-03"], "APP-03", AttackStage.CREDENTIAL_ACCESS, AttackStage.LATERAL_MOVEMENT, asset_ids["DB-02"], "DB-02", 0.91, 0.93),
        ("A-002", "64.62.197.10", asset_ids["VPN-GW-01"], "VPN-GW-01", AttackStage.INITIAL_ACCESS, AttackStage.CREDENTIAL_ACCESS, asset_ids["APP-01"], "APP-01", 0.73, 0.66),
        ("A-003", "203.0.113.77", asset_ids["WEB-01"], "WEB-01", AttackStage.DISCOVERY, AttackStage.LATERAL_MOVEMENT, asset_ids["APP-02"], "APP-02", 0.61, 0.58),
    ]
    actor_rows: List[ThreatActor] = []
    for disp, src, cur_id, cur_name, cst, pst, tgt_id, tgt_name, conf, risk in actor_specs:
        actor = ThreatActor(
            display_id=disp,
            incident_id=incident.id,
            first_seen=now - timedelta(minutes=9),
            last_seen=now,
            source_observations=[{"source": src, "evidence": "auth failures + SMB enumeration"}],
            correlated_sources=[src],
            current_asset_id=UUID(cur_id),
            current_asset_name=cur_name,
            current_stage=cst,
            predicted_stage=pst,
            predicted_target_id=UUID(tgt_id) if tgt_id else None,
            predicted_target_name=tgt_name,
            confidence=conf,
            risk_score=risk,
            response_state=ActorResponseState.TRACKING,
            metadata_={"simulation": True},
        )
        db.add(actor)
        await db.flush()
        actor_rows.append(actor)
        db.add(ThreatTrajectory(
            actor_id=actor.id, incident_id=incident.id, observed_source=src, src_ip=src,
            current_asset_id=UUID(cur_id), current_asset_name=cur_name, current_stage=cst,
            predicted_stage=pst, predicted_target_id=UUID(tgt_id) if tgt_id else None,
            predicted_target_name=tgt_name, confidence=conf, risk_score=risk,
            evidence=[{"type": "flow", "detail": f"suspicious flow to {cur_name}"}],
            timestamp=now - timedelta(minutes=2),
        ))

    # --- honeypot pool ---------------------------------------------------------
    hp_pool: List[HoneypotInstance] = []
    for h in _sim_honeypots():
        inst = HoneypotInstance(
            name=h["name"], honeypot_type=h["type"], os=h["os"], status=h["status"],
            ip_address=h["ip"], location="honeynet", ports=h["ports"], services=h["services"],
            telemetry_sources={"sessions": True, "commands": True, "decoys": 8},
            risk_profile={"value": "high.deception"},
            metadata_={"simulation": True},
        )
        db.add(inst)
        await db.flush()
        hp_pool.append(inst)

    # --- prediction (labelled simulation) ---------------------------------------
    stages_chain = [AttackStage.CREDENTIAL_ACCESS, AttackStage.LATERAL_MOVEMENT, AttackStage.COLLECTION, AttackStage.EXFILTRATION]
    pred = Prediction(
        incident_id=incident.id,
        current_stage=AttackStage.CREDENTIAL_ACCESS,
        current_confidence=0.89,
        model_version="flow-wm-v3.0.0",
        generated_at=now - timedelta(minutes=1),
        horizon=4,
        timeline=[
            {"window_offset": i + 1, "stage": s.value, "probability": round(0.95 - 0.07 * i, 3),
             "confidence": round(0.9 - 0.04 * i, 3), "eta_seconds": 30.0 * (i + 1)}
            for i, s in enumerate(stages_chain)
        ],
        predicted_targets=[
            {"asset_id": asset_ids["DB-02"], "asset_name": "DB-02", "asset_type": "database",
             "probability": 0.87, "reasoning": ["SMB to DB subnet", "DB reachable from APP-03"]}
        ],
        explanation={"feature_importance": {"ct_dst_ltm": 0.34, "spkts": 0.21}, "top_factors": [],
                     "natural_language": "SIMULATION forecast", "attention_visualization": {}},
    )
    db.add(pred)
    await db.flush()
    for i, s in enumerate(stages_chain):
        db.add(ForecastWindow(prediction_id=pred.id, window_offset=i + 1, stage=s,
                              probability=round(0.95 - 0.07 * i, 3), target_asset_id=UUID(asset_ids["DB-02"]),
                              target_asset_name="DB-02", eta_seconds=30.0 * (i + 1), confidence=round(0.9 - 0.04 * i, 3)))
    db.add(PredictedTarget(prediction_id=pred.id, asset_id=UUID(asset_ids["DB-02"]), asset_name="DB-02",
                           asset_type="database", probability=0.87, reasoning=["targeted"]))

    # --- policy + response actions ------------------------------------------------
    policy = PolicyDecision(
        incident_id=incident.id, prediction_id=pred.id, risk_score=88.5, risk_level="high",
        confidence=0.89, recommended_action=ResponseActionType.CONTAIN_AND_DECEIVE,
        rationale="Two trajectories converging on DB-02 (simulated).", rule_id="deceive-critical-target",
        requires_human_approval=True, approved=True, approved_by="sim-admin",
        approved_at=now, timestamp=now - timedelta(seconds=50),
    )
    db.add(policy)
    action = ResponseAction(
        incident_id=incident.id, action_type=ResponseActionType.CONTAIN_AND_DECEIVE,
        status=ActionStatus.VERIFIED, requested_by="simulation", requires_human_approval=True,
        approved_by="sim-admin", approved_timestamp=now - timedelta(seconds=40),
        executed_timestamp=now - timedelta(seconds=30), verified_timestamp=now - timedelta(seconds=28),
        asset_ids=[UUID(asset_ids["APP-03"])], simulation=True,
        details={"mode": "simulation"},
        result={"verified": True, "mode": "simulation"},
    )
    db.add(action)
    await db.flush()

    # --- config snapshots -----------------------------------------------------------
    db.add(ConfigSnapshot(incident_id=incident.id, label="sim-pre-incident", description="SIMULATION",
                          snapshot_type="pre_incident", configuration={"vlan": {"APP-03": 20}},
                          sha256_hash="sim" + "0" * 61, created_at=now - timedelta(seconds=45)))
    db.add(ConfigSnapshot(incident_id=incident.id, label="sim-quarantine", description="SIMULATION",
                          snapshot_type="containment", configuration={"vlan": {"APP-03": 90, "DB-02": 90}},
                          sha256_hash="sim" + "1" * 61, created_at=now - timedelta(seconds=25)))

    # --- evidence + custody + file events ---------------------------------------------
    ev = Evidence(
        incident_id=incident.id, evidence_type=EvidenceType.PCAP, name="sim-eth0.pcap",
        description="SIMULATION capture", source_asset_id=UUID(asset_ids["APP-03"]),
        size_bytes=2048576, sha256_hash="a" * 64, collection_method="simulation",
        storage_path="/evidence/sim", is_verified=True, metadata_={"simulation": True},
    )
    db.add(ev)
    await db.flush()
    db.add(EvidenceCustodyEvent(evidence_id=ev.id, event="collected", custodian="simulation",
                                timestamp=now - timedelta(seconds=20), notes="SIMULATION data"))
    db.add(FileEvent(incident_id=incident.id, asset_id=UUID(asset_ids["APP-03"]), file_path="/opt/app/users.csv",
                     action=FileEventAction.DISCOVERED, timestamp=now - timedelta(minutes=2),
                     process_name="find", user="svc_webapp", metadata_={"simulation": True}))
    db.add(FileEvent(incident_id=incident.id, asset_id=UUID(asset_ids["APP-03"]), file_path="/opt/app/backup.tar.gz",
                     action=FileEventAction.COPIED, timestamp=now - timedelta(minutes=1),
                     process_name="tar", user="svc_webapp", was_copied=True, metadata_={"simulation": True}))

    # --- timeline -------------------------------------------------------------------------
    timeline_spec = [
        (now - timedelta(minutes=9), "suspicious_activity", "Suspicious RDP/SMB scanning from 185.220.101.5", "low"),
        (now - timedelta(minutes=6), "threat_detected", "Threat trajectory A-001 correlated from 3 sources", "high"),
        (now - timedelta(minutes=1), "prediction_generated", "K-step forecast: APP-03 -> DB-02 (0.87)", "high"),
        (now - timedelta(seconds=50), "policy_decision", "Policy decision: CONTAIN_AND_DECEIVE (human approval)", "high"),
        (now - timedelta(seconds=40), "approval", "Containment approved by sim-admin", "medium"),
        (now - timedelta(seconds=30), "containment", "APP-03 quarantined (simulated)", "high"),
        (now - timedelta(seconds=25), "deception_activated", "HNY-DB-01 activated in honeynet zone", "medium"),
        (now - timedelta(seconds=20), "evidence_collected", "PCAP + file audit collected for incident", "medium"),
        (now, "model_updated", "World model updated with new telemetry (simulated)", "low"),
    ]
    for ts, etype, title, sev in timeline_spec:
        db.add(TimelineEvent(incident_id=incident.id, timestamp=ts, event_type=etype, title=title,
                             description=title, severity=sev, source="simulation", asset_ids=[], metadata_={"simulation": True}))

    SIMULATION_STATE["active"] = True
    SIMULATION_STATE["incident_id"] = incident.id
    SIMULATION_STATE["scenario"] = "multi-actor-intrusion"
    SIMULATION_STATE["started_at"] = datetime.utcnow()
    await log_audit(db, actor="simulation", action="SIMULATION_START", target_type="incident",
                    target_id=incident.id, summary="Started simulation scenario",
                    details={"incident_id": str(incident.id)})
    await db.commit()

    return {
        "active": True,
        "scenario": SIMULATION_STATE["scenario"],
        "incident_id": str(incident.id),
        "started_at": str(SIMULATION_STATE["started_at"]),
        "label": "SIMULATION DATA",
        "assets": len(_sim_assets()),
        "actors": len(actor_rows),
        "honeypots": len(hp_pool),
        "message": "Simulation data generated and clearly labelled.",
    }


async def stop_simulation(db: AsyncSession) -> Dict:
    """Remove all simulation data. DB returns to a clean state."""
    sim_incidents = await db.execute(select(Incident).where(Incident.metadata_["simulation"].astext == "true"))
    incident_ids = [i.id for i in sim_incidents.scalars().all()]

    if incident_ids:
        # network-state rows tied to simulation assets
        sim_asset_ids = (await db.execute(
            select(Asset.id).where(Asset.incident_id.in_(incident_ids))
        )).scalars().all()
        if sim_asset_ids:
            await db.execute(delete(AuthEvent).where(AuthEvent.asset_id.in_(sim_asset_ids)))
            await db.execute(delete(UserAccount).where(UserAccount.asset_id.in_(sim_asset_ids)))
            await db.execute(delete(NetworkService).where(NetworkService.asset_id.in_(sim_asset_ids)))
            await db.execute(delete(Vulnerability).where(Vulnerability.asset_id.in_(sim_asset_ids)))
        # assets tied to simulation incidents
        await db.execute(delete(Asset).where(Asset.incident_id.in_(incident_ids)))
        # cascade should handle incident children via FK ondelete; delete incidents last
        await db.execute(delete(Incident).where(Incident.id.in_(incident_ids)))

    # orphaned network-state rows left behind by earlier cleanup rounds
    for model in (AuthEvent, UserAccount, NetworkService, Vulnerability):
        await db.execute(delete(model).where(
            model.asset_id.not_in(select(Asset.id))
        ))

    # orphaned simulation honeypots / custody marked via metadata
    await db.execute(delete(HoneypotInstance).where(HoneypotInstance.metadata_["simulation"].astext == "true"))

    SIMULATION_STATE["active"] = False
    SIMULATION_STATE["incident_id"] = None
    SIMULATION_STATE["started_at"] = None
    await log_audit(db, actor="simulation", action="SIMULATION_STOP",
                    summary="Stopped simulation mode and removed demo data")
    await db.commit()
    return {"active": False, "removed_incidents": len(incident_ids), "message": "Simulation data removed."}