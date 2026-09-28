"""
Demo simulation engine.
State machine that replays a controlled attack through the UXH pipeline:
attacker action -> simulated telemetry -> world model -> risk/policy ->
containment -> deception -> interaction -> forensics.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, desc, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.runtime import challenges
from app.models.demo import (
    DemoAsset, AssetStatus, AssetRole,
    DemoIncident, IncidentStatus,
    Challenge, DemoEvent, PredictionRecord, DecoyInteraction,
    EvidenceRecord, Participant, ParticipantRole,
    ThreatActor, ThreatTrajectory, ActorCorrelation,
)
from app.services import world_model_adapter
from app.services.risk_policy import compute_risk, policy_decision
from app.services.event_bus import bus
from app.services.network_identity import resolve_network_identity
from app.services import deception_edge as edge

log = logging.getLogger("demo.engine")


def _uid(prefix: str = "EV") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}"


def _now_ms() -> int:
    return int(time.time() * 1000)


async def _emit(db, kind: str, payload: Dict, source: str = "system",
                incident_id: str | None = None) -> DemoEvent:
    event = await bus.emit(kind, payload, source=source, incident_id=incident_id)
    row = DemoEvent(
        event_id=event["event_id"],
        kind=kind,
        timestamp=datetime.utcnow(),
        incident_id=incident_id,
        simulation=True,
        source=source,
        payload=payload,
    )
    db.add(row)
    return row


async def _add_evidence(db, incident_id: str, evidence_type: str, payload: Dict,
                        source: str = "system") -> EvidenceRecord:
    ev = EvidenceRecord(
        evidence_id=_uid("EVID"),
        incident_id=incident_id,
        evidence_type=evidence_type,
        source=source,
        payload=payload,
        simulation=True,
    )
    db.add(ev)
    return ev


async def get_active_incident(db: AsyncSession) -> Optional[DemoIncident]:
    res = await db.execute(
        select(DemoIncident)
        .where(DemoIncident.status != IncidentStatus.RESOLVED)
        .order_by(desc(DemoIncident.started_at))
        .limit(1)
    )
    return res.scalar_one_or_none()


async def list_active_incidents(db: AsyncSession) -> List[DemoIncident]:
    """All currently non-resolved incidents (multi-actor engagements)."""
    res = await db.execute(
        select(DemoIncident)
        .where(DemoIncident.status != IncidentStatus.RESOLVED)
        .order_by(DemoIncident.started_at)
    )
    return list(res.scalars().all())


async def active_incident_for_participant(db: AsyncSession, participant_id: str) -> Optional[DemoIncident]:
    res = await db.execute(
        select(DemoIncident)
        .where(DemoIncident.status != IncidentStatus.RESOLVED,
               DemoIncident.attacker == participant_id)
        .order_by(desc(DemoIncident.started_at))
        .limit(1)
    )
    return res.scalar_one_or_none()


async def get_incident(db: AsyncSession, incident_id: str) -> Optional[DemoIncident]:
    res = await db.execute(
        select(DemoIncident).where(DemoIncident.incident_id == incident_id)
    )
    return res.scalar_one_or_none()


async def get_asset(db: AsyncSession, asset_id: str) -> Optional[DemoAsset]:
    res = await db.execute(select(DemoAsset).where(DemoAsset.asset_id == asset_id))
    return res.scalar_one_or_none()


async def list_assets(db: AsyncSession) -> List[DemoAsset]:
    res = await db.execute(select(DemoAsset).order_by(DemoAsset.asset_id))
    return list(res.scalars().all())


# Device roles that can join the range as a physical node. `observer` and
# `attacker` are participants only — they never become assets.
DEVICE_ROLES = {"server", "host", "client", "other"}
ROLE_PREFIX = {"server": "SERVER", "host": "HOST", "client": "CLIENT", "other": "NODE"}
ROLE_ASSET_TYPE = {"server": "application-server", "host": "workstation",
                   "client": "client", "other": "device"}
ROLE_CRITICALITY = {"server": "high", "host": "medium", "client": "low", "other": "medium"}


async def _next_device_id(db: AsyncSession, role: str) -> str:
    """Next free sequential device id.

    Uses the HIGHEST existing numeric suffix + 1 (not a row count) so that
    previously deleted ids are never reused; e.g. after SERVER-21/22 are wiped,
    SERVER-27 is still minted next rather than colliding with a surviving row.
    """
    prefix = ROLE_PREFIX.get(role, "NODE")
    res = await db.execute(select(DemoAsset.asset_id).where(DemoAsset.asset_id.like(f"{prefix}-%")))
    mx = 0
    for a in list(res.scalars().all()):
        tail = a.rsplit("-", 1)[-1]
        if tail.isdigit():
            mx = max(mx, int(tail))
    return f"{prefix}-{mx + 1:02d}"


async def register_device(db: AsyncSession, *, hostname: str, role: str = "other",
                          ip: Optional[str] = None, device_type: Optional[str] = None,
                          page_endpoint: Optional[str] = None,
                          asset_id: Optional[str] = None,
                          participant_id: Optional[str] = None) -> DemoAsset:
    """Register (or refresh) a physical device on the range.

    Nothing is pre-created: the device's identity is supplied over the wire at
    registration time (QR/join flow or explicit /device/register call), and the
    asset only exists because that device declared it. No registry = no device.
    """
    role = (role or "other").lower()
    if role not in DEVICE_ROLES:
        role = "other"
    role_enum = AssetRole(role)

    a = None
    if asset_id:
        a = await get_asset(db, asset_id.upper())
    if a is None:
        device_type = device_type or ROLE_ASSET_TYPE.get(role, "device")
        a = DemoAsset(
            asset_id=asset_id.upper() if asset_id else await _next_device_id(db, role),
            hostname=hostname or f"device-{uuid.uuid4().hex[:4].upper()}",
            role=role_enum,
            asset_type=device_type,
            ip=ip,
            zone="lan",
            status=AssetStatus.HEALTHY,
            criticality=ROLE_CRITICALITY.get(role, "medium"),
            service={"server": "Application Server", "host": "Workstation",
                     "client": "Client", "other": "Device"}.get(role),
            is_physical=True,
            registered=True,
            page_endpoint=page_endpoint,
            last_seen=datetime.utcnow(),
            meta={"owner": participant_id} if participant_id else {},
        )
        db.add(a)
        await db.flush()
        await ensure_clean_backup(db, a)
        await db.flush()
        await _emit(db, "device_registered", {
            "asset_id": a.asset_id, "name": a.hostname, "role": a.role.value,
            "ip": a.ip, "type": a.asset_type,
        }, source="device")
    else:
        a.role = role_enum
        if hostname:
            a.hostname = hostname
        if device_type:
            a.asset_type = device_type
        if ip:
            a.ip = ip
        if page_endpoint:
            a.page_endpoint = page_endpoint
        a.registered = True
        a.is_physical = True
        a.last_seen = datetime.utcnow()
        if a.status == AssetStatus.OFFLINE:
            a.status = AssetStatus.HEALTHY
        await db.flush()
    return a


async def device_heartbeat(db: AsyncSession, *, asset_id: Optional[str],
                           hostname: Optional[str] = None, ip: Optional[str] = None,
                           page_endpoint: Optional[str] = None,
                           device_type: Optional[str] = None) -> DemoAsset:
    a = await get_asset(db, asset_id.upper()) if asset_id else None
    if a is None:
        # A heartbeat without a resolvable asset id must NOT mint an unbounded
        # device farm every few seconds (a stale device tab or an external
        # monitor can otherwise turn one host into hundreds of NODE-xxx rows).
        # Dedupe by hostname first: re-adopt a matching physical device that is
        # offline or unattached, otherwise fall back to a single registration.
        if hostname:
            res = await db.execute(select(DemoAsset).where(
                DemoAsset.hostname == hostname).limit(1))
            candidate = res.scalar_one_or_none()
            if candidate is not None and candidate.role not in (
                    AssetRole.DECOY, AssetRole.INFRA):
                a = candidate
        if a is None:
            return await register_device(
                db, hostname=hostname or "device", role="other", ip=ip,
                device_type=device_type, page_endpoint=page_endpoint)
    a.last_seen = datetime.utcnow()
    a.registered = True
    a.is_physical = True
    if hostname:
        a.hostname = hostname
    if ip:
        a.ip = ip
    if page_endpoint:
        a.page_endpoint = page_endpoint
    if device_type:
        a.asset_type = device_type
    if a.status == AssetStatus.OFFLINE:
        a.status = AssetStatus.HEALTHY
        await _emit(db, "device_online", {"asset_id": a.asset_id, "name": a.hostname},
                    source="device")
    await db.flush()
    if a.role == AssetRole.SERVER and a.status == AssetStatus.HEALTHY:
        await ensure_clean_backup(db, a)
        await db.flush()
    return a


async def connected_devices(db: AsyncSession) -> List[DemoAsset]:
    """Physical, registered devices seen recently. Decoys/infra are never nodes."""
    rows = await list_assets(db)
    now = datetime.now(timezone.utc)
    timeout = timedelta(seconds=settings.DEMO_HEARTBEAT_TIMEOUT)
    dirty = False
    out: List[DemoAsset] = []
    for a in rows:
        if a.role in (AssetRole.DECOY, AssetRole.INFRA) or not a.is_physical:
            continue
        last_seen = a.last_seen
        if isinstance(last_seen, datetime) and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if last_seen and (now - last_seen) > timeout and a.status != AssetStatus.OFFLINE:
            a.status = AssetStatus.OFFLINE
            dirty = True
        if a.status == AssetStatus.OFFLINE:
            continue
        out.append(a)
    if dirty:
        await db.flush()
    return out


async def archive_stale_incidents(db: AsyncSession, live_asset_ids: set[str]) -> int:
    """Close stale live engagements without deleting their evidence.

    A live incident without a heartbeating physical origin is misleading on the
    command floor. It is archived (resolved with an explicit reason) so its
    predictions, evidence and actor history remain available to Forensics.

    The archived engagement's transient deception assets (decoy twins, segment
    baits, and — when no engagement remains — the honeypot replica farm) are
    removed as well, so honeypots never accumulate beyond what the current
    story needs. Forensic records are unaffected.
    """
    incidents = await list_active_incidents(db)
    archived = 0
    for incident in incidents:
        if incident.origin_asset_id in live_asset_ids:
            continue
        # Preserve executive presentation and simulated scenarios
        if (incident.meta or {}).get("scenario_id") or incident.scenario in ("ransomware", "dns_exfil", "ddos_syn", "presentation"):
            continue
        # A trapped engagement's origin is the honeypot decoy (never a
        # heartbeating device), so "device left the range" is meaningless for
        # it — the attacker may still be interacting inside the honeynet. It
        # stays live until reset or an explicit resolve.
        if _is_trapped(incident):
            continue
        incident.status = IncidentStatus.RESOLVED
        incident.meta = {**(incident.meta or {}), "archive": {
            "reason": "origin device left the live range",
            "archived_at": datetime.utcnow().isoformat(),
        }}
        archived += 1
        await _emit(db, "incident_archived", {
            "reason": "origin device left the live range",
            "origin": incident.origin_asset_id,
        }, source="system", incident_id=incident.incident_id)
    if archived:
        # Honeypot hygiene: drop transient deception nodes that no live
        # engagement references any more. The replica farm is range
        # infrastructure while ANY engagement is live; with none live it goes
        # too, so the next demo starts from a clean segment.
        remaining = await list_active_incidents(db)
        referenced: set[str] = set()
        for inc in remaining:
            if inc.decoy_asset_id:
                referenced.add(inc.decoy_asset_id)
            referenced.update((inc.meta or {}).get("baits", []))
            monitoring = (inc.meta or {}).get("monitoring") or {}
            if monitoring.get("decoy"):
                referenced.add(monitoring["decoy"])
        decoys = (await db.execute(
            select(DemoAsset).where(DemoAsset.role == AssetRole.DECOY))).scalars().all()
        removed = 0
        for decoy in decoys:
            # The farm survives only while some engagement is live.
            farm = decoy.meta and decoy.meta.get("kind") == "honeypot_farm"
            if decoy.asset_id in referenced:
                continue
            if farm and remaining:
                continue
            await db.delete(decoy)
            removed += 1
        if removed:
            await _emit(db, "deception_assets_cleared", {
                "removed": removed,
                "reason": "engagements archived; honeypots returned to pool",
            }, source="simulation")
        await db.flush()
    return archived


def _challenge_options(chall: Challenge) -> List[Dict]:
    """Attacker-friendly answer options derived from the challenge's schema.

    Each option carries an opaque `id` the client echoes back as the answer, so
    the attacker is never shown the real level mapping (that stays server-side).
    The first listed value in the schema is the level-3 / strongest option so a
    naive "select the first" attacker still advances the demo.
    """
    opts = []
    for spec in (chall.answer_schema or []):
        val = str(spec.get("value", ""))
        if not val:
            continue
        tag = spec.get("tag") or spec.get("hint") or _option_tag(val)
        opts.append({"id": val, "value": val, "label": f"{val} — {tag}"})
    return opts


def _option_tag(value: str) -> str:
    lowered = value.lower().strip()
    if "http" in lowered or "tcp" in lowered or "protocol" in lowered:
        return "networking"
    if "dns" in lowered or "domain" in lowered or "hostname" in lowered or "packet" in lowered:
        return "resolution"
    if "osi" in lowered or "rout" in lowered or "network" in lowered:
        return "OSI model"
    if any(c.isdigit() for c in lowered):
        return "arithmetic"
    return "technique"


async def start_attack(db: AsyncSession, participant: Participant, target_id: str) -> Dict:
    if participant.role != ParticipantRole.ATTACKER:
        raise ValueError("Only attacker participants may start an attack")
    # Multi-actor: each attacker runs their own engagement. Only block if this
    # attacker already has a live incident — other attackers may act in parallel.
    mine = await active_incident_for_participant(db, participant.participant_id)
    if mine:
        raise ValueError("You already have an active engagement — reset or resolve it first")

    connected = await connected_devices(db)
    servers = [asset for asset in connected if asset.role == AssetRole.SERVER]
    lateral_hosts = [asset for asset in connected if asset.asset_id != target_id.upper()]
    if len(connected) < 2 or not servers or not lateral_hosts:
        raise ValueError(
            "Lateral-movement demo requires two live physical devices, including "
            "one server. Keep both enrolled device pages open, then retry.")
    target = None
    for a in connected:
        if a.asset_id == target_id.upper():
            target = a
            break
    if target is None:
        raise ValueError(
            "Target is not a connected device. Open that device's page so it "
            "registers and heartbeats, then start the engagement again.")

    incident = DemoIncident(
        incident_id=_uid("DEMO"),
        scenario="discovery",
        status=IncidentStatus.PENDING,
        stage="reconnaissance",
        simulation_level=1,
        origin_asset_id=target.asset_id,
        attacker=participant.participant_id,
        started_at=datetime.utcnow(),
        meta={"target_name": target.hostname, "model": "flow-wm-v3.0.0"},
    )
    db.add(incident)
    await db.flush()

    # The deception farm (server-shaped honeypot replicas) comes to life as
    # soon as the range has an engagement — ready to absorb lateral movement.
    await _ensure_shadow_servers(db)

    await _emit(db, "participant_joined", {
        "participant_id": participant.participant_id,
        "role": participant.role,
        "device": participant.device_context.get("category", "browser"),
    }, source=participant.participant_id)

    await _emit(db, "attack_started", {
        "target": target.asset_id,
        "target_name": target.hostname,
        "actor": participant.participant_id,
    }, source=participant.participant_id, incident_id=incident.incident_id)

    # Choose a safe challenge
    question = challenges()[_now_ms() % len(challenges())]
    chall = Challenge(
        incident_id=incident.incident_id,
        question=question["question"],
        answer_schema=question["answers"],
    )
    db.add(chall)
    await db.flush()

    await _add_evidence(db, incident.incident_id, "attack_initiated", {
        "actor": participant.participant_id,
        "target": target.asset_id,
        "simulation": True,
    }, source=participant.participant_id)

    # Capture only the identity data passively observable for this participant.
    # The resolver queries no ports and does not enumerate unrelated devices.
    identity = resolve_network_identity((participant.device_context or {}).get("source_ip"))
    incident.meta = {**(incident.meta or {}), "attacker_identity": identity}
    await _add_evidence(db, incident.incident_id, "attacker_identity_observed", {
        "actor": participant.participant_id,
        "identity": identity,
        "observed_at": datetime.utcnow().isoformat(timespec="seconds"),
    }, source="lan_identity")
    await _emit(db, "attacker_identity_captured", {
        "actor": participant.participant_id,
        "source_ip": identity["source_ip"]["value"],
    }, source="lan_identity", incident_id=incident.incident_id)

    return {
        "incident_id": incident.incident_id,
        "target": {"id": target.asset_id, "name": target.hostname},
        "status": incident.status.value,
        "challenge": {
            "challenge_id": str(chall.id),
            "question": chall.question,
            "options": _challenge_options(chall),
        },
    }


async def _apply_attack_progression(db: AsyncSession, incident: DemoIncident,
                                    origin: DemoAsset, level: int) -> None:
    """Advance the origin asset through simulated states based on challenge level."""
    stage_by_level = {1: "reconnaissance", 2: "discovery", 3: "initial_access",
                      4: "execution", 5: "lateral_movement", 6: "collection"}
    stage = stage_by_level.get(level, "discovery")
    incident.stage = stage
    incident.simulation_level = level

    # Progress asset state: healthy -> suspicious -> under_attack -> compromised
    states = [origin.status.value]
    if level >= 1:
        origin.status = AssetStatus.SUSPICIOUS
        await _emit(db, "attack_started", {"target": origin.asset_id, "actor": incident.attacker,
                                           "sender": True, "stage": stage},
                    source="simulation", incident_id=incident.incident_id)
    if level >= 2:
        origin.status = AssetStatus.UNDER_ATTACK
        await _emit(db, "attack_stage_changed", {"target": origin.asset_id, "actor": incident.attacker,
                                                 "stage": stage, "level": level},
                    source="simulation", incident_id=incident.incident_id)
    if level >= 4:
        origin.status = AssetStatus.COMPROMISED
        origin.zone = "threat"
        await _emit(db, "risk_changed", {"target": origin.asset_id, "actor": incident.attacker,
                                         "stage": stage, "level": level, "status": "compromised"},
                    source="simulation", incident_id=incident.incident_id)


async def answer_challenge(db: AsyncSession, incident_id: str, token: str,
                           answer: str) -> Dict:
    incident = await get_incident(db, incident_id)
    if not incident:
        raise ValueError("Incident not found")
    participant = await _participant_for_incident(db, incident)
    if not participant or participant.token != token:
        raise ValueError("Unauthorized")
    if participant.status == "ejected":
        raise ValueError("Range access revoked after honeynet capture")

    chall = (await db.execute(
        select(Challenge).where(Challenge.incident_id == incident_id)
        .order_by(desc(Challenge.created_at)).limit(1)
    )).scalar_one_or_none()
    if not chall:
        raise ValueError("Challenge not found")

    # A captured attacker keeps "working" inside the service console (feeding
    # the honeypot) — every handshake is recorded, nothing escalates further.
    if _is_trapped(incident):
        await _add_evidence(db, incident.incident_id, "attacker_intel", {
            "actor": participant.participant_id,
            "question": chall.question, "provided_answer": answer,
            "stage": "captured", "captured": True, "monitoring": True,
            "device": participant.device_context,
            "captured_at": datetime.utcnow().isoformat(timespec="seconds"),
        }, source=participant.participant_id)
        await _emit(db, "decoy_interaction", {
            "actor": participant.participant_id,
            "decoy": (incident.meta or {}).get("monitoring", {}).get("decoy"),
            "captured": True, "monitoring": True},
            source=participant.participant_id, incident_id=incident.incident_id)
        await db.flush()
        return {
            "incident_id": incident.incident_id,
            "trapped": True,
            "monitoring": (incident.meta or {}).get("monitoring"),
            "stage": "captured",
            "message": "You are inside the service console. Everything here is recorded.",
        }

    if isinstance(answer, dict):
        answer = str(answer.get("value") or answer.get("label") or "")
    elif not isinstance(answer, str):
        answer = str(answer or "")

    matched = []
    for spec in (chall.answer_schema or []):
        if answer and answer.strip().lower() == str(spec.get("value")).lower():
            matched.append(spec)
    level = matched[0].get("level", 1) if matched else 1
    observed_level = max(1, level)
    chall.provided_answer = answer
    chall.result_level = observed_level

    incident.status = IncidentStatus.ACTIVE
    origin = await get_asset(db, incident.origin_asset_id)
    if not origin:
        raise ValueError("Origin asset missing")

    await db.flush()

    # Honeypot capture: every handshake the attacker submits is collected and
    # stored with the device context that produced it (attribution telemetry).
    await _add_evidence(db, incident.incident_id, "attacker_intel", {
        "actor": participant.participant_id,
        "question": chall.question,
        "provided_answer": answer,
        "result_level": observed_level,
        "stage": incident.stage,
        "device": participant.device_context,
        "origin": origin.asset_id,
        "origin_name": origin.hostname,
        "captured_at": datetime.utcnow().isoformat(timespec="seconds"),
    }, source=participant.participant_id)

    return await _run_progression(db, incident, origin, participant, observed_level)


async def _run_progression(db: AsyncSession, incident: DemoIncident,
                           origin: DemoAsset, participant: Participant,
                           observed_level: int) -> Dict:
    """Shared per-actor attack-resolution path (answer_challenge and pivot).

    Simulated telemetry -> real world model -> per-actor prediction + decoy ->
    containment/failover -> actor/trajectory/convergence snapshots.
    """
    await _apply_attack_progression(db, incident, origin, observed_level)
    await db.flush()

    # Run the REAL world model on the new simulated state
    forecast = world_model_adapter.try_world_model_forecast(
        stage=incident.stage, level=observed_level, horizon=4)

    if not forecast:
        # Model unavailable path is honest: report offline/unavailable forecast.
        forecast = {
            "current_stage": incident.stage,
            "current_confidence": 0.0,
            "timeline": [],
            "model_version": "unavailable",
            "explanation": {"natural_language": "World model checkpoint unavailable."},
            "thinking": None,
        }

    # Bridge "unknown" annotations with the canonical kill chain for display,
    # then let the real model's terminal stage steer candidate resolution.
    kill_chain = ["reconnaissance", "discovery", "initial_access", "execution",
                  "persistence", "privilege_escalation", "defense_evasion",
                  "lateral_movement", "collection", "exfiltration", "impact"]
    predicted_stages = [t.get("stage") for t in forecast.get("timeline", [])]
    filled = []
    _i = 0
    for s in predicted_stages:
        if isinstance(s, str) and s.lower() != "unknown":
            filled.append(s)
        else:
            filled.append(kill_chain[min(_i, len(kill_chain) - 1)])
        _i += 1
    predicted_stages = filled
    terminal = predicted_stages[-1] if predicted_stages else "lateral_movement"
    model_conf = float(forecast.get("current_confidence", 0.0))
    conf = min(0.99, max(0.34, model_conf))

    # Resolve the next target from the live pool of *connected* devices (never
    # the origin, never an already-contained node). The model picks the stage;
    # the demo resolves a host from the devices that actually exist on the
    # range — never from a pre-seeded asset list.
    pool = [a for a in await connected_devices(db)
            if a.asset_id != origin.asset_id and a.status != AssetStatus.CONTAINED]
    if terminal in ("collection", "exfiltration", "impact"):
        preferred = [a for a in pool if a.asset_type == "database"]
    elif terminal in ("lateral_movement", "execution", "initial_access"):
        preferred = [a for a in pool if a.role == AssetRole.SERVER]
    else:
        preferred = []
    predicted = (preferred or pool)[0] if (preferred or pool) else None

    # If the only connected device is the origin (a single-surfaced demo), the
    # model would otherwise stall with no predicted target and no decoy. Fall
    # back to a server-shaped honeypot replica already poised on the range so
    # deception still stages and the attacker's trail stays funneled to the
    # honeypot instead of dead-ending the engagement.
    if predicted is None:
        farm = [a for a in await list_assets(db)
                if a.role == AssetRole.DECOY and a.asset_type == "application-server"]
        predicted = farm[0] if farm else None

    risk = compute_risk(incident.stage, conf, observed_level,
                        criticality=origin.criticality)
    policy = policy_decision(incident.stage, risk, predicted=(predicted is not None))

    incident.predicted_target_id = predicted.asset_id if predicted else None
    incident.predicted_target_name = predicted.hostname if predicted else None

    # A decoy is ONLY ever created after the model has predicted a target. It
    # is a synthesized twin of that target, produced on demand — never seeded.
    decoy = None
    if predicted:
        decoy = await ensure_decoy_for_incident(db, incident)
        # The confirmed intrusion changes the attacker's neighborhood: fake
        # segment hosts materialize around the attacker as believable bait.
        await _ensure_bait_ring(db, incident, origin)

    # Persist real prediction
    pred = PredictionRecord(
        incident_id=incident.incident_id,
        actor_id=incident.attacker,
        model_version=forecast.get("model_version", "flow-wm-v3.0.0"),
        horizon=4,
        current_stage=incident.stage,
        predicted_stages=predicted_stages,
        predicted_target=predicted.hostname if predicted else None,
        predicted_target_id=predicted.asset_id if predicted else None,
        confidence=round(conf, 4),
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        lead_time_seconds=round(18.4, 1),
        belief={**(forecast.get("thinking") or {}),
                "novelty": forecast.get("novelty") or [],
                "model_decision": forecast.get("model_decision") or {}},
        explanation=forecast.get("explanation"),
    )
    db.add(pred)

    if forecast.get("model_decision"):
        await _emit(
            db,
            "model_decision_executed",
            {
                "actor": incident.attacker,
                "incident_id": incident.incident_id,
                "target_host": predicted.hostname if predicted else origin.hostname,
                "target_id": predicted.asset_id if predicted else origin.asset_id,
                "decision": forecast["model_decision"],
                "model_decision": forecast["model_decision"],
                "forecast": forecast,
            },
            source="g_flowwm_engine",
            incident_id=incident.incident_id,
        )

    # Containment + deception (accumulates across pivots / actors). A real
    # server origin isolates AUTOMATICALLY the moment the attack executes
    # (level >= 4): it becomes a soft-404 dead end, traffic fails over to the
    # replica pool and the clean-restore pipeline opens — the attacker only
    # ever moves forward through the decoy farm around them.
    contained = list(incident.contained_asset_ids or [])
    restore_plan: Optional[Dict] = None
    if policy["action"] in ("CONTAIN_AND_DECEIVE", "ISOLATE") or (
            origin.role == AssetRole.SERVER and observed_level >= 4):
        origin.status = AssetStatus.CONTAINED
        origin.zone = "threat"
        origin.meta = {**(origin.meta or {}), "contained": True,
                       "contained_at": datetime.utcnow().isoformat(timespec="seconds"),
                       "isolated": True}
        if origin.asset_id not in contained:
            contained.append(origin.asset_id)
        incident.contained_asset_ids = contained
        await _emit(db, "containment_started",
                    {"target": origin.asset_id, "actor": incident.attacker,
                     "policy": policy["action"]},
                    source="simulation", incident_id=incident.incident_id)
        await _emit(db, "containment_completed",
                    {"target": origin.asset_id, "actor": incident.attacker,
                     "quarantine": True},
                    source="simulation", incident_id=incident.incident_id)
        # The isolated server answers a soft 404 from now on; the replica
        # absorbs the service load automatically (never downtime).
        await _emit(db, "server_isolated", {
            "target": origin.asset_id, "name": origin.hostname,
            "actor": incident.attacker, "surface": "404",
            "auto_failover": True,
            "reason": "confidential service with weak segment security",
        }, source="simulation", incident_id=incident.incident_id)
        # HA continuity: a contained server replica's traffic is rerouted to
        # the next healthy server so the shared domain never goes down.
        if origin.role == AssetRole.SERVER:
            fallback = await _service_failover(db, origin.asset_id)
            if fallback:
                await _emit(db, "traffic_rerouted", {
                    "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in"),
                    "from": origin.asset_id, "to": fallback.asset_id,
                    "actor": incident.attacker, "availability": "serving",
                    "surface": "404",
                }, source="simulation", incident_id=incident.incident_id)
            # The edge production surface really reports which replica is
            # serving the shared domain now.
            await edge.set_serving(fallback.asset_id if fallback else origin.asset_id)
            # Deception in the isolation: the isolated server is replaced in
            # the attacker's view by a believable decoy twin of itself.
            await ensure_origin_twin(db, incident, origin)
            # Remediation: the attacker is quarantined in containment and the
            # infected server is pushed to maintenance — diagnostics + a
            # data-loss report run, then it can be restored from the clean copy.
            restore_plan = await plan_cleanup_and_restore(db, origin, incident)
            if origin.role == AssetRole.SERVER:
                maint = await _start_maintenance(db, origin, incident)
                restore_plan = {**restore_plan,
                                "maintenance": maint["job"],
                                "recoverable": maint["recoverable"]}

    if decoy:
        decoy_asset = decoy
        decoy_asset.status = AssetStatus.DECOY
        await _emit(db, "deception_activated",
                    {"decoy": decoy.asset_id, "decoy_name": decoy.hostname,
                     "actor": incident.attacker,
                     "predicted": predicted.asset_id if predicted else None,
                     "intercept": True},
                    source="simulation", incident_id=incident.incident_id)

    # Recommended action + lead time
    await _emit(db, "prediction_generated", {
        "incident": incident.incident_id,
        "model": pred.model_version,
        "current_stage": incident.stage,
        "predicted_target": pred.predicted_target,
        "confidence": round(conf, 4),
        "lead_time": pred.lead_time_seconds,
        "risk_level": pred.risk_level,
        "recommended_action": policy["action"],
    }, source="world-model", incident_id=incident.incident_id)

    await _add_evidence(db, incident.incident_id, "prediction", {
        "model": pred.model_version,
        "stage": incident.stage,
        "predicted_target": pred.predicted_target,
        "confidence": round(conf, 4),
        "lead_time": pred.lead_time_seconds,
    }, source="world-model")

    await _add_evidence(db, incident.incident_id, "containment", {
        "asset": origin.asset_id,
        "policy": policy["action"],
        "reason": policy["reason"],
        "risk": risk["risk_level"],
    }, source="simulation")

    await _add_evidence(db, incident.incident_id, "deception", {
        "decoy": decoy.asset_id if decoy else None,
        "actor": incident.attacker,
        "predicted_target": predicted.asset_id if predicted else None,
        "level": observed_level,
    }, source="simulation")

    # Multi-actor snapshots: per-actor summary, trajectory, convergence links
    await _upsert_actor_snapshot(db, incident, origin, conf)
    await _upsert_trajectory_snapshot(db, incident, origin)
    await _ensure_convergence_correlation(db, incident)

    await db.flush()

    return {
        "incident_id": incident.incident_id,
        "level": observed_level,
        "stage": incident.stage,
        "origin": {"id": origin.asset_id, "status": origin.status.value},
        "prediction": {
            "model": pred.model_version,
            "predicted_target": pred.predicted_target,
            "predicted_target_id": pred.predicted_target_id,
            "confidence": round(conf, 4),
            "lead_time": pred.lead_time_seconds,
            "risk_level": pred.risk_level,
        },
        "policy": policy,
        "deception": {
            "activated": decoy is not None,
            "decoy": decoy.asset_id if decoy else None,
            "decoy_name": decoy.hostname if decoy else None,
        },
        "restore": restore_plan,
        "next": {
            "prompt": "Follow the target environment to simulate the attack trajectory."
                if decoy else "No decoy staged.",
        },
    }


# ---- Multi-actor helpers ---------------------------------------------------
# Failover / HA continuity for the shared server domain (zero-downtime story).

# ---- Deception continuity -------------------------------------------------

def _is_server_replica(a: DemoAsset) -> bool:
    """A real production server or a server-shaped honeypot replica/mirror."""
    if a.role == AssetRole.SERVER:
        return True
    return a.role == AssetRole.DECOY and a.asset_type == "application-server"


async def _ensure_shadow_servers(db: AsyncSession) -> List[DemoAsset]:
    """Poise the honeypot server replicas (the deception farm).

    Two server-shaped honeypots live in the backend the moment a range
    engagement begins, ready to be swapped in for any real server path the
    attacker tries to cross laterally. They never exist before devices join,
    and they are removed on reset. They are what keeps the shared domain
    serving the whole way through the demo.
    """
    replicas = [a for a in await list_assets(db)
                if a.role == AssetRole.DECOY and a.asset_type == "application-server"]
    if replicas:
        return replicas
    created: List[DemoAsset] = []
    for i, ident in enumerate(("9f4c", "e21a")):
        seed = sum(ord(c) for c in f"REPL-{ident}") % 250 + 2
        rep = DemoAsset(
            asset_id=f"REPL-{ident.upper()}",
            hostname=f"replica-{ident}",
            role=AssetRole.DECOY,
            asset_type="application-server",
            ip=f"10.11.1.{seed + i}",
            zone="honeynet",
            status=AssetStatus.DECOY,
            criticality="high",
            service="Application Server",
            is_physical=False,
            registered=False,
            page_endpoint="/target",
            meta={"kind": "honeypot_farm",
                  "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in")},
        )
        db.add(rep)
        created.append(rep)
    await db.flush()
    await _emit(db, "honeypot_farm_ready", {
        "replicas": [r.asset_id for r in created],
        "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in"),
    }, source="simulation")
    return created


async def _mint_server_mirror(db: AsyncSession, source: DemoAsset) -> DemoAsset:
    """Mint a continuity mirror of a lost server replica (never-down guarantee)."""
    mirror_id = f"{source.asset_id}-MIRROR"
    mirror = await get_asset(db, mirror_id)
    if mirror:
        return mirror
    seed = sum(ord(c) for c in mirror_id) % 250 + 10
    mirror = DemoAsset(
        asset_id=mirror_id,
        hostname=f"{source.hostname}-mirror",
        role=AssetRole.DECOY,
        asset_type="application-server",
        ip=f"10.11.2.{seed}",
        zone="honeynet",
        status=AssetStatus.DECOY,
        criticality=source.criticality or "high",
        service=source.service or "Application Server",
        is_physical=False,
        registered=False,
        page_endpoint="/target",
        meta={"kind": "continuity_mirror", "mirror_of": source.hostname,
              "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in")},
    )
    db.add(mirror)
    await db.flush()
    return mirror


# ---- Clean backup / restore (zero-downtime recovery) -----------------------

def _clean_backups(asset: DemoAsset) -> List[Dict]:
    return [b for b in (asset.meta or {}).get("backups", [])
            if b.get("state") == "clean"]


def _last_clean_backup(asset: DemoAsset) -> Optional[Dict]:
    backups = _clean_backups(asset)
    return backups[-1] if backups else None


async def ensure_clean_backup(db: AsyncSession, asset: DemoAsset) -> Optional[Dict]:
    """Snapshot a healthy real server as the last *clean* copy (pre-attack).

    A clean copy is only ever taken from a healthy node — an infected node is
    never snapshotted, so the restore engine always has a malware-free image.
    """
    if asset.role != AssetRole.SERVER or not asset.is_physical:
        return None
    if asset.status != AssetStatus.HEALTHY:
        return None
    existing = (asset.meta or {}).get("backups") or []
    if existing:
        return existing[-1]
    snap = {
        "id": _uid("SNAP"),
        "taken_at": datetime.utcnow().isoformat(timespec="seconds"),
        "state": "clean",
        "role": asset.role.value,
        "service": asset.service,
        "apps": [asset.service] if asset.service else ["app"],
        "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in"),
    }
    asset.meta = {**(asset.meta or {}), "backups": existing + [snap]}
    await _emit(db, "backup_created", {
        "asset": asset.asset_id, "name": asset.hostname, "snapshot": snap["id"],
        "domain": snap["domain"]}, source="simulation")
    return snap


def _cleanup_plan(asset: DemoAsset) -> Dict:
    backup = _last_clean_backup(asset)
    return {
        "asset": asset.asset_id,
        "plan": "quarantine -> sanitize -> restore-from-clean-snapshot -> verify",
        "snapshot": backup["id"] if backup else None,
        "snapshot_state": backup["state"] if backup else "none",
        "eta_seconds": 6 if backup else None,
        "residual_risk": "none" if backup else "rebuilt-from-baseline",
        "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in"),
    }


async def plan_cleanup_and_restore(db: AsyncSession, origin: DemoAsset,
                                   incident: DemoIncident) -> Dict:
    """After containment, emit the remediation plan backed by the clean copy."""
    plan = _cleanup_plan(origin)
    await _emit(db, "cleanup_planned", {
        "target": origin.asset_id, "actor": incident.attacker,
        "plan": plan["plan"], "snapshot": plan["snapshot"],
        "snapshot_state": plan["snapshot_state"],
        "eta_seconds": plan["eta_seconds"]},
        source="simulation", incident_id=incident.incident_id)
    await _add_evidence(db, incident.incident_id, "restore_plan", plan,
                        source="simulation")
    return plan


async def restore_server_from_backup(db: AsyncSession, asset_id: str,
                                     incident_id: Optional[str] = None,
                                     force: bool = False) -> Dict:
    """Clean-and-restore a contained server from the last malware-free copy.

    Gated by maintenance: the server must have finished its diagnostics
    (data-loss report + checklist) unless the presenter forces it. On restore
    the node is wiped, re-provisioned from the clean snapshot, returns to the
    live serving set and re-snapshots a FRESH clean copy (so a new attack never
    restores a stale image). Attribution trail is kept for the model retrain.
    """
    asset = await get_asset(db, asset_id.upper())
    if asset is None:
        raise ValueError(f"Asset {asset_id} not on the range")
    if asset.role != AssetRole.SERVER or not asset.is_physical:
        raise ValueError("Only a real server replica can be restored")
    backup = _last_clean_backup(asset)
    maint = (asset.meta or {}).get("maintenance") or {}
    if not force and not maint.get("recoverable"):
        raise ValueError(
            f"{asset.asset_id} is still in maintenance diagnostics — wait for the "
            "diagnostic checks to pass, then restore & re-add (or force).")
    restored_at = datetime.utcnow()
    if backup is None:
        backup = {"id": _uid("SNAP"), "taken_at": restored_at.isoformat(timespec="seconds"),
                  "state": "baseline"}
    asset.status = AssetStatus.HEALTHY
    asset.zone = "lan"
    meta = dict(asset.meta or {})
    maint_done = dict(meta.pop("maintenance", {}) or {})
    meta.pop("contained", None)
    meta.pop("contained_at", None)
    meta["last_restore"] = {
        "snapshot": backup["id"],
        "taken_at": backup["taken_at"],
        "restored_at": restored_at.isoformat(timespec="seconds"),
        "method": "clean-snapshot-restore",
        "data_loss": maint_done.get("data_loss"),
        "diagnostics": maint_done.get("checks") or [],
    }
    asset.meta = meta
    await db.flush()

    # The restored server leaves quarantine: drop it from every active
    # incident's contained set so the topology stops drawing the CONTAINED
    # edge, re-wires CORE-SWITCH -> server and re-admits it into the traffic
    # reassignment pool. Without this the restore would look unconvincing —
    # the node kept floating in "contained" after coming back healthy.
    _live_incs = (await db.execute(
        select(DemoIncident).where(DemoIncident.status != IncidentStatus.RESOLVED)
    )).scalars().all()
    for _inc in _live_incs:
        _cs = list(_inc.contained_asset_ids or [])
        if asset.asset_id in _cs:
            _inc.contained_asset_ids = [c for c in _cs if c != asset.asset_id]

    # Fresh clean copy immediately after restore — never reuse a stale image.
    asset.meta = {**dict(asset.meta or {}), "backups": []}
    await db.flush()
    await ensure_clean_backup(db, asset)
    await db.flush()

    await _emit(db, "maintenance_released", {
        "asset": asset.asset_id, "name": asset.hostname,
        "job": "released", "snapshot": backup["id"], "fresh_copy": True,
        "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in")},
        source="simulation",
        incident_id=incident_id if (incident_id or "").startswith("DEMO") else None)
    await _emit(db, "server_restored", {
        "asset": asset.asset_id, "name": asset.hostname,
        "snapshot": backup["id"], "method": backup["state"],
        "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in")},
        source="simulation",
        incident_id=incident_id if (incident_id or "").startswith("DEMO") else None)
    await _add_evidence(db, incident_id or asset.asset_id, "restore", {
        "asset": asset.asset_id, "snapshot": backup["id"],
        "method": backup["state"],
        "restored_at": restored_at.isoformat(timespec="seconds"),
        "diagnostics": maint_done.get("checks") or [],
        "data_loss": maint_done.get("data_loss"),
        "fresh_snapshot_taken": True},
        source="simulation")

    svc = service_status(await list_assets(db))
    await edge.set_serving(asset.asset_id)
    await _emit(db, "service_recovered", {
        "domain": svc["domain"], "status": svc["status"],
        "real_serving": svc["continuity"]["real_serving"],
        "restored": asset.asset_id},
        source="simulation",
        incident_id=incident_id if (incident_id or "").startswith("DEMO") else None)
    return {
        "asset": asset.asset_id,
        "status": "restored",
        "snapshot": backup["id"],
        "method": backup["state"],
        "availability": svc["status"],
        "fresh_snapshot": (asset.meta or {}).get("backups", [])[-1].get("id")
                          if (asset.meta or {}).get("backups") else None,
    }


async def _service_failover(db: AsyncSession, exclude_asset_id: str) -> Optional[DemoAsset]:
    """Next continuity replica that can absorb app.payg.in traffic.

    Prefers a healthy real server; if none is left it hands the domain to a
    server-shaped honeypot replica (shadow farm or decoy twin). As a last
    resort it mints a mirror of the lost replica — the domain is always served.
    """
    for a in await connected_devices(db):
        if (a.role == AssetRole.SERVER and a.asset_id != exclude_asset_id
                and a.status not in (AssetStatus.COMPROMISED, AssetStatus.CONTAINED,
                                     AssetStatus.OFFLINE)):
            return a
    replicas = [a for a in await list_assets(db)
                if a.role == AssetRole.DECOY and a.asset_type == "application-server"
                and a.asset_id != exclude_asset_id]
    if replicas:
        return replicas[0]
    src = await get_asset(db, exclude_asset_id)
    if src is not None and src.role == AssetRole.SERVER:
        return await _mint_server_mirror(db, src)
    return None


def service_status(assets_rows: List[DemoAsset]) -> Dict:
    """HA / deception continuity: the shared domain is always served.

    Real servers that are healthy, plus the server-shaped honeypot replicas
    kept ready in the backend, act as continuity replicas for app.payg.in.
    Serving never drops below one replica while the range has a server — the
    domain does not go down at any point during the demo.
    """
    real = [a for a in assets_rows
            if a.role == AssetRole.SERVER and a.is_physical and a.registered]
    replicas = [a for a in assets_rows if _is_server_replica(a)]
    serving = [a for a in replicas
               if a.status.value not in ("contained", "offline")]
    # Equal-balance view: sorted clients round-robin across the healthy real
    # servers (or honeypot replicas when no real server is left) matches the
    # topology's deterministic load-balancing exactly.
    _pool = sorted([a for a in real
                    if a.status.value not in ("compromised", "contained", "offline")],
                   key=lambda a: a.asset_id) or serving
    _clients = sorted([a for a in assets_rows if a.role == AssetRole.CLIENT
                       and a.status.value not in ("compromised", "contained", "offline")],
                      key=lambda a: a.asset_id)
    client_load: Dict[str, int] = {}
    client_edges: Dict[str, str] = {}
    if _pool:
        for _i, _c in enumerate(_clients):
            _sid = _pool[_i % len(_pool)].asset_id
            client_load[_sid] = client_load.get(_sid, 0) + 1
            client_edges[_c.asset_id] = _sid
    return {
        "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in"),
        "replicas": len(replicas),
        "serving": len(serving),
        "serving_ids": [a.asset_id for a in serving],
        "fallback": serving[0].asset_id if serving else None,
        "status": "serving" if serving else ("down" if replicas else "na"),
        "client_load": client_load,
        "client_edges": client_edges,
        "continuity": {
            "real": len(real),
            "real_serving": sum(1 for a in real
                                if a.status.value not in ("compromised", "contained", "offline")),
            "honeypot": sum(1 for a in replicas if a.role == AssetRole.DECOY),
        },
        "backups": {
            "count": sum(1 for a in real if _last_clean_backup(a)),
            "recent": [{"asset": a.asset_id, "snapshot": _last_clean_backup(a)["id"]}
                       for a in real if _last_clean_backup(a)],
        },
        "restores": sum(1 for a in real if (a.meta or {}).get("last_restore")),
        "maintenance": [_maintenance_info(a) for a in real
                        if (a.meta or {}).get("maintenance")],
    }


# ---- Lateral movement (segmented production paths) -------------------------

_DECOY_ROLE_BY_TYPE = {"application-server": "server", "database": "database",
                       "client": "client", "workstation": "host", "device": "other"}


def _decoy_display_role(a: DemoAsset) -> str:
    return _DECOY_ROLE_BY_TYPE.get(a.asset_type or "", "server")


def _reachable_host(a: DemoAsset) -> Dict:
    display_role = "server" if a.asset_type == "application-server" \
        else _decoy_display_role(a) if a.role == AssetRole.DECOY else a.role.value
    return {
        "id": a.asset_id,
        "name": a.hostname,
        "role": display_role,
        "asset_type": a.asset_type,
        "service": a.service,
        "ip": a.ip,
        "status": a.status.value,
        "trap": a.role == AssetRole.DECOY,
    }


async def lateral_targets(db: AsyncSession, incident: DemoIncident):
    """Hosts reachable from the attacker's foothold (network sweep results).

    Two regimes:

    * BEFORE deception is staged (no decoy twin / bait ring yet): the real
      production servers are severed from the segment entirely and never
      offered as hop targets; only ordinary workstations/clients are still
      reachable — the realistic blind spot while the defender is confirming
      the engagement and preparing the trap.

    * ONCE deception is staged (decoy twin minted, bait ring placed, or the
      attacker captured): the sweep collapses to the DECOY farm only —
      server-shaped honeypot replicas first, then bait hosts. The attacker can
      no longer see or hop to any real server or workstation; their only way
      forward is the honeypot garden, where every step is captured telemetry
      and the destination is a trap.
    """
    staged = _is_trapped(incident) or incident.deception_activated \
        or bool(incident.decoy_asset_id or (incident.meta or {}).get("baits"))
    hits: List[Dict] = []
    if staged:
        for a in await list_assets(db):
            if a.role != AssetRole.DECOY or a.status == AssetStatus.OFFLINE:
                continue
            hits.append(_reachable_host(a))
        hits.sort(key=lambda h: (h["role"] != "server", h["id"]))
        return hits, ("Encased — every reachable host is a service replica "
                      "of app.payg.in. Nothing else is on this segment.")
    origin_id = incident.origin_asset_id
    contained = set(incident.contained_asset_ids or [])
    # Pre-deception sweep: only the segment workstations/clients that are
    # *live right now* remain (no stale offline hosts, no build-up from past
    # registrations); production servers failed over to the replica pool
    # (auto-404) and the decoy garden is not planted yet, so nothing else shows.
    for a in await connected_devices(db):
        if a.asset_id == origin_id or a.asset_id in contained:
            continue
        if a.role in (AssetRole.SERVER, AssetRole.DECOY):
            continue
        hits.append({
            "id": a.asset_id, "name": a.hostname,
            "role": a.role.value, "asset_type": a.asset_type,
            "service": a.service, "ip": a.ip, "status": a.status.value,
        })
    hits.sort(key=lambda h: (h["role"] != "server", h["id"]))
    return hits, "Reachable segment hosts from your current foothold."


async def _deceive_isolation(db: AsyncSession, incident: DemoIncident,
                             target: DemoAsset) -> Dict:
    """Soft-404 deception on an isolated real server.

    The probe is recorded for the defender's telemetry and the attacker gets a
    dead-end — no foothold, no progression. The decoy twin placed in the
    isolation is the only way forward, and it traps.
    """
    await _emit(db, "deception_error", {
        "actor": incident.attacker, "target": target.asset_id,
        "surface": "404", "isolated": True,
        "reason": "service unavailable / resource not found",
    }, source="simulation", incident_id=incident.incident_id)
    await _add_evidence(db, incident.incident_id, "service_error_404", {
        "actor": incident.attacker, "target": target.asset_id,
        "surface": "404", "isolated": True, "progression": "none",
    }, source="simulation")
    await db.flush()
    return {
        "incident_id": incident.incident_id,
        "deceived": True,
        "surface": "404",
        "target": target.asset_id,
        "hostname": target.hostname,
        "message": ("404 — the service at that host is unavailable or does "
                    "not exist. No foothold established."),
    }


async def _upsert_actor_snapshot(db: AsyncSession, incident: DemoIncident,
                                 origin: DemoAsset, confidence: float) -> ThreatActor:
    actor_id = incident.attacker
    row = (await db.execute(
        select(ThreatActor).where(ThreatActor.actor_id == actor_id))).scalar_one_or_none()
    now = datetime.utcnow()
    if row is None:
        row = ThreatActor(
            actor_id=actor_id,
            incident_id=incident.incident_id,
            first_seen=incident.started_at,
            last_seen=now,
            source_ips=[origin.ip] if origin.ip else [],
            confidence=confidence,
            status=incident.status.value,
            current_asset=origin.asset_id,
            current_stage=incident.stage,
            predicted_target=incident.predicted_target_name,
            predicted_target_id=incident.predicted_target_id,
            meta={"model": "flow-wm-v3.0.0"},
        )
        db.add(row)
    else:
        row.incident_id = incident.incident_id
        row.last_seen = now
        row.confidence = confidence
        row.status = incident.status.value
        row.current_asset = origin.asset_id
        row.current_stage = incident.stage
        row.predicted_target = incident.predicted_target_name
        row.predicted_target_id = incident.predicted_target_id
        new_ips = list(row.source_ips or [])
        if origin.ip and origin.ip not in new_ips:
            new_ips.append(origin.ip)
        row.source_ips = new_ips
    return row


async def _upsert_trajectory_snapshot(db: AsyncSession, incident: DemoIncident,
                                      origin: DemoAsset) -> ThreatTrajectory:
    tid = incident.meta.get("trajectory_id") or f"TR-{incident.incident_id}"
    row = (await db.execute(
        select(ThreatTrajectory).where(ThreatTrajectory.trajectory_id == tid))).scalar_one_or_none()
    now = datetime.utcnow()
    if row is None:
        row = ThreatTrajectory(
            trajectory_id=tid,
            incident_id=incident.incident_id,
            actor_id=incident.attacker,
            asset_sequence=[origin.asset_id],
            stage_sequence=[incident.stage],
            status=incident.status.value,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
    else:
        new_assets = list(row.asset_sequence or [])
        if not new_assets or new_assets[-1] != origin.asset_id:
            new_assets.append(origin.asset_id)
        row.asset_sequence = new_assets
        new_stages = list(row.stage_sequence or [])
        if not new_stages or new_stages[-1] != incident.stage:
            new_stages.append(incident.stage)
        row.stage_sequence = new_stages
        row.status = incident.status.value
        row.updated_at = now
    return row


async def _ensure_convergence_correlation(db: AsyncSession,
                                          incident: DemoIncident) -> Optional[ActorCorrelation]:
    """When two live actors predict the same target, record the correlation."""
    target = incident.predicted_target_id
    if not target:
        return None
    siblings = [i for i in await list_active_incidents(db)
                if i.incident_id != incident.incident_id
                and i.predicted_target_id == target and i.attacker]
    if not siblings:
        return None
    actor_ids = sorted({incident.attacker} | {s.attacker for s in siblings})
    corr_id = "CORR-" + "-".join(actor_ids)
    incident_ids = sorted({incident.incident_id} | {s.incident_id for s in siblings})
    method = "botnet" if len(actor_ids) >= 3 else "convergence"
    row = (await db.execute(
        select(ActorCorrelation).where(ActorCorrelation.correlation_id == corr_id))).scalar_one_or_none()
    now = datetime.utcnow().isoformat(timespec="seconds")
    if row is None:
        row = ActorCorrelation(
            correlation_id=corr_id, actor_ids=actor_ids, incident_ids=incident_ids,
            method=method, confidence=1.0, target=target,
            events=[{"ts": now, "kind": "convergence_detected", "target": target}],
            updated_at=datetime.utcnow(),
        )
        db.add(row)
        await db.flush()
        await _emit(db, "actor_correlation" if method != "botnet" else "botnet_consensus", {
            "correlation_id": corr_id, "actors": actor_ids,
            "target": target, "method": method},
            source="world-model", incident_id=incident.incident_id)
    else:
        row.method = method
        row.events = list(row.events or []) + [
            {"ts": now, "kind": "convergence_confirmed", "target": target}]
        row.updated_at = datetime.utcnow()
    return row


async def pivot_origin(db: AsyncSession, participant: Participant,
                       incident_id: str, target_id: str) -> Dict:
    """Attacker moves their foothold to another live device (lateral pivot).

    The previous origin is contained by the defender (caught foothold); if it
    was a server replica, traffic fails over so the shared domain keeps serving.
    A fresh safe challenge is minted — answering it runs the standard per-actor
    progression (new forecast -> new predicted target -> new decoy).
    """
    incident = await get_incident(db, incident_id)
    if not incident or incident.status == IncidentStatus.RESOLVED:
        raise ValueError("Incident not found or already resolved")
    if incident.attacker != participant.participant_id:
        raise ValueError("Not your engagement")

    target = await get_asset(db, target_id.upper())
    if target is None:
        raise ValueError("Pivot target is not on the range")
    if target.asset_id == incident.origin_asset_id:
        # Probing the real server you already hold answers a soft 404 once the
        # honeynet is staged (the defender has walled it off — the only path
        # forward is the decoy garden), and always once it is contained.
        if target.role == AssetRole.SERVER and target.is_physical \
                and (target.status == AssetStatus.CONTAINED
                     or incident.deception_activated or _is_trapped(incident)):
            return await _deceive_isolation(db, incident, target)
        raise ValueError("Pivot target is the current origin")
    if target.status == AssetStatus.CONTAINED and not (
            target.role == AssetRole.SERVER and target.is_physical):
        raise ValueError("Pivot target is already contained")
    if _is_trapped(incident):
        raise ValueError("You are inside the service console — no path to the real network from here.")
    is_bait = target.role == AssetRole.DECOY
    is_honeypot = is_bait and target.asset_type == "application-server"
    if target.role == AssetRole.SERVER and target.is_physical:
        # Soft-404 deception: the real server is isolated, so it answers like a
        # dead end. No foothold is ever established on it; the decoy twin
        # placed beside it is the only way forward, and it traps.
        return await _deceive_isolation(db, incident, target)
    if not (is_bait or (target.is_physical and target.role != AssetRole.SERVER)):
        raise ValueError("Pivot target is not reachable from your foothold")

    origin = await get_asset(db, incident.origin_asset_id)
    if origin:
        origin.status = AssetStatus.CONTAINED
        origin.zone = "threat"
        origin.meta = {**(origin.meta or {}), "contained": True}
        incident.contained_asset_ids = list(dict.fromkeys(
            (incident.contained_asset_ids or []) + [origin.asset_id]))
        await _emit(db, "containment_completed",
                    {"target": origin.asset_id, "actor": incident.attacker,
                     "quarantine": True, "reason": "abandoned by attacker after pivot"},
                    source="simulation", incident_id=incident.incident_id)
        if origin.role == AssetRole.SERVER:
            fallback = await _service_failover(db, origin.asset_id)
            if fallback:
                await _emit(db, "traffic_rerouted", {
                    "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in"),
                    "from": origin.asset_id, "to": fallback.asset_id,
                    "actor": incident.attacker, "availability": "serving",
                }, source="simulation", incident_id=incident.incident_id)
            await ensure_origin_twin(db, incident, origin)
            # Contained production servers are immediately pushed into the
            # maintenance workflow so the admin panel can show the rebuild
            # state instead of leaving them as a bare contained asset.
            # (_start_maintenance persists the job on the asset and emits its
            # own events; it returns a summary only.)
            if not (origin.meta or {}).get("maintenance"):
                await _start_maintenance(db, origin, incident)

    # The hop itself may be the trap: moving into any honeypot (segment bait,
    # shadow replica or decoy twin) captures the attacker. The engagement turns
    # into deception containment and the attacker is kept with the decoy,
    # monitored — their "reachable hosts" collapse to the honeypot only.
    if is_bait:
        return await _capture_in_decoy(db, incident, target, origin)

    # Retire the previous decoy / prediction for this incident
    if incident.decoy_asset_id:
        old = await get_asset(db, incident.decoy_asset_id)
        if old:
            await db.delete(old)
    incident.decoy_asset_id = None
    incident.deception_activated = False
    incident.predicted_target_id = None
    incident.predicted_target_name = None
    count = incident.meta.get("pivot_count", 0) + 1
    incident.meta = {**(incident.meta or {}),
                     "pivot_count": count,
                     "trajectory_id": incident.meta.get("trajectory_id")
                         or f"TR-{incident.incident_id}"}
    incident.origin_asset_id = target.asset_id
    incident.stage = "reconnaissance"
    incident.simulation_level = max(1, count)
    incident.status = (IncidentStatus.ACTIVE if incident.status in
                       (IncidentStatus.ACTIVE, IncidentStatus.DECEPTION,
                        IncidentStatus.CONTAINED) else incident.status)

    await _emit(db, "attacker_pivoted", {
        "actor": incident.attacker,
        "from": origin.asset_id if origin else None,
        "to": target.asset_id, "pivot": count},
        source="simulation", incident_id=incident.incident_id)

    question = challenges()[_now_ms() % len(challenges())]
    chall = Challenge(
        incident_id=incident.incident_id,
        question=question["question"],
        answer_schema=question["answers"],
    )
    db.add(chall)
    await db.flush()

    await _add_evidence(db, incident.incident_id, "attacker_pivoted", {
        "actor": incident.attacker,
        "from": origin.asset_id if origin else None,
        "to": target.asset_id, "pivot": count,
    }, source=participant.participant_id)

    return {
        "incident_id": incident.incident_id,
        "from": origin.asset_id if origin else None,
        "to": target.asset_id,
        "pivot": count,
        "status": incident.status.value,
        "challenge": {"challenge_id": str(chall.id), "question": chall.question,
                      "options": _challenge_options(chall),
                      "hint": "Answer correctly to set your new stage."},
    }


async def ensure_decoy_for_incident(db: AsyncSession,
                                    incident: DemoIncident) -> Optional[DemoAsset]:
    """Dynamically create (or reuse) the decoy twin of the predicted target.

    The decoy never exists before the world model has picked a target: it is a
    synthesized copy of that target, minted on demand and bound to the current
    incident. It is removed on reset.
    """
    predicted_id = incident.predicted_target_id
    if not predicted_id:
        return None
    predicted = await get_asset(db, predicted_id)
    if predicted is None:
        return None

    # If the predicted target is *already* a honeypot (shadow farm replica,
    # segment bait, or an earlier decoy twin), that node itself is the trap —
    # don't mint a second twin on top of it.
    if predicted.role == AssetRole.DECOY:
        incident.decoy_asset_id = predicted.asset_id
        incident.deception_activated = True
        incident.status = IncidentStatus.DECEPTION
        return predicted

    decoy_id = f"{predicted.asset_id}-DECOY"
    decoy = await get_asset(db, decoy_id)
    if decoy is None:
        seed = sum(ord(c) for c in decoy_id)
        decoy = DemoAsset(
            asset_id=decoy_id,
            hostname=f"{predicted.hostname}-decoy",
            role=AssetRole.DECOY,
            asset_type=predicted.asset_type or "server",
            ip=f"10.9.{seed % 255}.1",
            zone="threat",
            status=AssetStatus.DECOY,
            criticality="low",
            service=f"Simulated {predicted.service or 'target'}",
            is_physical=False,
            registered=False,
            page_endpoint="/target",
            meta={"twin_of": predicted.hostname, "origin": predicted.asset_id},
        )
        db.add(decoy)
        await db.flush()
        await _emit(db, "decoy_created", {
            "decoy": decoy.asset_id, "decoy_name": decoy.hostname,
            "twin_of": predicted.hostname, "zone": "honeynet",
        }, source="simulation", incident_id=incident.incident_id)
    incident.decoy_asset_id = decoy.asset_id
    incident.deception_activated = True
    incident.status = IncidentStatus.DECEPTION
    return decoy


async def ensure_origin_twin(db: AsyncSession, incident: DemoIncident,
                             origin: DemoAsset) -> Optional[DemoAsset]:
    """Mint the deception twin of an isolated real server ("decoy added in the
    isolation").

    When a real production server is contained, a convincing decoy copy of it
    is placed in the segment the attacker still sees, so the neighboring
    architecture keeps looking alive. The real isolated server now only ever
    answers with a soft 404 (see pivot_origin); the twin absorbs any follow-up
    approach and traps the attacker.
    """
    if origin.role != AssetRole.SERVER or not origin.is_physical:
        return None
    twin_id = f"{origin.asset_id}-DECOY"
    twin = await get_asset(db, twin_id)
    if twin is None:
        seed = sum(ord(c) for c in twin_id)
        twin = DemoAsset(
            asset_id=twin_id,
            hostname=f"{origin.hostname}-decoy",
            role=AssetRole.DECOY,
            asset_type="application-server",
            ip=f"10.9.{seed % 255}.1",
            zone="honeynet",
            status=AssetStatus.DECOY,
            criticality="low",
            service=f"Simulated {origin.service or 'server'}",
            is_physical=False,
            registered=False,
            page_endpoint="/target",
            meta={"twin_of": origin.hostname, "origin": origin.asset_id,
                  "kind": "isolated_origin_twin",
                  "domain": getattr(settings, "DEMO_DOMAIN", "app.payg.in")},
        )
        db.add(twin)
        await db.flush()
        await _emit(db, "decoy_origin_twin", {
            "decoy": twin.asset_id, "decoy_name": twin.hostname,
            "isolated": origin.asset_id, "zone": "honeynet",
        }, source="simulation", incident_id=incident.incident_id)
    return twin


# ---- Deception containment / attacker capture ------------------------------

def _is_trapped(incident: DemoIncident) -> bool:
    return bool((incident.meta or {}).get("trapped"))


async def _capture_in_decoy(db: AsyncSession, incident: DemoIncident,
                            decoy: DemoAsset, origin: Optional[DemoAsset]) -> Dict:
    """The attacker hopped into what they believed was a real host — it was a
    honeypot. The engagement becomes deception containment: the attacker stays
    inside the decoy, monitored, and their "reachable hosts" collapse to the
    trap only. The infected path the attacker abandoned is contained already.
    """
    now = datetime.utcnow()
    incident.meta = {**(incident.meta or {}),
                     "trapped": True,
                     "captured_at": now.isoformat(timespec="seconds"),
                     "monitoring": {"decoy": decoy.asset_id,
                                    "decoy_name": decoy.hostname,
                                    "since": now.isoformat(timespec="seconds"),
                                    "type": "honeypot_monitor"}}
    incident.status = IncidentStatus.DECEPTION
    incident.origin_asset_id = decoy.asset_id
    incident.decoy_asset_id = decoy.asset_id
    incident.deception_activated = True
    decoy.status = AssetStatus.DECOY
    decoy.zone = "threat"
    decoy.meta = {**(decoy.meta or {}), "monitoring": True,
                  "captured": incident.attacker}

    await _emit(db, "deception_containment", {
        "actor": incident.attacker, "decoy": decoy.asset_id,
        "decoy_name": decoy.hostname, "monitoring": True,
        "since": now.isoformat(timespec="seconds"),
    }, source="simulation", incident_id=incident.incident_id)
    # Real enforcement: the honeypot listener (:8091) takes on the decoy's
    # identity, and the attacker's real source IP is fenced off the real
    # production surface (:8090) with a genuine HTTP 403.
    await edge.activate_decoy(decoy.asset_id, decoy.hostname,
                              str(getattr(decoy, "asset_type", "server") or "server"),
                              actor=incident.attacker)
    src_ip = await edge.attacker_source_ip(db, incident)
    if src_ip:
        await edge.block_ip(src_ip, "trapped-in-honeypot", actor=incident.attacker)
    # End the participant's access to the controlled range immediately after
    # capture.  The record/token remains in the database for evidence linkage,
    # but every public API call is rejected by routes._participant. Physical
    # Wi-Fi disassociation is intentionally outside this app's authority.
    participant = await _participant_for_incident(db, incident)
    if participant:
        participant.status = "ejected"
        participant.device_context = {
            **(participant.device_context or {}),
            "range_ejected_at": now.isoformat(timespec="seconds"),
            "range_ejection_reason": "honeynet_capture",
        }
    await _emit(db, "attacker_ejected", {
        "actor": incident.attacker,
        "source_ip": src_ip or "confidential",
        "reason": "honeynet_capture",
        "scope": "controlled_demo_range",
    }, source="simulation", incident_id=incident.incident_id)
    await _add_evidence(db, incident.incident_id, "attacker_ejected", {
        "actor": incident.attacker,
        "source_ip": src_ip or "confidential",
        "reason": "honeynet_capture",
        "scope": "controlled_demo_range",
        "session_status": "ejected",
        "at": now.isoformat(timespec="seconds"),
    }, source="simulation")
    await _add_evidence(db, incident.incident_id, "attacker_captured", {
        "actor": incident.attacker, "decoy": decoy.asset_id,
        "decoy_name": decoy.hostname,
        "captured_at": now.isoformat(timespec="seconds"),
        "monitoring": True,
        "footprint_kept_for_attribution": True,
        "range_access": "revoked",
    }, source="simulation")
    await db.flush()
    return {
        "incident_id": incident.incident_id,
        "trapped": True,
        "monitoring": incident.meta["monitoring"],
        "range_access": "revoked",
        "message": (f"Attacker captured inside {decoy.hostname}. Controlled-range "
                    "access has been revoked; evidence is retained for review."),
    }


# ---- Segment bait ring around the attacker ---------------------------------

BAIT_PROFILES = [
    ("client", "client", "Client Terminal"),
    ("database", "database", "Database Replica"),
    ("host", "workstation", "Workstation"),
]


async def _ensure_bait_ring(db: AsyncSession, incident: DemoIncident,
                            origin: DemoAsset) -> List[DemoAsset]:
    """Materialize fake segment hosts right around the attacker once the
    intrusion is confirmed. They look like ordinary network inventory in the
    attacker's sweep; every interaction inside them is captured telemetry and
    the world-model reads them as the attacker's "next reachable hosts".
    """
    # The bait ring is a property of the segment (origin asset), not of any one
    # engagement: two attackers on the SAME origin share the same baits, so reuse
    # any existing ring assets globally instead of creating another ring that
    # would collide on the deterministic {origin}-BAIT{n} ids.
    prefix_like = f"{origin.asset_id}-BAIT%"
    shared = (await db.execute(
        select(DemoAsset).where(DemoAsset.asset_id.like(prefix_like)))).scalars().all()
    if shared:
        shared.sort(key=lambda a: a.asset_id)
        incident.meta = {**(incident.meta or {}),
                         "baits": [b.asset_id for b in shared]}
        return [b for b in shared]
    existing = [(await get_asset(db, b)) for b in (incident.meta or {}).get("baits", [])]
    existing = [a for a in existing if a is not None]
    if existing:
        return existing
    created: List[DemoAsset] = []
    for i, (role, atype, svc) in enumerate(BAIT_PROFILES):
        seed = sum(ord(c) for c in f"{origin.asset_id}-BAIT{i+1}") % 240 + 20
        bait = DemoAsset(
            asset_id=f"{origin.asset_id}-BAIT{i+1}",
            hostname=f"{origin.hostname}-segment-{i+1}",
            role=AssetRole.DECOY,
            asset_type=atype,
            ip=f"10.9.{seed}.{i+2}",
            zone="threat",
            status=AssetStatus.DECOY,
            criticality="low",
            service=svc,
            is_physical=False,
            registered=False,
            page_endpoint="/target",
            meta={"kind": "segment_bait", "bait_of": incident.attacker,
                  "presented_as": svc, "trap": "honeypot"},
        )
        db.add(bait)
        created.append(bait)
    await db.flush()
    incident.meta = {**(incident.meta or {}),
                     "baits": [b.asset_id for b in created]}
    await _emit(db, "bait_ring_deployed", {
        "actor": incident.attacker, "origin": origin.asset_id,
        "baits": [b.asset_id for b in created],
        "visible_as": [b.hostname for b in created],
    }, source="simulation", incident_id=incident.incident_id)
    for b in created:
        await _add_evidence(db, incident.incident_id, "bait_deployed", {
            "decoy": b.asset_id, "name": b.hostname,
            "presented_as": b.service, "attacker": incident.attacker,
        }, source="simulation")
    await db.flush()
    return created


# ---- Maintenance: diagnostics + data-loss report (server lifecycle) --------

MAINTENANCE_CHECKS = [
    ("filesystem_integrity", "Volume checksums vs clean copy"),
    ("process_sweep", "Unknown / unsigned processes"),
    ("persistence_audit", "Startup keys, crontabs, services"),
    ("ioc_signatures", "Known-bad hashes & beacon artifacts"),
    ("config_drift", "Firewall rules & listening sockets"),
]
_DATA_CLASSES = ["customer_records", "credentials", "session_tokens", "configuration"]


async def _data_loss_report(db: AsyncSession, incident: DemoIncident,
                            origin: DemoAsset) -> Dict:
    """Simulated data-loss estimate: severity from how deep the attacker got."""
    stage = incident.stage or "reconnaissance"
    level = incident.simulation_level or 1
    confirmed = stage in ("collection", "exfiltration", "impact") or level >= 6
    suspected = level >= 3
    touch = 1
    pivot_count = (incident.meta or {}).get("pivot_count", 0)
    if pivot_count:
        touch += int(pivot_count)
    if (incident.meta or {}).get("baits"):
        touch += 1
    est = (level * 740 + touch * 260) if suspected else 0
    now = datetime.utcnow()
    window = None
    if incident.started_at:
        st = incident.started_at
        if st.tzinfo is None:
            st = st.replace(tzinfo=timezone.utc)
        window = max(0, int((now.replace(tzinfo=timezone.utc) - st).total_seconds()))
    return {
        "asset": origin.asset_id,
        "severity": "confirmed" if confirmed
                    else ("suspected" if suspected else "none"),
        "estimated_records_at_risk": est,
        "data_classes": list(_DATA_CLASSES),
        "exposure_window_seconds": window,
        "attribution_signals": touch,
        "note": ("Same-session decoy capture confirmed; real data never left the "
                 "LAN. Blast radius is a simulated estimate fed to the model.")
    }


async def _start_maintenance(db: AsyncSession, origin: DemoAsset,
                             incident: DemoIncident) -> Dict:
    """Push a contained real server into maintenance.

    Records the job + data-loss report and streams the start event. Diagnostics
    are then advanced by the persistent maintenance supervisor (started from the
    app lifespan), which streams verdicts over ~6s and flips the job to
    recoverable so restore & re-add opens for the presenter.
    """
    dl = await _data_loss_report(db, incident, origin)
    origin.meta = {**(origin.meta or {}),
                   "maintenance": {
                       "since": datetime.utcnow().isoformat(timespec="seconds"),
                       "job": "diagnosing", "recoverable": False,
                       "checks": [], "data_loss": dl,
                       "incident_id": incident.incident_id}}
    await db.flush()
    await _emit(db, "maintenance_started", {
        "asset": origin.asset_id, "name": origin.hostname, "job": "diagnosing",
        "eta_seconds": len(MAINTENANCE_CHECKS) * _CHECK_STEP_SECONDS,
        "plan": "diagnostics -> data-loss report -> restore-from-clean -> verify",
        "data_loss": dl,
    }, source="simulation", incident_id=incident.incident_id)
    await _add_evidence(db, incident.incident_id, "maintenance_started", {
        "asset": origin.asset_id,
        "since": origin.meta["maintenance"]["since"],
        "job": "diagnosing", "data_loss": dl}, source="simulation")
    await db.flush()
    return origin.meta["maintenance"]


_MAINT_VERDICTS = {"filesystem_integrity": "clean",
                   "process_sweep": "quarantined",
                   "persistence_audit": "clean",
                   "ioc_signatures": "clean",
                   "config_drift": "clean"}

_CHECK_STEP_SECONDS = 1.1
_supervisor_logged = False
_LAST_AUTO_TICK = 0.0
_TICK_LOCK = asyncio.Lock()
_last_tick_note = "never-run"


def maintenance_ticker_note() -> str:
    return _last_tick_note


async def tick_maintenance_on_request() -> None:
    """Request-path maintenance tick (safety net for the background supervisor).

    The lifespan supervisor is the primary driver, but uvicorn --reload and
    some deploy styles can leave it stalled while request serving continues.
    Any command-center read co-fires one bounded, lock-protected maintenance
    pass at most once per second so a contained server always progresses to
    diagnostics-complete + auto-restore within seconds of a presenter looking
    at it. Never raises.
    """
    global _LAST_AUTO_TICK
    now = time.monotonic()
    if now - _LAST_AUTO_TICK < 1.0:
        return
    if _TICK_LOCK.locked():
        return
    async with _TICK_LOCK:
        _LAST_AUTO_TICK = time.monotonic()
        global _last_tick_note
        try:
            from app.core.db import async_session_maker
            async with async_session_maker() as db:
                rows = (await db.execute(
                    select(DemoAsset).where(
                        DemoAsset.role == AssetRole.SERVER,
                        DemoAsset.is_physical.is_(True)))).scalars().all()
                diagnosing = [a for a in rows
                              if ((a.meta or {}).get("maintenance") or {}).get("job") == "diagnosing"]
                _last_tick_note = f"servers={len(rows)} diagnosing={len(diagnosing)}"
                for asset in diagnosing:
                    m = (asset.meta or {}).get("maintenance")
                    done = await _advance_maintenance(db, asset)
                    if done:
                        try:
                            await restore_server_from_backup(
                                db, asset.asset_id,
                                incident_id=(m.get("incident_id")))
                        except Exception:
                            log.exception("auto-restore failed for %s", asset.asset_id)
                # Best-effort: pull real honeypot HTTP hits from the edge into
                # the evidence ledger (bounded to one drain per 5s inside).
                try:
                    await drain_edge_hits(db)
                except Exception:
                    log.debug("edge drain skipped", exc_info=True)
                await db.commit()
        except Exception as exc:
            _last_tick_note = f"error: {str(exc)[:140]}"


_LAST_EDGE_DRAIN = 0.0


async def drain_edge_hits(db: AsyncSession) -> int:
    """Ingest the Deception Edge's real honeypot HTTP hits as evidence.

    The edge's :8091 listener is a genuine HTTP service; every request an
    attacker makes to it is drained here and attached to their live
    engagement as `honeypot_http_hit` evidence (source ip, path, headers).
    Bounded: at most one drain per 5 seconds, skipped silently when the
    edge is not reachable. Returns the number of evidence rows written.
    """
    global _LAST_EDGE_DRAIN
    if not settings.EDGE_ENABLED or time.monotonic() - _LAST_EDGE_DRAIN < 5.0:
        return 0
    _LAST_EDGE_DRAIN = time.monotonic()
    state = await edge.status()
    if not state.get("available"):
        return 0
    result = await edge.drain_hits()
    hits = (result or {}).get("hits") or []
    stored = 0
    for hit in hits:
        actor = hit.get("actor")
        inc = None
        if actor:
            rows = await db.execute(
                select(DemoIncident)
                .where(DemoIncident.attacker == actor,
                       DemoIncident.status != IncidentStatus.RESOLVED)
                .order_by(desc(DemoIncident.started_at)).limit(1))
            inc = rows.scalar_one_or_none()
        if not inc:
            continue
        await _add_evidence(db, inc.incident_id, "honeypot_http_hit", hit,
                            source="edge")
        stored += 1
    if stored:
        await db.flush()
    return stored


async def _advance_maintenance(db: AsyncSession, asset: DemoAsset) -> bool:
    """Run one ~1.1s maintenance tick for a diagnosing server.

    Advances the diagnostic checklist (time-driven), emits verdicts, and when
    the last check completes flips the job to recoverable so the presenter's
    restore & re-add becomes available. Returns True if the job is now done.
    """
    asset_id = asset.asset_id
    maint = dict((asset.meta or {}).get("maintenance") or {})
    if maint.get("job") != "diagnosing":
        return True
    # The owning incident id is recorded on the maintenance job itself. Falling
    # back to an origin lookup alone breaks once the engagement captured the
    # attacker: capture rewrites the incident's origin to the honeypot decoy,
    # so the origin lookup returns nothing and evidence writes (NOT NULL
    # incident_id) would abort the whole maintenance tick.
    incident_id = maint.get("incident_id")
    if not incident_id:
        rows = await db.execute(
            select(DemoIncident).where(DemoIncident.origin_asset_id == asset_id,
                                       DemoIncident.status != IncidentStatus.RESOLVED))
        inc = rows.scalar_one_or_none()
        if inc:
            incident_id = inc.incident_id
    if not incident_id:
        incident_id = "maintenance"
    checks = list(maint.get("checks") or [])
    done = len(checks) >= len(MAINTENANCE_CHECKS)
    if not done:
        name, label = MAINTENANCE_CHECKS[len(checks)]
        verdict = _MAINT_VERDICTS.get(name, "clean")
        checks.append({"check": name, "label": label, "verdict": verdict,
                       "at": datetime.utcnow().isoformat(timespec="seconds")})
        _m = dict(maint); _m["checks"] = checks
        asset.meta = {**(asset.meta or {}), "maintenance": _m}
        await _emit(db, "diagnostic_check", {
            "asset": asset_id, "check": name, "label": label, "verdict": verdict,
            "index": len(checks), "of": len(MAINTENANCE_CHECKS)},
            source="simulation", incident_id=incident_id)
        await _add_evidence(db, incident_id, "diagnostic_check", {
            "asset": asset_id, "check": name, "label": label, "verdict": verdict},
            source="simulation")
    if len(checks) >= len(MAINTENANCE_CHECKS):
        _m = dict(maint)
        _m.update(job="recoverable", recoverable=True,
                  completed_at=datetime.utcnow().isoformat(timespec="seconds"),
                  checks=checks)
        asset.meta = {**(asset.meta or {}), "maintenance": _m}
        dl = _m.get("data_loss") or {}
        await _emit(db, "maintenance_complete", {
            "asset": asset_id, "job": "recoverable",
            "checks_passed": len(checks), "data_loss": dl,
            "restore_available": True},
            source="simulation", incident_id=incident_id)
        if dl and dl.get("severity") in ("suspected", "confirmed"):
            await _emit(db, "data_loss_reported", {
                "asset": asset_id, "severity": dl.get("severity"),
                "estimated_records_at_risk": dl.get("estimated_records_at_risk"),
                "data_classes": dl.get("data_classes"),
                "exposure_window_seconds": dl.get("exposure_window_seconds")},
                source="simulation", incident_id=incident_id)
        await _add_evidence(db, incident_id, "diagnostic_report", {
            "asset": asset_id, "checks": checks, "data_loss": dl},
            source="simulation")
        return True
    return False


async def run_maintenance_supervisor() -> None:
    """Persistent background worker (started from the app lifespan).

    Owns progression of every contained server's diagnostics: each pass visits
    every real server currently in 'diagnosing' maintenance and advances one
    check (a ~1.1s paced heartbeat), so the ~6s diagnostic arc unmistakeably
    completes and restore & re-add opens for the presenter — even across many
    requests, because this loop runs on the app's main event loop, not a
    request's. It uses its own throwaway DB sessions and is deliberately
    tolerant of transient DB issues (it just tries again on the next tick).
    """
    while True:
        try:
            await asyncio.sleep(_CHECK_STEP_SECONDS)
            from app.core.db import async_session_maker
            async with async_session_maker() as db:
                # Query the mapped CLASS (an instance here raises ArgumentError,
                # which the blanket except below used to swallow silently —
                # maintenance never advanced and restores never opened).
                rows = await db.execute(
                    select(DemoAsset).where(
                        DemoAsset.role == AssetRole.SERVER,
                        DemoAsset.is_physical.is_(True)))
                for asset in rows.scalars():
                    m = (asset.meta or {}).get("maintenance")
                    if not m or m.get("job") != "diagnosing":
                        continue
                    done = await _advance_maintenance(db, asset)
                    if done:
                        # Fully automated recovery: the moment the essential
                        # checkup finishes, the server is restored from its
                        # clean snapshot and comes straight back online — no
                        # presenter click required. The attacker is already
                        # drawn into the decoy farm, so this is safe.
                        try:
                            await restore_server_from_backup(
                                db, asset.asset_id,
                                incident_id=(m.get("incident_id")))
                        except Exception:
                            # Restore races / transient state — retried next
                            # diagnostic pass is unnecessary here; the server
                            # stays recoverable and the admin path can still
                            # restore it. Log-less on purpose: don't spam SSE.
                            pass
                # Ingest real honeypot HTTP hits from the edge into evidence
                # (bounded to one drain per 5s inside drain_edge_hits).
                try:
                    await drain_edge_hits(db)
                except Exception:
                    logging.getLogger("demo").debug("edge drain skipped", exc_info=True)
                await db.commit()
        except Exception:
            # Supervisor never dies: transient DB errors just skip a tick.
            # Log the first failure so a permanent breakage is never silent.
            global _supervisor_logged
            if not _supervisor_logged:
                _supervisor_logged = True
                logging.getLogger("demo").exception(
                    "Maintenance supervisor tick failed; retrying each tick")
            continue





def _maintenance_info(asset: DemoAsset) -> Optional[Dict]:
    m = (asset.meta or {}).get("maintenance")
    if not m:
        return None
    return {"asset": asset.asset_id, "name": asset.hostname,
            "job": m.get("job"), "since": m.get("since"),
            "recoverable": bool(m.get("recoverable")),
            "checks": m.get("checks") or [],
            "data_loss": m.get("data_loss"),
            "degraded": bool(m.get("degraded"))}


async def _participant_for_incident(db, incident: DemoIncident) -> Optional[Participant]:
    if not incident.attacker:
        return None
    res = await db.execute(
        select(Participant).where(Participant.participant_id == incident.attacker)
    )
    return res.scalar_one_or_none()


async def record_decoy_interaction(db: AsyncSession, incident_id: str, token: str,
                                   answers: List[Dict], event: str = "continue",
                                   context: Optional[Dict] = None) -> Dict:
    incident = await get_incident(db, incident_id)
    if not incident:
        raise ValueError("Incident not found")
    participant = await _participant_for_incident(db, incident)
    if not participant or participant.token != token:
        raise ValueError("Unauthorized")
    if participant.status == "ejected":
        raise ValueError("Range access revoked after honeynet capture")

    if not incident.deception_activated:
        raise ValueError("Deception not active for this incident")

    decoy = await get_asset(db, incident.decoy_asset_id) if incident.decoy_asset_id else None
    if decoy is None:
        raise ValueError("Decoy asset missing")

    # Capture whatever the session offers: browser, platform, screen, language,
    # timing, and every touchpoint the attacker submits inside the honeypot.
    device_capture = dict(participant.device_context or {})
    for k, v in (context or {}).items():
        if v is not None and k not in device_capture:
            device_capture[k] = v
        elif v is not None:
            device_capture[f"client_{k}"] = v
    device_capture["captured_at"] = datetime.utcnow().isoformat(timespec="seconds")

    session_ref = _uid("S")
    interaction = DecoyInteraction(
        incident_id=incident.incident_id,
        session_ref=session_ref,
        decoy_asset_id=decoy.asset_id,
        device_context=device_capture,
        events=[
            {"type": event, "ts": datetime.utcnow().isoformat(),
             "device": device_capture.get("category", "browser")}
        ],
        answers=answers or [],
    )
    db.add(interaction)

    decoy.meta = {**(decoy.meta or {}), "interactions": 1}

    await _emit(db, "decoy_interaction", {
        "actor": participant.participant_id,
        "decoy": decoy.asset_id,
        "session": session_ref,
        "device": device_capture.get("category", "browser"),
        "platform": device_capture.get("platform"),
        "browser": device_capture.get("browser"),
        "timezone": device_capture.get("timezone"),
        "screen": device_capture.get("screen"),
        "language": device_capture.get("language"),
        "answers": len(answers or []),
    }, source=participant.participant_id, incident_id=incident.incident_id)

    await _add_evidence(db, incident.incident_id, "attacker_telemetry", {
        "decoy": decoy.asset_id,
        "actor": participant.participant_id,
        "session": session_ref,
        "device": device_capture,
        "answers": answers or [],
        "touchpoints": 1,
    }, source=participant.participant_id)

    await db.flush()
    return {
        "session": session_ref,
        "decoy": decoy.asset_id,
        "interaction": "recorded",
        "device": device_capture,
    }


async def purge_devices(db: AsyncSession) -> int:
    """Remove every registered device row and synthetic decoy from the range.

    Unlike reset_demo (which preserves registrations so a demo can restart
    with the same audience), this is the between-demo-days eraser: all physical
    device rows, all synthetic decoys/baits/replicas, and any live incident
    rows are removed. Evidence and prediction ledgers are untouched. Devices
    whose browser tabs are still open simply re-register on their next
    heartbeat, so only genuinely-absent sample devices disappear.
    """
    # Close live engagements first so nothing re-mints decoys mid-purge.
    live = (await db.execute(
        select(DemoIncident).where(DemoIncident.status != IncidentStatus.RESOLVED)
    )).scalars().all()
    for inc in live:
        inc.status = IncidentStatus.RESOLVED
    rows = (await db.execute(select(DemoAsset))).scalars().all()
    removed = 0
    for a in rows:
        await db.delete(a)
        removed += 1
    await db.flush()
    await _emit(db, "devices_purged", {
        "removed": removed,
        "note": "all device rows removed; open tabs re-register on next heartbeat",
    }, source="system")
    await db.flush()
    try:
        if settings.EDGE_ENABLED:
            await edge.reset_edge()
    except Exception:
        log.debug("edge reset skipped during purge", exc_info=True)
    return removed


async def reset_demo(db: AsyncSession, clear_all: bool = False,
                     record_reset_event: bool = True) -> Dict:
    """Reset attack-linked state back to CLEAN / HEALTHY. Never touches research data."""
    assets_rows = await list_assets(db)
    devices = 0
    for a in assets_rows:
        if a.role == AssetRole.DECOY or not a.is_physical:
            # Synthetic decoys are tied to an incident and never outlive it.
            await db.delete(a)
            continue
        devices += 1
        a.status = AssetStatus.HEALTHY
        a.zone = "lan"
        a.meta = {}
        a.registered = True

    # Any live incident is closed so a fresh engagement can start. Its
    # challenge/event evidence remains visible unless clear_all is requested.
    live = (await db.execute(
        select(DemoIncident).where(DemoIncident.status != IncidentStatus.RESOLVED))).scalars().all()
    for inc in live:
        inc.status = IncidentStatus.RESOLVED

    if clear_all:
        for table in (DecoyInteraction, Challenge, EvidenceRecord, PredictionRecord,
                      DemoEvent, DemoIncident):
            await db.execute(delete(table))
        # Also clear non-incident events referenced by participant joins
        participants = (await db.execute(select(Participant))).scalars().all()
        for p in participants:
            p.status = "active"

    await db.flush()
    if record_reset_event:
        await _emit(db, "incident_updated", {"action": "reset", "state": "clean"},
                    source="system")
    await db.flush()
    # Lift every real IP block on the Deception Edge and retire its decoy
    # identity — a fresh demo must start with a clean production surface.
    try:
        if settings.EDGE_ENABLED:
            await edge.reset_edge()
    except Exception:
        log.debug("edge reset skipped", exc_info=True)
    return {"state": "clean", "devices": devices, "assets": len(assets_rows)}


def build_topology(assets_rows: List[DemoAsset],
                   incident: Optional[DemoIncident] = None,
                   predictions: Optional[Dict] = None) -> Dict:
    """Derive the network graph purely from live demo state.

    Nothing is drawn from config: base segments (INTERNET / FIREWALL /
    CORE-SWITCH) plus the devices that actually heartbeat. THREAT ZONE /
    CONTAINED / HONEYNET / MAINTENANCE / decoy nodes appear dynamically, and
    only as a consequence of an incident (compromise -> containment zone,
    prediction -> decoy twin + bait ring, restore -> maintenance zone).
    Every active attacker is a node roaming the topology; client/host nodes
    carry "traffic" edges to the server that serves them (failover moves the
    edge when a server is contained).
    """
    if incident is None:
        incidents: List[DemoIncident] = []
    elif isinstance(incident, (list, tuple)):
        incidents = [i for i in incident if i is not None
                     and i.status != IncidentStatus.RESOLVED]
    else:
        incidents = [incident] if incident.status != IncidentStatus.RESOLVED else []

    nodes: List[Dict] = []
    edges: List[Dict] = []
    node_ids: set[str] = set()

    def _infra(nid: str, label: str, asset_type: str) -> None:
        if nid in node_ids:
            return
        node_ids.add(nid)
        nodes.append({"id": nid, "label": label, "type": "infra",
                      "asset_type": asset_type, "role": "infra", "status": "infra"})

    # When several relationships collapse onto the same (source, target) pair —
    # e.g. a bait segment that ALSO captures the attacker — keep a single trace
    # so the topology never draws overlapping parallel lines. Higher priority wins.
    #   capture (trapped) > bait ring (engaged) > deception steer > foothold
    #   > live traffic / maintenance > ingress > infra/plain
    _EDGE_PRIORITY = {
        "capture": 6,
        "bait": 5,
        "deception": 4,
        "foothold": 3,
        "prediction": 3,
        "traffic": 2,
        "maintenance": 2,
        "ingress": 1,
        "service": 1,
        "zone": 0,
        "membership": 0,
    }
    _edge_index: Dict[tuple, int] = {}

    def _edge(source: str, target: str, kind: str | None = None,
              flow: int | None = None, **extra) -> None:
        key = (source, target)
        pri = _EDGE_PRIORITY.get(kind, 0)
        existing = _edge_index.get(key)
        if existing is not None:
            previous = edges[existing]
            prev_pri = _EDGE_PRIORITY.get(previous.get("kind"), 0)
            if prev_pri >= pri:
                if flow is not None and flow > (previous.get("flow") or 0):
                    previous["flow"] = flow
                return
            previous.pop("kind", None)
            previous.pop("flow", None)
            if kind:
                previous["kind"] = kind
            if flow:
                previous["flow"] = flow
            for k, v in extra.items():
                if v is not None:
                    previous[k] = v
            return
        _edge_index[key] = len(edges)
        edges.append({"source": source, "target": target,
                      **({"kind": kind} if kind else {}),
                      **({"flow": flow} if flow else {}),
                      **{k: v for k, v in extra.items() if v is not None}})

    _infra("INTERNET", "INTERNET", "internet")
    _infra("FIREWALL", "FIREWALL", "firewall")
    _infra("CORE-SWITCH", "CORE-SWITCH", "switch")
    _edge("INTERNET", "FIREWALL", flow=1)
    _edge("FIREWALL", "CORE-SWITCH", flow=1)

    active = bool(incidents)
    contained_ids = set()
    for inc in incidents:
        contained_ids.update(inc.contained_asset_ids or [])

    incident_assets = set()
    for inc in incidents:
        if inc.origin_asset_id:
            incident_assets.add(inc.origin_asset_id)
        if inc.predicted_target_id:
            incident_assets.add(inc.predicted_target_id)

    devices = [a for a in assets_rows
               if a.role != AssetRole.DECOY and (a.is_physical or a.asset_id in incident_assets)
               and a.status != AssetStatus.OFFLINE]

    threat_zone_needed = bool(incidents and (
        contained_ids or any(a.status in (AssetStatus.COMPROMISED,
                                          AssetStatus.CONTAINED,
                                          AssetStatus.UNDER_ATTACK) for a in devices)))

    by_id = {a.asset_id: a for a in assets_rows}

    def _asset_node(a: DemoAsset, extra: Optional[Dict] = None) -> None:
        if a.asset_id in node_ids:
            # Merge additive flags (e.g. capture_of / bait) onto an existing node
            # so later story beats still decorate the same disc.
            if extra:
                for n in nodes:
                    if n["id"] == a.asset_id:
                        n.update({k: v for k, v in extra.items() if v is not None})
                        break
            return
        node_ids.add(a.asset_id)
        nodes.append({
            "id": a.asset_id, "label": a.hostname, "type": "asset",
            "asset_type": a.asset_type, "role": a.role.value,
            "status": a.status.value, "ip": a.ip, "zone": a.zone,
            "criticality": a.criticality,
            **({} if not extra else extra),
        })

    _serving_candidates = [a for a in devices
                           if a.role == AssetRole.SERVER
                           and a.status not in (AssetStatus.COMPROMISED,
                                                AssetStatus.CONTAINED,
                                                AssetStatus.OFFLINE)]
    _decoy_servers = [a for a in assets_rows
                      if a.role == AssetRole.DECOY
                      and a.asset_type == "application-server"
                      and a.status != AssetStatus.OFFLINE]

    # Equal load-balancing: connected CLIENT nodes are divided as evenly as
    # possible across the healthy serving pool (real servers first, honeypot
    # replicas as an overflow for the never-down guarantee). The assignment is
    # deterministic — sorted clients round-robin over sorted servers — so the
    # topology redraws identically on every poll.
    _serving_pool = sorted(_serving_candidates, key=lambda a: a.asset_id) \
        or _decoy_servers
    _client_order = sorted(
        (a for a in devices if a.role == AssetRole.CLIENT
         and a.status not in (AssetStatus.COMPROMISED, AssetStatus.CONTAINED)
         and a.asset_id not in contained_ids),
        key=lambda a: a.asset_id)
    _client_assignment: Dict[str, DemoAsset] = {}
    for _i, _c in enumerate(_client_order):
        if _serving_pool:
            _client_assignment[_c.asset_id] = _serving_pool[_i % len(_serving_pool)]

    def _primary_server_for(client: DemoAsset) -> Optional[DemoAsset]:
        return _client_assignment.get(client.asset_id) \
            or (_serving_pool[0] if _serving_pool else None)

    attacked = {i.origin_asset_id for i in incidents}

    for a in devices:
        _asset_node(a)
        if a.status in (AssetStatus.COMPROMISED, AssetStatus.CONTAINED) or a.asset_id in contained_ids:
            continue
        _edge("CORE-SWITCH", a.asset_id, flow=1)
        # Only clients ride the business traffic edge — load-balanced evenly
        # across the serving pool. Hosts/other devices stay network-only.
        if a.role == AssetRole.CLIENT:
            srv = _primary_server_for(a)
            if srv:
                _asset_node(srv)
                flow = 1 + (2 if a.asset_id in attacked else 0)
                _edge(a.asset_id, srv.asset_id, kind="traffic", flow=flow)

    if threat_zone_needed:
        _infra("THREAT-ZONE", "THREAT ZONE", "zone")
        _infra("CONTAINED", "CONTAINED", "zone")
        # Zone spine — membership/geography only; the UI draws theater boxes
        # and hides these unless "wires" is toggled on.
        _edge("CONTAINED", "THREAT-ZONE", kind="zone")
        for a in devices:
            if a.status in (AssetStatus.COMPROMISED, AssetStatus.CONTAINED) or a.asset_id in contained_ids:
                _edge(a.asset_id, "CONTAINED", kind="membership")

    all_decoys = [a for a in assets_rows if a.role == AssetRole.DECOY]
    decoys_active = (any(inc.deception_activated and inc.decoy_asset_id for inc in incidents)
                     or any(a.asset_type == "application-server" for a in all_decoys))
    if decoys_active:
        _infra("HONEYNET", "HONEYNET", "zone")
        _edge("THREAT-ZONE" if threat_zone_needed else "CORE-SWITCH", "HONEYNET", kind="zone")
        for a in all_decoys:
            if a.asset_type == "application-server":
                _asset_node(a)
                _edge("HONEYNET", a.asset_id, kind="membership")
        for inc in incidents:
            if not (inc.deception_activated and inc.decoy_asset_id):
                continue
            decoy = by_id.get(inc.decoy_asset_id)
            if decoy is None:
                continue
            _asset_node(decoy)
            _edge("HONEYNET", decoy.asset_id, kind="membership")
            # Steer edge only when the predicted target is already on the canvas
            # (avoids dangling spokes into offline / missing hosts).
            if (inc.predicted_target_id
                    and inc.predicted_target_id != decoy.asset_id
                    and inc.predicted_target_id in node_ids):
                _edge(inc.predicted_target_id, decoy.asset_id, kind="deception")

    # The shared domain (app.payg.in) is carried as data (service_status) for
    # the dashboard panel rather than as a stuck topology node. Each server
    # currently serving the domain is badged via metadata, and the live
    # failover story stays visible through the clients' balanced traffic edges.
    _svc = service_status(assets_rows)
    _serving_ids = set(_svc["serving_ids"])
    for n in nodes:
        if n["id"] in _serving_ids:
            n["serving"] = True
        if n["type"] != "asset":
            continue
        _a = by_id.get(n["id"])
        if _a is None:
            continue
        _lr = (_a.meta or {}).get("last_restore") or {}
        if _lr.get("restored_at"):
            n["last_restore_at"] = _lr["restored_at"]
        if (_a.meta or {}).get("maintenance"):
            n["recovering"] = True

    # Every active attacker is a node; bait decoys orbit them. A captured
    # attacker is glued to the decoy with a "capture" edge.
    for inc in incidents:
        if not inc.attacker:
            continue
        attn = inc.attacker
        trapped = _is_trapped(inc)
        meta_attn = {"incident": inc.incident_id, "monitoring": bool(trapped),
                     "pivot": (inc.meta or {}).get("pivot_count", 0)}
        nodes.append({
            "id": attn, "label": f"ATK · {attn}", "type": "attacker",
            "asset_type": "attacker", "role": "attacker",
            "status": "trapped" if trapped else "active",
            "zone": "THREAT-ZONE", "meta": meta_attn,
        })
        node_ids.add(attn)
        # The attacker enters through the spine — INTERNET -> FIREWALL ->
        # CORE-SWITCH (the backbone edges above) and then pours into the LAN
        # from the core switch, exactly like the presenter story: the ingress
        # path is visible from the internet all the way to the victim segment.
        _edge("CORE-SWITCH", attn, kind="ingress", flow=2)
        origin = by_id.get(inc.origin_asset_id)
        if origin is not None:
            _asset_node(origin)
            flow = 1 + int((inc.meta or {}).get("pivot_count", 0))
            _edge(attn, origin.asset_id, kind="foothold", flow=flow)
        if not trapped and inc.predicted_target_id:
            _tgt_id = inc.predicted_target_id
            _tgt = by_id.get(_tgt_id)
            if _tgt is not None and _tgt.status != AssetStatus.OFFLINE:
                _asset_node(_tgt)
                _head = _tgt_id
            else:
                _head = f"PRED-{_tgt_id}"
                if _head not in node_ids:
                    node_ids.add(_head)
                    nodes.append({
                        "id": _head, "type": "forecast", "role": "forecast",
                        "status": "predicted", "label": inc.predicted_target_name or _tgt_id,
                        "forecast_of": _tgt_id,
                        "asset_type": _tgt.asset_type if _tgt else "server",
                        "criticality": _tgt.criticality if _tgt else None,
                    })
            _pd = (predictions or {}).get(inc.incident_id) or {}
            _edge(attn, _head, kind="prediction", flow=0,
                  actor_id=attn, confidence=_pd.get("confidence"))
        if trapped:
            mon = (inc.meta or {}).get("monitoring") or {}
            decoy = by_id.get(mon.get("decoy"))
            if decoy is not None:
                _asset_node(decoy, extra={"capture_of": attn})
                _edge(attn, decoy.asset_id, kind="capture", flow=3)
        for bait_id in (inc.meta or {}).get("baits", []):
            bait = by_id.get(bait_id)
            if bait is None:
                continue
            _asset_node(bait, extra={
                "bait": True, "ring_of": attn,
                "presented_as": (bait.meta or {}).get("presented_as", bait.service),
            })
            _edge(attn, bait.asset_id, kind="bait", flow=2)
            _edge("HONEYNET" if "HONEYNET" in node_ids else "CORE-SWITCH",
                  bait.asset_id, kind="membership")

    # Maintenance zone: contained real servers being rebuilt from clean state.
    maint_servers = [a for a in assets_rows
                     if a.role == AssetRole.SERVER and a.is_physical
                     and (a.meta or {}).get("maintenance")]
    if maint_servers:
        _infra("MAINTENANCE", "MAINTENANCE", "zone")
        if "THREAT-ZONE" in node_ids:
            _edge("THREAT-ZONE", "MAINTENANCE", kind="zone")
        for a in maint_servers:
            _asset_node(a)
            _edge("MAINTENANCE", a.asset_id, kind="maintenance", flow=2)

    return {"nodes": nodes, "edges": edges}


def build_forecast_view(incident: Optional[DemoIncident],
                        prediction: Optional[PredictionRecord]) -> Optional[Dict]:
    if not incident or not prediction:
        return None
    belief = prediction.belief or {}
    branches = []
    n_branches = belief.get("branches", 0)
    if isinstance(n_branches, int) and n_branches > 0:
        agreement = float(belief.get("consensus_agreement", 0.0))
        worst = belief.get("worst_case") or {}
        if isinstance(worst, str):
            worst = {"terminal_stage": worst}
        elif not isinstance(worst, dict):
            worst = {}
        branch_details = belief.get("branch_details")
        branch_spec = branch_details if isinstance(branch_details, list) else None
        if branch_spec:
            for d in branch_spec[:n_branches]:
                branches.append({
                    "branch": int(d.get("branch", len(branches) + 1)) + 1,
                    "confidence": round(agreement, 3),
                    "target": prediction.predicted_target,
                    "stage": d.get("terminal_stage") or worst.get("terminal_stage") or prediction.current_stage,
                    "risk": round(float(d.get("peak_infil_risk", 0.0)) * 100, 1),
                })
        else:
            for i in range(n_branches):
                branches.append({
                    "branch": i + 1,
                    "confidence": round(agreement, 3),
                    "target": prediction.predicted_target,
                    "stage": worst.get("terminal_stage") or prediction.current_stage,
                    "risk": round(float(worst.get("peak_infil_risk", 0.0)) * 100, 1),
                })
        branches.sort(key=lambda b: -b["risk"])
    elif isinstance(belief.get("branches"), list):
        for i, b in enumerate(belief["branches"]):
            branches.append({
                "branch": i + 1,
                "confidence": round(float(b.get("confidence", 0)), 3),
                "target": prediction.predicted_target,
                "stage": b.get("terminal_stage"),
                "risk": round(float(b.get("peak_risk", 0)), 1),
            })

    return {
        "incident_id": prediction.incident_id,
        "model": prediction.model_version,
        "current_stage": prediction.current_stage,
        "predicted_stages": prediction.predicted_stages,
        "predicted_target": prediction.predicted_target,
        "confidence": prediction.confidence,
        "risk_score": prediction.risk_score,
        "risk_level": prediction.risk_level,
        "lead_time": prediction.lead_time_seconds,
        "belief": {"branches": branches[:5],
                    "consensus": prediction.predicted_target,
                    "agreement": float(belief.get("consensus_agreement", 0.0)),
                    "chain_of_thought": belief.get("chain_of_thought", []),
                    "novelty": belief.get("novelty", [])},
        "explanation": prediction.explanation,
    }


async def export_training_samples(db: AsyncSession) -> Dict:
    """Dump every interaction from these runs into an append-only training set.

    Written OUTSIDE the repo (TRAINING_EXPORT_PATH) so demo runs stay removable
    from the project while attack samples keep accumulating for the later model
    retrain: predictions, evidenced intel/telemetry, decoy sessions, challenge
    answers and actor correlations are kept as labelled JSONL samples.
    """
    import json as _json
    from pathlib import Path

    incidents = {i.incident_id: i
                 for i in (await db.execute(select(DemoIncident))).scalars().all()}
    evidence = (await db.execute(select(EvidenceRecord))).scalars().all()
    preds = (await db.execute(select(PredictionRecord))).scalars().all()
    challenges = (await db.execute(select(Challenge))).scalars().all()
    interactions = (await db.execute(select(DecoyInteraction))).scalars().all()
    correlations = (await db.execute(select(ActorCorrelation))).scalars().all()

    rows: List[Dict] = []
    for p in preds:
        inc = incidents.get(p.incident_id)
        rows.append({
            "kind": "prediction", "incident_id": p.incident_id, "actor": p.actor_id,
            "model_version": p.model_version, "origin": inc.origin_asset_id if inc else None,
            "current_stage": p.current_stage, "predicted_stages": p.predicted_stages,
            "predicted_target": p.predicted_target, "confidence": p.confidence,
            "risk_score": p.risk_score, "risk_level": p.risk_level,
            "lead_time_seconds": p.lead_time_seconds,
            "created_at": p.created_at.isoformat(sep=" ", timespec="seconds")
                if p.created_at else None,
        })
    for e in evidence:
        rows.append({
            "kind": "evidence", "incident_id": e.incident_id, "type": e.evidence_type,
            "source": e.source, "payload": e.payload,
            "captured_at": e.created_at.isoformat(sep=" ", timespec="seconds")
                if e.created_at else None,
        })
    for c in challenges:
        rows.append({
            "kind": "challenge", "incident_id": c.incident_id, "question": c.question,
            "answer": c.provided_answer, "level": c.result_level,
        })
    for i in interactions:
        rows.append({
            "kind": "decoy_interaction", "incident_id": i.incident_id,
            "decoy": i.decoy_asset_id, "device": i.device_context, "answers": i.answers,
        })
    for co in correlations:
        rows.append({
            "kind": "correlation", "correlation_id": co.correlation_id,
            "actors": co.actor_ids, "method": co.method, "target": co.target,
            "confidence": co.confidence,
        })
    for inc in incidents.values():
        kept = {k: v for k, v in (inc.meta or {}).items()
                if k in ("pivot_count", "trajectory_id")}
        rows.append({
            "kind": "incident", "incident_id": inc.incident_id, "actor": inc.attacker,
            "origin": inc.origin_asset_id, "predicted_target": inc.predicted_target_id,
            "stage": inc.stage, "level": inc.simulation_level,
            "status": inc.status.value, "deception": inc.deception_activated,
            "contained": inc.contained_asset_ids, "trapped": _is_trapped(inc),
            "monitoring": bool((inc.meta or {}).get("monitoring")),
            "meta": kept,
            "started_at": inc.started_at.isoformat(sep=" ", timespec="seconds")
                if inc.started_at else None,
        })

    path = Path(settings.TRAINING_EXPORT_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as _f:
        for r in rows:
            _f.write(_json.dumps(r) + "\n")
    total = sum(1 for _ in path.open("r", encoding="utf-8"))
    return {"exported": len(rows), "path": str(path), "total_in_file": total}
