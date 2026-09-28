"""
Demo public API: join, device page state, attacker flow, decoy interaction,
heartbeat and live SSE stream.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.runtime import base_url, decoy_questions
from app.models.demo import (
    Participant, ParticipantRole, DemoAsset, DemoIncident,
    AssetStatus, AssetRole, DecoyInteraction, DemoEvent, EvidenceRecord,
    IncidentStatus, ThreatActor, ThreatTrajectory, Challenge,
)
from app.services import simulation_engine as engine
from app.services.event_bus import bus
from app.services.risk_policy import fusion_risk

router = APIRouter()


def _client_context(request: Request) -> Dict[str, Any]:
    ua = request.headers.get("user-agent", "")
    lower = ua.lower()
    if "android" in lower or "mobile" in lower:
        category = "Mobile"
    elif "iphone" in lower or "ipad" in lower:
        category = "Mobile"
    else:
        category = "Desktop"
    platform = "Android" if "android" in lower else (
        "iOS" if "iphone" in lower or "ipad" in lower else (
            "Windows" if "windows" in lower else (
                "macOS" if "mac os" in lower else ("Linux" if "linux" in lower else "Unknown"))))
    browser = "Chrome" if "chrome" in lower and "edg" not in lower else (
        "Edge" if "edg" in lower else (
            "Safari" if "safari" in lower else (
                "Firefox" if "firefox" in lower else "Unknown")))
    return {
        "category": category,
        "platform": platform,
        "browser": browser,
        "viewport": "_UNKNOWN",
        "language": request.headers.get("accept-language", "")[:64],
        "timestamp": datetime.utcnow().isoformat(),
    }


def _validate_role(role: str) -> ParticipantRole:
    try:
        return ParticipantRole(role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")


@router.get("/config")
async def public_config(request: Request, db: AsyncSession = Depends(get_db)):
    # A configured LAN URL wins over a presenter's localhost Origin. This lets
    # the presenter use localhost while audience phones reach the host on wlan0.
    origin = request.headers.get("origin", "").rstrip("/")
    configured = base_url().rstrip("/")
    pub = configured if "localhost" not in configured and "127.0.0.1" not in configured else (origin or configured)
    api = pub.replace(":8088", ":8100", 1) + settings.DEMO_PREFIX
    return {
        "name": "Predictive Cyber Defence — Live Cyber-Range",
        "mode": "controlled",
        "simulation": True,
        "roles": [r.value for r in ParticipantRole],
        "join_url": "/join",
        "public_base_url": pub,
        "api_base_url": api,
    }


DEVICE_JOIN_ROLES = ("server", "host", "client", "other")


@router.post("/join")
async def join(role: str = Query(...), request: Request = None,
               db: AsyncSession = Depends(get_db)):
    role_enum = _validate_role(role)
    ctx = _client_context(request)
    prefix = {"attacker": "A", **{r: "D" for r in DEVICE_JOIN_ROLES}}.get(role, "P")
    # The join id is the public identity of this browser/device session; keep it
    # short for the UI but regen on collision (orphaned joins accumulate across
    # demo resets, so 4-hex ids are not enough to be born-unique).
    participant_id = None
    token = uuid.uuid4().hex
    for _ in range(10):
        candidate = f"{prefix}-{uuid.uuid4().hex[:6].upper()}"
        p = Participant(participant_id=candidate, role=role_enum,
                        device_context=ctx, token=token,
                        last_seen=datetime.utcnow())
        db.add(p)
        try:
            await db.flush()
            participant_id = candidate
            break
        except IntegrityError:
            await db.rollback()
    if participant_id is None:
        raise HTTPException(status_code=500, detail="Could not allocate a session id")

    result = {
        "participant_id": participant_id,
        "role": role_enum.value,
        "token": token,
        "device_context": ctx,
        "asset_id": None,
        "page_endpoint": None,
    }
    # Device roles register a physical asset on the range the moment they join.
    # No pre-created assets exist — the device's identity comes from the join.
    if role in DEVICE_JOIN_ROLES:
        client_ip = None
        if request and request.client and request.client.host:
            client_ip = request.client.host
        short = participant_id.split("-")[-1].lower()
        device = await engine.register_device(
            db,
            hostname=f"{role}-{short}",
            role=role,
            ip=client_ip,
            device_type=None,
            participant_id=participant_id,
        )
        result["asset_id"] = device.asset_id
        result["page_endpoint"] = f"/device/{device.asset_id}"
        result["hostname"] = device.hostname
        result["device_type"] = device.asset_type
        device.page_endpoint = result["page_endpoint"]
        await db.flush()
    return result


async def _participant(token: str, db: AsyncSession) -> Participant:
    res = await db.execute(select(Participant).where(Participant.token == token))
    p = res.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=401, detail="Unknown session")
    return p


@router.get("/me")
async def me(token: str = Query(...), db: AsyncSession = Depends(get_db)):
    p = await _participant(token, db)
    incident = await engine.get_active_incident(db)
    return {
        "participant_id": p.participant_id,
        "role": p.role.value,
        "device_context": p.device_context,
        "incident": None,
    }


@router.get("/assets")
async def public_assets(db: AsyncSession = Depends(get_db)):
    rows = await engine.connected_devices(db)
    return [
        {"id": a.asset_id, "hostname": a.hostname, "role": a.role.value,
         "status": a.status.value, "service": a.service, "ip": a.ip,
         "asset_type": a.asset_type}
        for a in rows
    ]


@router.post("/device/register")
async def device_register(body: dict, db: AsyncSession = Depends(get_db)):
    """Registration endpoint for real network devices (JSON over HTTP)."""
    a = await engine.register_device(
        db,
        asset_id=body.get("asset_id"),
        hostname=body.get("hostname") or body.get("device_id"),
        role=body.get("role") or "other",
        ip=body.get("ip"),
        device_type=body.get("device_type") or body.get("type"),
        page_endpoint=body.get("page_endpoint"),
    )
    await db.flush()
    return {"asset_id": a.asset_id, "hostname": a.hostname, "role": a.role.value,
            "status": a.status.value, "registered": True}


@router.get("/asset/{asset_id}/state")
async def asset_state(asset_id: str, db: AsyncSession = Depends(get_db)):
    a = await engine.get_asset(db, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    incidents = await engine.list_active_incidents(db)
    predicted = any(i.predicted_target_id == asset_id for i in incidents)
    contained = any(asset_id in (i.contained_asset_ids or []) for i in incidents)
    orig = next((i for i in incidents if i.origin_asset_id == asset_id), None)
    service = None
    maint = (a.meta or {}).get("maintenance") or None
    if a.role == AssetRole.SERVER:
        svc = engine.service_status(await engine.list_assets(db))
        service = {
            "domain": svc["domain"],
            "serving": a.status.value not in ("compromised", "contained", "offline"),
            "fallback": svc["fallback"],
            "status": svc["status"],
        }
    trap_for = next((i for i in incidents if engine._is_trapped(i)), None)
    return {
        "id": a.asset_id,
        "hostname": a.hostname,
        "status": a.status.value,
        "role": a.role.value,
        "service": service if a.role == AssetRole.SERVER else a.service,
        "asset_type": a.asset_type,
        "ip": a.ip,
        "zone": a.zone,
        "registered": a.registered,
        "page_endpoint": a.page_endpoint,
        "predicted_target": predicted,
        "contained": contained,
        "trapped": trap_for is not None,
        "maintenance": engine._maintenance_info(a) if maint else None,
        "deception_active": bool(any(i.deception_activated for i in incidents)),
        "stage": orig.stage if orig else None,
        "actor": orig.attacker if orig else None,
        "risk": None,
        "service": service,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
    }


@router.post("/heartbeat")
async def heartbeat(body: dict, db: AsyncSession = Depends(get_db)):
    asset_id = body.get("asset_id", "").strip().upper() or None
    a = await engine.device_heartbeat(
        db, asset_id=asset_id, hostname=body.get("hostname"),
        ip=body.get("ip"), page_endpoint=body.get("page_endpoint"),
        device_type=body.get("device_type"))
    await db.flush()
    # Keep the owning participant's last_seen alive so live metrics / scoring
    # can tell who is actually present on the range right now.
    owner = (a.meta or {}).get("owner") if a.meta else None
    if owner:
        owner_row = (await db.execute(
            select(Participant).where(Participant.participant_id == owner)
        )).scalar_one_or_none()
        if owner_row:
            owner_row.last_seen = datetime.utcnow()
            await db.flush()
    return {"asset_id": a.asset_id, "online": True, "registered": a.registered,
            "role": a.role.value, "status": a.status.value}


# ---- Attacker flow --------------------------------------------------------

@router.get("/attacker/options")
async def attacker_options(token: str = Query(...), db: AsyncSession = Depends(get_db)):
    p = await _participant(token, db)
    if p.role != ParticipantRole.ATTACKER:
        raise HTTPException(status_code=403, detail="Attacker role required")
    rows = await engine.connected_devices(db)
    targets = [{"id": a.asset_id, "name": a.hostname, "role": a.role.value,
                "asset_type": a.asset_type, "service": a.service, "ip": a.ip,
                "status": a.status.value}
               for a in rows]
    return {"targets": targets}


@router.post("/attacker/start")
async def attacker_start(token: str = Query(...), target: str = Query(""),
                         db: AsyncSession = Depends(get_db)):
    p = await _participant(token, db)
    try:
        result = await engine.start_attack(db, p, target.upper())
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    await db.flush()
    return result


@router.post("/attacker/answer")
async def attacker_answer(token: str = Query(...), incident_id: str = Query(...),
                          answer: str = Query(...), db: AsyncSession = Depends(get_db)):
    try:
        result = await engine.answer_challenge(db, incident_id, token, answer)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    await db.flush()
    return result


@router.get("/attacker/state")
async def attacker_state(token: str = Query(...), db: AsyncSession = Depends(get_db)):
    p = await _participant(token, db)
    incident = await engine.active_incident_for_participant(db, p.participant_id)
    if not incident:
        return {"state": "idle", "incident": None}
    pred = (await db.execute(select(engine.PredictionRecord)
            .where(engine.PredictionRecord.incident_id == incident.incident_id)
            .order_by(desc(engine.PredictionRecord.created_at)).limit(1))).scalar_one_or_none()
    origin_asset = (await engine.get_asset(db, incident.origin_asset_id)
                    if incident.origin_asset_id else None)
    chall = (await db.execute(
        select(Challenge).where(Challenge.incident_id == incident.incident_id)
        .order_by(desc(Challenge.created_at)).limit(1)
    )).scalar_one_or_none()
    # Surface an unanswered challenge so the console can restore the handshake
    # after a refresh (answered challenges already have provided_answer set).
    pending = None
    if chall and not chall.provided_answer:
        pending = {"challenge_id": str(chall.id), "question": chall.question,
                   "options": engine._challenge_options(chall)}
    return {
        "state": "trapped" if engine._is_trapped(incident) else
                 ("active" if incident.status != IncidentStatus.RESOLVED else "resolved"),
        "challenge": pending,
        "incident": {
            "incident_id": incident.incident_id,
            "status": incident.status.value,
            "stage": incident.stage,
            "level": incident.simulation_level,
            "origin": incident.origin_asset_id,
            "origin_name": (origin_asset.hostname if origin_asset
                            else incident.origin_asset_id),
            "predicted_target": incident.predicted_target_name,
            "deception_active": incident.deception_activated,
            "decoy": incident.decoy_asset_id,
            "trapped": engine._is_trapped(incident),
            "monitoring": (incident.meta or {}).get("monitoring"),
            "pivot_count": incident.meta.get("pivot_count", 0),
            "prediction": engine.build_forecast_view(incident, pred),
        },
    }


@router.get("/attacker/pivot-options")
async def attacker_pivot_options(token: str = Query(...), db: AsyncSession = Depends(get_db)):
    p = await _participant(token, db)
    if p.role != ParticipantRole.ATTACKER:
        raise HTTPException(status_code=403, detail="Attacker role required")
    incident = await engine.active_incident_for_participant(db, p.participant_id)
    if not incident:
        raise HTTPException(status_code=409, detail="No active engagement for this attacker")
    options, hint = await engine.lateral_targets(db, incident)
    return {"origin": incident.origin_asset_id, "pivot_options": options,
            "hint": hint}


@router.post("/attacker/pivot")
async def attacker_pivot(token: str = Query(...), incident_id: str = Query(...),
                         target: str = Query(...), db: AsyncSession = Depends(get_db)):
    p = await _participant(token, db)
    try:
        result = await engine.pivot_origin(db, p, incident_id, target)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    await db.flush()
    return result


# ---- Decoy flow -----------------------------------------------------------

@router.get("/decoy/questions")
async def decoy_questions_api(token: str = Query(...), db: AsyncSession = Depends(get_db)):
    await _participant(token, db)
    return {"questions": decoy_questions()}


@router.post("/decoy/interact")
async def decoy_interact(token: str = Query(...), incident_id: str = Query(...),
                         body: dict = None, db: AsyncSession = Depends(get_db)):
    answers = (body or {}).get("answers", [])
    context = (body or {}).get("context")
    try:
        result = await engine.record_decoy_interaction(
            db, incident_id, token, answers, context=context)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    await db.flush()
    return result


# ---- Command center data ---------------------------------------------------

@router.get("/command/overview")
async def command_overview(db: AsyncSession = Depends(get_db)):
    rows = await engine.connected_devices(db)
    all_rows = await engine.list_assets(db)
    decoys = [a for a in all_rows if a.role == AssetRole.DECOY]
    registered_total = sum(1 for a in all_rows if a.is_physical and a.registered)
    incidents = await engine.list_active_incidents(db)
    participants = (await db.execute(select(Participant))).scalars().all()
    evidence = (await db.execute(
        select(EvidenceRecord).order_by(desc(EvidenceRecord.created_at)).limit(200)
    )).scalars().all()

    async def _incident_summary(inc: DemoIncident) -> Dict:
        pred = (await db.execute(
            select(engine.PredictionRecord)
            .where(engine.PredictionRecord.incident_id == inc.incident_id)
            .order_by(desc(engine.PredictionRecord.created_at)).limit(1)
        )).scalar_one_or_none()
        return {
            "id": inc.incident_id,
            "status": inc.status.value,
            "stage": inc.stage,
            "level": inc.simulation_level,
            "origin": inc.origin_asset_id,
            "predicted_target": inc.predicted_target_name,
            "predicted_target_id": inc.predicted_target_id,
            "deception": inc.deception_activated,
            "decoy": inc.decoy_asset_id,
            "actor": inc.attacker,
            "trapped": engine._is_trapped(inc),
            "pivot_count": inc.meta.get("pivot_count", 0),
            "prediction": engine.build_forecast_view(inc, pred),
        }

    summaries = [await _incident_summary(i) for i in incidents]

    # Multi-actor convergence: count distinct trajectories pointing at one asset
    by_target: Dict[str, List[Dict]] = {}
    for s in summaries:
        if not s["predicted_target_id"]:
            continue
        by_target.setdefault(s["predicted_target_id"], []).append(s)
    converging = []
    for target_id, lst in by_target.items():
        if len(lst) < 2:
            continue
        fused = fusion_risk([s["prediction"]["risk_score"] for s in lst
                             if s.get("prediction") and s["prediction"]["risk_score"] is not None]
                            or [50.0] * len(lst))
        converging.append({
            "target": target_id,
            "actors": [s["actor"] for s in lst],
            "incidents": [s["id"] for s in lst],
            "count": len(lst),
            "consensus": "botnet" if len(lst) >= 3 else "convergence",
            "risk_score": fused["risk_score"],
            "risk_level": fused["risk_level"],
        })

    actors = [{
        "actor": s["actor"],
        "incident_id": s["id"],
        "origin": s["origin"],
        "stage": s["stage"],
        "level": s["level"],
        "predicted_target": s["predicted_target"],
        "predicted_target_id": s["predicted_target_id"],
        "deception": s["deception"],
        "decoy": s["decoy"],
        "status": s["status"],
        "trapped": s["trapped"],
        "pivot_count": s["pivot_count"],
        "risk_level": (s["prediction"] or {}).get("risk_level"),
        "risk_score": (s["prediction"] or {}).get("risk_score"),
        "confidence": (s["prediction"] or {}).get("confidence"),
        "converging": any(s["predicted_target_id"] == c["target"] for c in converging),
    } for s in summaries]

    primary = summaries[0] if summaries else None
    if primary is None:
        primary = {
            "id": None, "status": None, "stage": None, "level": 0,
            "origin": None, "predicted_target": None, "predicted_target_id": None,
            "deception": False, "decoy": None, "actor": None, "pivot_count": 0,
            "trapped": False,
            "prediction": None,
        }
    service = engine.service_status(all_rows)
    maintenance = service.get("maintenance") or []
    trapped = sum(1 for s in summaries if s["trapped"])

    # Live participant presence: count only people actually on the range now
    # (owners of currently online devices, engaged attackers, or anyone with a
    # last_seen inside the heartbeat window) rather than every join ever.
    now = datetime.now(timezone.utc)
    timeout = timedelta(seconds=settings.DEMO_HEARTBEAT_TIMEOUT)

    def _recent(p: Participant) -> bool:
        ls = p.last_seen
        if not ls:
            return False
        if ls.tzinfo is None:
            ls = ls.replace(tzinfo=timezone.utc)
        return (now - ls) <= timeout

    owner_online = {(a.meta or {}).get("owner") for a in rows if (a.meta or {}).get("owner")}
    active_attackers = {s.get("actor") for s in summaries if s.get("actor")}
    live_participants = [
        p for p in participants
        if p.participant_id in owner_online
        or (p.role == ParticipantRole.ATTACKER and
            (p.participant_id in active_attackers or _recent(p)))
        or (p.role != ParticipantRole.OBSERVER and _recent(p))
    ]
    return {
        "simulation": True,
        "mode": "controlled",
        "threats": len(summaries),
        "contained": sum(1 for a in rows if a.status.value == "contained"),
        "decoys": len(decoys),
        "trapped": trapped,
        "maintenance": maintenance,
        "healthy": sum(1 for a in rows if a.status.value == "healthy"),
        "assets": registered_total,
        "online_assets": len(rows),
        "participants": len(live_participants),
        "participants_total": len(participants),
        "attackers": sum(1 for p in live_participants if p.role == ParticipantRole.ATTACKER),
        "attackers_total": sum(1 for p in participants if p.role == ParticipantRole.ATTACKER),
        "incidents": summaries,
        "actors": actors,
        "convergence": converging,
        "incident": primary,
        "prediction": primary["prediction"] if primary else None,
        "service": service,
        "evidence_count": len(evidence),
    }


@router.get("/command/participants")
async def command_participants(db: AsyncSession = Depends(get_db)):
    """Live participant scoreboard: ranks everyone on the range right now.

    Score is built from observable demo behaviour — presence, online heartbeat,
    engagement in the incident, being a predicted target, and entering the
    honeypot — and drives the score tags on the live timeline.
    """
    participants = (await db.execute(
        select(Participant).order_by(desc(Participant.created_at))
    )).scalars().all()
    rows = await engine.connected_devices(db)
    all_rows = await engine.list_assets(db)
    incidents = await engine.list_active_incidents(db)

    online_ids = {a.asset_id for a in rows}
    asset_by_owner: Dict[str, DemoAsset] = {}
    for a in all_rows:
        owner = (a.meta or {}).get("owner")
        if owner:
            asset_by_owner.setdefault(owner, a)

    origin_ids = {i.origin_asset_id for i in incidents if i.origin_asset_id}
    predicted_ids = {i.predicted_target_id for i in incidents if i.predicted_target_id}
    engaged_attackers = {i.attacker for i in incidents if i.attacker}

    interacted = set()
    for ev in (await db.execute(
            select(DemoEvent.kind, DemoEvent.payload).where(DemoEvent.kind == "decoy_interaction")
    )).all():
        actor = (ev.payload or {}).get("actor")
        if actor:
            interacted.add(actor)

    now = datetime.now(timezone.utc)
    timeout = timedelta(seconds=settings.DEMO_HEARTBEAT_TIMEOUT)

    def _recent(p: Participant) -> bool:
        ls = p.last_seen
        if not ls:
            return False
        if ls.tzinfo is None:
            ls = ls.replace(tzinfo=timezone.utc)
        return (now - ls) <= timeout

    out = []
    for p in participants:
        asset = asset_by_owner.get(p.participant_id)
        online = bool(asset and asset.asset_id in online_ids)
        engaged = p.participant_id in engaged_attackers
        targeted = bool(asset and (asset.asset_id in origin_ids or asset.asset_id in predicted_ids))
        score = 30  # joined
        chips = ["joined"]
        if online:
            score += 25
            chips.append("online")
        if p.role == ParticipantRole.ATTACKER and engaged:
            score += 25
            chips.append("engaged")
        elif targeted:
            score += 15
            chips.append("crosshairs")
        if _recent(p):
            score += 5
            chips.append("active")
        if p.participant_id in interacted:
            score += 10
            chips.append("honeypot")
        score = min(100, score)
        level = "tier-1" if score >= 85 else "advanced" if score >= 65 else "active" if score >= 45 else "volunteer"
        out.append({
            "participant_id": p.participant_id,
            "role": p.role.value,
            "browser": (p.device_context or {}).get("browser"),
            "platform": (p.device_context or {}).get("platform"),
            "asset_id": asset.asset_id if asset else None,
            "asset_role": asset.role.value if asset else None,
            "asset_status": asset.status.value if asset else None,
            "online": online,
            "engaged": engaged,
            "score": score,
            "level": level,
            "chips": chips,
            "last_seen": p.last_seen.isoformat(sep=" ", timespec="seconds") if p.last_seen else None,
            "joined": p.created_at.isoformat(sep=" ", timespec="seconds"),
        })
    out.sort(key=lambda r: (-r["score"], r["participant_id"]))
    return {
        "participants": out,
        "live": sum(1 for r in out if r["online"]),
        "max_score": 100,
    }


@router.get("/command/topology")
async def command_topology(db: AsyncSession = Depends(get_db)):
    rows = await engine.list_assets(db)
    incidents = await engine.list_active_incidents(db)
    by_id = {a.asset_id: a for a in rows}

    pred_rows = (await db.execute(
        select(engine.PredictionRecord).order_by(engine.PredictionRecord.created_at))).scalars().all()
    preds: Dict[str, Any] = {}
    for _p in pred_rows:
        preds[_p.incident_id] = _p
    active_ids = {i.incident_id for i in incidents}
    pred_meta = {i.incident_id: {
        "confidence": (preds[i.incident_id].confidence if i.incident_id in preds else None),
    } for i in incidents}

    forecasts: List[Dict] = []
    actors: List[Dict] = []
    containment: List[Dict] = []
    deception: List[Dict] = []
    for inc in incidents:
        _p = preds.get(inc.incident_id)
        fv = engine.build_forecast_view(inc, _p) if _p else None
        if fv:
            forecasts.append(fv)
        _origin = by_id.get(inc.origin_asset_id)
        actors.append({
            "actor": inc.attacker,
            "incident_id": inc.incident_id,
            "origin": inc.origin_asset_id,
            "origin_name": _origin.hostname if _origin else None,
            "origin_status": _origin.status.value if _origin else None,
            "stage": inc.stage,
            "status": inc.status.value,
            "trapped": engine._is_trapped(inc),
            "deception_active": bool(inc.deception_activated),
            "monitoring": bool((inc.meta or {}).get("monitoring")),
            "predicted_target_id": inc.predicted_target_id,
            "predicted_target": inc.predicted_target_name,
            "pivot_count": (inc.meta or {}).get("pivot_count", 0),
            "confidence": _p.confidence if _p else None,
            "risk_score": _p.risk_score if _p else None,
            "risk_level": _p.risk_level if _p else None,
        })
        for _cid in (inc.contained_asset_ids or []):
            _ca = by_id.get(_cid)
            containment.append({
                "asset_id": _cid,
                "name": _ca.hostname if _ca else None,
                "actor": inc.attacker,
                "incident_id": inc.incident_id,
                "contained": True,
            })
        if inc.deception_activated and inc.decoy_asset_id:
            _dec = by_id.get(inc.decoy_asset_id)
            if _dec:
                deception.append({
                    "decoy_id": _dec.asset_id,
                    "decoy_name": _dec.hostname,
                    "incident_id": inc.incident_id,
                    "actor": inc.attacker,
                    "predicted_target_id": inc.predicted_target_id,
                    "predicted_target": inc.predicted_target_name,
                    "status": _dec.status.value,
                    "stage": inc.stage,
                    "explanation": _p.explanation if _p else None,
                })

    _groups: Dict[str, Dict] = {}
    for inc in incidents:
        _tgt = inc.predicted_target_id
        if not _tgt:
            continue
        _p = preds.get(inc.incident_id)
        _g = _groups.setdefault(_tgt, {
            "target": _tgt,
            "target_name": inc.predicted_target_name,
            "incident_ids": [],
            "actors": [],
        })
        if inc.incident_id not in _g["incident_ids"]:
            _g["incident_ids"].append(inc.incident_id)
        _g["actors"].append({
            "actor": inc.attacker,
            "incident_id": inc.incident_id,
            "stage": inc.stage,
            "confidence": _p.confidence if _p else None,
            "risk_score": _p.risk_score if _p else None,
            "risk_level": _p.risk_level if _p else None,
        })
    convergence: List[Dict] = []
    for _g in _groups.values():
        _scores = [a["risk_score"] for a in _g["actors"] if a["risk_score"] is not None]
        _fus = fusion_risk(_scores) if len(_scores) >= 2 else None
        _g["count"] = len(_g["actors"])
        _g["aggregate_risk_score"] = _fus["risk_score"] if _fus else None
        _g["aggregate_risk_level"] = _fus["risk_level"] if _fus else None
        _g["correlation_id"] = ("CORR-" + "-".join(
            sorted(a["actor"] for a in _g["actors"]))) if _g["count"] >= 2 else None
        convergence.append(_g)
    convergence.sort(key=lambda g: -(g["count"] or 0))

    graph = engine.build_topology(rows, incidents, predictions=pred_meta)
    graph["predictions"] = forecasts
    graph["actors"] = actors
    graph["containment"] = containment
    graph["deception"] = deception
    graph["assets"] = [{
        "id": a.asset_id,
        "name": a.hostname,
        "role": a.role.value,
        "asset_type": a.asset_type or "device",
        "status": a.status.value,
        "zone": a.zone,
        "ip": a.ip,
        "criticality": a.criticality,
        "registered": bool(a.is_physical and a.registered),
        "decoy": a.role == AssetRole.DECOY,
        "service": a.service,
    } for a in rows]
    graph["infrastructure"] = [n for n in graph["nodes"] if n.get("type") == "infra"]
    graph["services"] = engine.service_status(rows)
    graph["convergence"] = convergence
    return graph


@router.get("/command/health")
async def command_health(db: AsyncSession = Depends(get_db)):
    """Presenter health strip (no PIN needed on the public command center)."""
    from app.services.world_model_adapter import model_ready, model_version, feature_dim
    try:
        await db.execute(select(DemoIncident).limit(1))
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "db": db_ok,
        "model": model_ready(),
        "model_version": model_version(),
        "feature_dim": feature_dim(),
        "sse": True,
        "simulation": True,
        "ts": datetime.utcnow().isoformat(timespec="seconds"),
    }


@router.get("/ai/observability")
async def ai_observability(db: AsyncSession = Depends(get_db)):
    """Read-only demo model and data-provenance dashboard payload."""
    from pathlib import Path
    from app.services.world_model_adapter import model_ready, model_version, feature_dim
    from app.services.ai_training import status as training_status, build_training_plan
    from app.services.schema_intelligence import status as schema_status
    samples = Path(settings.TRAINING_EXPORT_PATH)
    records = sum(1 for _ in samples.open("r", encoding="utf-8")) if samples.exists() else 0
    events = (await db.execute(select(func.count()).select_from(DemoEvent))).scalar_one()
    assets = await engine.connected_devices(db)
    train_state = training_status()
    plan = build_training_plan(
        records,
        current_metrics={
            "model_version": model_version(),
            "stage_accuracy": None,
            "infiltration_accuracy": None,
            "macro_f1": None,
            "val_loss": None,
        },
        schema_scan=schema_status(),
    )
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "model": {"ready": model_ready(), "version": model_version(), "feature_dim": feature_dim(), "kind": "temporal flow world model", "serving_checkpoint": "validated serving checkpoint"},
        "range": {"real_devices": len(assets), "live_telemetry_events": events, "simulation": True, "scanner": "QR join + heartbeat observer"},
        "training": {
            "demo_records": records,
            "candidate": schema_status().get("manifest"),
            "promotion": "manual review required",
            "status": train_state,
            "plan": plan,
        },
        "schema_intake": schema_status(),
        "knowledge_flow": [
            {"label": "Real devices", "detail": "QR joins and heartbeats"},
            {"label": "Range telemetry", "detail": "bounded simulated engagement signals"},
            {"label": "World model", "detail": "multi-step forecast and belief branches"},
            {"label": "Policy", "detail": "containment and deception recommendation"},
        ],
    }


@router.get("/command/timeline")
async def command_timeline(limit: int = Query(40, ge=1, le=200), db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(DemoEvent).order_by(desc(DemoEvent.timestamp)).limit(limit))
    rows = res.scalars().all()
    rows.reverse()
    out = []
    for e in rows:
        payload = e.payload or {}
        actor_id = next((payload.get(k) for k in ("actor", "actor_id", "actor_participant_id")
                         if payload.get(k) is not None), None)
        asset_id = next((payload.get(k) for k in ("asset_id", "target", "decoy", "from", "origin",
                                                  "decoy_id", "current_asset")
                         if payload.get(k) is not None), None)
        out.append({
            "event_id": e.event_id, "kind": e.kind,
            "timestamp": e.timestamp.isoformat(sep=" ", timespec="seconds"),
            "incident_id": e.incident_id, "simulation": e.simulation,
            "source": e.source, "payload": payload,
            "actor_id": actor_id or (e.source if e.incident_id else None),
            "asset_id": asset_id,
        })
    return out


@router.get("/command/forecast")
async def command_forecast(db: AsyncSession = Depends(get_db)):
    incident = await engine.get_active_incident(db)
    if not incident:
        return {"incident": None, "prediction": None, "incidents": []}
    pred = (await db.execute(
        select(engine.PredictionRecord)
        .where(engine.PredictionRecord.incident_id == incident.incident_id)
        .order_by(desc(engine.PredictionRecord.created_at)).limit(1)
    )).scalar_one_or_none()
    forecasts = []
    for inc in await engine.list_active_incidents(db):
        p = (await db.execute(
            select(engine.PredictionRecord)
            .where(engine.PredictionRecord.incident_id == inc.incident_id)
            .order_by(desc(engine.PredictionRecord.created_at)).limit(1)
        )).scalar_one_or_none()
        forecasts.append({
            "incident_id": inc.incident_id, "actor": inc.attacker,
            "origin": inc.origin_asset_id, "stage": inc.stage,
            "status": inc.status.value, "deception": inc.deception_activated,
            "decoy": inc.decoy_asset_id, "predicted_target": inc.predicted_target_name,
            "prediction": engine.build_forecast_view(inc, p),
        })
    return {"incident": {
        "id": incident.incident_id, "status": incident.status.value,
        "stage": incident.stage, "level": incident.simulation_level,
        "origin": incident.origin_asset_id,
        "predicted_target": incident.predicted_target_name,
        "deception": incident.deception_activated,
        "decoy": incident.decoy_asset_id,
        "actor": incident.attacker,
    }, "prediction": engine.build_forecast_view(incident, pred),
       "incidents": forecasts}


@router.get("/command/threats")
async def command_threats(db: AsyncSession = Depends(get_db)):
    incidents = await engine.list_active_incidents(db)
    actors = []
    converging = []
    risks: Dict[str, List[float]] = {}
    for inc in incidents:
        pred = (await db.execute(
            select(engine.PredictionRecord)
            .where(engine.PredictionRecord.incident_id == inc.incident_id)
            .order_by(desc(engine.PredictionRecord.created_at)).limit(1)
        )).scalar_one_or_none()
        risk = pred.risk_level if pred else None
        score = pred.risk_score if pred else None
        actors.append({
            "actor": inc.attacker,
            "origin": inc.origin_asset_id,
            "stage": inc.stage,
            "predicted_target": inc.predicted_target_name,
            "deception": inc.deception_activated,
            "risk": risk,
            "risk_score": score,
        })
        if inc.predicted_target_id:
            risks.setdefault(inc.predicted_target_id, []).append({
                "actor": inc.attacker, "score": score or 50.0, "incident_id": inc.incident_id,
            })
    for target_id, lst in risks.items():
        if len(lst) < 2:
            continue
        fused = fusion_risk([r["score"] for r in lst])
        target = (await db.execute(
            select(DemoAsset.hostname).where(DemoAsset.asset_id == target_id))).scalar_one_or_none()
        converging.append({
            "target": target_id, "target_name": target or target_id,
            "actors": [r["actor"] for r in lst],
            "incidents": [r["incident_id"] for r in lst],
            "risk_level": fused["risk_level"], "risk_score": fused["risk_score"],
        })
    return {"actors": actors, "converging": converging}


@router.get("/forensics/evidence")
async def forensics_evidence(incident_id: Optional[str] = None,
                             db: AsyncSession = Depends(get_db)):
    q = select(EvidenceRecord).order_by(desc(EvidenceRecord.created_at)).limit(200)
    if incident_id:
        q = (select(EvidenceRecord)
             .where(EvidenceRecord.incident_id == incident_id)
             .order_by(desc(EvidenceRecord.created_at)).limit(200))
    res = await db.execute(q)
    rows = res.scalars().all()
    return [{
        "evidence_id": e.evidence_id, "incident_id": e.incident_id,
        "type": e.evidence_type, "source": e.source, "simulation": e.simulation,
        "payload": e.payload, "timestamp": e.created_at.isoformat(sep=" ", timespec="seconds"),
    } for e in rows]


@router.get("/forensics/decoy-sessions")
async def decoy_sessions(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(DecoyInteraction).order_by(desc(DecoyInteraction.created_at)).limit(50))
    rows = res.scalars().all()
    return [{
        "session_ref": s.session_ref, "incident_id": s.incident_id,
        "decoy": s.decoy_asset_id, "device": s.device_context,
        "events": len(s.events), "comments": s.answers,
        "timestamp": s.created_at.isoformat(sep=" ", timespec="seconds"),
    } for s in rows]


# ---- Threat actors & trajectories (multi-actor surface) --------------------

async def _derive_trajectory(db: AsyncSession, incident: DemoIncident) -> Dict:
    """Derive an actor's trace from challenge levels + prediction records."""
    chals = (await db.execute(
        select(engine.Challenge).where(engine.Challenge.incident_id == incident.incident_id)
        .order_by(engine.Challenge.created_at)
    )).scalars().all()
    stage_by_level = {1: "reconnaissance", 2: "discovery", 3: "initial_access",
                      4: "execution", 5: "lateral_movement", 6: "collection"}
    assets = [incident.origin_asset_id]
    stages = []
    for c in chals:
        lvl = c.result_level or 1
        stage = stage_by_level.get(lvl, "discovery")
        if not stages or stages[-1] != stage:
            stages.append(stage)
    if not stages:
        stages = [incident.stage or "reconnaissance"]
    if incident.predicted_target_id:
        assets.append(incident.predicted_target_id)
    return {
        "trajectory_id": f"TR-{incident.incident_id}",
        "incident_id": incident.incident_id,
        "actor_id": incident.attacker,
        "asset_sequence": assets,
        "stage_sequence": stages,
        "status": incident.status.value,
    }


@router.get("/threat/actors")
async def threat_actors(db: AsyncSession = Depends(get_db)):
    incidents = await engine.list_active_incidents(db)
    rows = await engine.list_assets(db)
    svc = engine.service_status(rows)
    by_target: Dict[str, List[str]] = {}
    for inc in incidents:
        if inc.predicted_target_id:
            by_target.setdefault(inc.predicted_target_id, []).append(inc.attacker)
    out = []
    for inc in incidents:
        pred = (await db.execute(
            select(engine.PredictionRecord)
            .where(engine.PredictionRecord.incident_id == inc.incident_id)
            .order_by(desc(engine.PredictionRecord.created_at)).limit(1)
        )).scalar_one_or_none()
        origin = await engine.get_asset(db, inc.origin_asset_id)
        out.append({
            "actor_id": inc.attacker,
            "incident_id": inc.incident_id,
            "first_seen": inc.started_at.isoformat(sep=" ", timespec="seconds") if inc.started_at else None,
            "last_seen": None,
            "source_ips": [origin.ip] if origin and origin.ip else [],
            "confidence": round(pred.confidence, 4) if pred else None,
            "status": inc.status.value,
            "current_asset": inc.origin_asset_id,
            "current_stage": inc.stage,
            "predicted_target": inc.predicted_target_name,
            "predicted_target_id": inc.predicted_target_id,
            "risk_level": pred.risk_level if pred else None,
            "risk_score": pred.risk_score if pred else None,
            "deception": inc.deception_activated,
            "decoy": inc.decoy_asset_id,
            "converging": len(by_target.get(inc.predicted_target_id or "", [])) > 1,
        })
    return {"actors": out, "service": svc}


@router.get("/threat/actors/{actor_id}")
async def threat_actor(actor_id: str, db: AsyncSession = Depends(get_db)):
    inc = (await db.execute(
        select(DemoIncident)
        .where(DemoIncident.attacker == actor_id)
        .order_by(desc(DemoIncident.started_at)).limit(1)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Actor not found")
    row = (await db.execute(
        select(ThreatActor).where(ThreatActor.actor_id == actor_id))).scalar_one_or_none()
    snapshot = {
        "first_seen": row.first_seen.isoformat(sep=" ", timespec="seconds") if row and row.first_seen else None,
        "last_seen": row.last_seen.isoformat(sep=" ", timespec="seconds") if row and row.last_seen else None,
        "source_ips": row.source_ips if row else [],
        "confidence": row.confidence if row else None,
    }
    detail = await threat_actors(db)
    base = next((a for a in detail["actors"] if a["actor_id"] == actor_id), {})
    return {**base, **snapshot}


@router.get("/threat/trajectories/{actor_id}")
async def threat_trajectory(actor_id: str, db: AsyncSession = Depends(get_db)):
    inc = (await db.execute(
        select(DemoIncident)
        .where(DemoIncident.attacker == actor_id)
        .order_by(desc(DemoIncident.started_at)).limit(1)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Actor not found")
    trace = await _derive_trajectory(db, inc)
    row = (await db.execute(
        select(ThreatTrajectory).where(ThreatTrajectory.actor_id == actor_id)
        .order_by(desc(ThreatTrajectory.updated_at)).limit(1))).scalar_one_or_none()
    if row and row.asset_sequence:
        trace["asset_sequence"] = row.asset_sequence
        trace["stage_sequence"] = row.stage_sequence
        trace["status"] = row.status
    return {"actor_id": actor_id, "trajectory": trace}


# ---- Live stream (SSE) ------------------------------------------------------

@router.get("/stream")
async def stream(request: Request):
    async def gen():
        q = await bus.subscribe()
        # send a ping to establish the stream
        yield "event: ping\ndata: {\"kind\":\"ping\"}\n\n"
        try:
            while True:
                event = await q.get()
                if await request.is_disconnected():
                    break
                data = json.dumps(event)
                yield f"event: event\ndata: {data}\n\n"
        finally:
            await bus.unsubscribe(q)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "Connection": "keep-alive",
                                      "X-Accel-Buffering": "no"})
