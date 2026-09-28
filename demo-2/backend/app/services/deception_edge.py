"""Client for the real Deception Edge (demo-2-edge container).

The edge runs REAL listeners:
  * :8090  production surface for the shared domain (app.payg.in) — refuses
           blocked source IPs with an actual HTTP 403 + connection close
  * :8091  the live honeypot decoy — a real HTTP service whose identity is
           pushed by the engine; every hit is ingested as range evidence
  * :8099  control plane (state push + status)

Every helper here is best-effort: if the edge container is not running the
demo flow continues unchanged (the state machine remains the source of
truth; the edge adds real network enforcement on top).
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from functools import partial
from typing import Any, Dict, Optional

from app.core.config import settings

log = logging.getLogger("demo.edge")

_status_cache: Dict[str, Any] = {"ok": False, "checked_at": 0.0, "state": None}


def _sync_post(path: str, payload: Dict[str, Any], timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    url = f"{settings.DECEPTION_EDGE_URL}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "X-Edge-Secret": settings.EDGE_SHARED_SECRET,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except Exception as exc:
        log.debug("edge call failed (%s): %s", url, exc)
        return None


def _sync_get(path: str, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    url = f"{settings.DECEPTION_EDGE_URL}{path}"
    req = urllib.request.Request(url, headers={"X-Edge-Secret": settings.EDGE_SHARED_SECRET})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except Exception as exc:
        log.debug("edge call failed (%s): %s", url, exc)
        return None


async def _post(path: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return await asyncio.to_thread(partial(_sync_post, path, payload))


async def _get(path: str) -> Optional[Dict[str, Any]]:
    return await asyncio.to_thread(partial(_sync_get, path))


async def block_ip(ip: Optional[str], reason: str, actor: Optional[str] = None) -> bool:
    """Really refuse this source IP on the production surface (HTTP 403)."""
    if not ip:
        return False
    result = await _post("/internal/block", {"ip": ip, "reason": reason, "actor": actor})
    return bool(result and result.get("ok"))


async def unblock_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    result = await _post("/internal/unblock", {"ip": ip})
    return bool(result and result.get("ok"))


async def activate_decoy(decoy_id: str, decoy_name: str, service: str,
                         actor: Optional[str] = None) -> bool:
    """Put the live honeypot listener into this decoy's identity."""
    result = await _post("/internal/decoy", {
        "id": decoy_id, "name": decoy_name, "service": service, "actor": actor,
    })
    return bool(result and result.get("ok"))


async def clear_decoys() -> bool:
    return bool(await _post("/internal/decoy", {"id": None}))


async def reset_edge() -> bool:
    """Lift all IP blocks and retire the live decoy identity (range reset)."""
    return bool(await _post("/internal/reset", {}))


async def drain_hits() -> Optional[Dict[str, Any]]:
    """Drain the honeypot's real HTTP hit log for evidence ingestion."""
    return await _post("/internal/collect", {})


async def set_serving(serving_from: Optional[str]) -> bool:
    """Reflect the real continuity state on the production surface page."""
    result = await _post("/internal/serving", {"from": serving_from})
    return bool(result and result.get("ok"))


async def status(force: bool = False) -> Dict[str, Any]:
    """Cached edge status for dashboards; safe to call on every request."""
    import time
    now = time.monotonic()
    if not force and _status_cache["ok"] and now - _status_cache["checked_at"] < 5.0:
        return {"available": True, **(_status_cache["state"] or {})}
    state = await _get("/internal/state")
    ok = bool(state and isinstance(state, dict))
    _status_cache.update(ok=ok, checked_at=now, state=state if ok else None)
    if ok:
        return {"available": True, **state}
    return {"available": False}


async def attacker_source_ip(db: Any, incident: Any) -> Optional[str]:
    """The real source IP the attacker joined the range from, if captured."""
    try:
        from app.services.simulation_engine import _participant_for_incident
        participant = await _participant_for_incident(db, incident)
        if not participant:
            return None
        ctx = participant.device_context or {}
        ip = ctx.get("source_ip")
        return ip if ip and ip != "testclient" else None
    except Exception:
        return None
