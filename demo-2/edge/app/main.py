"""
Deception Edge — REAL network enforcement for the Demo-2 range.

Runs three genuine listeners:

  :8090  production surface for the shared domain (app.payg.in). Blocked
         attacker IPs receive an actual HTTP 403 with connection close;
         everyone else gets a real page reflecting the live failover state.
  :8091  the live honeypot decoy: a genuine HTTP service whose identity is
         pushed by the range engine. Every real request is logged to the
         edge's hit log with source IP, headers and timing.
  :8099  control plane (POST /internal/* + GET /internal/state).

State is in-memory only; the range engine remains the source of truth. The
edge is deliberately dependency-free (FastAPI + uvicorn) so it starts in
milliseconds and never touches the range database.
"""
from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

# Three separate ASGI apps served by serve.py on ports 8099/8090/8091.
control = FastAPI(title="Demo-2 Deception Edge — control", docs_url=None, redoc_url=None)
production = FastAPI(title="Demo-2 Deception Edge — production surface", docs_url=None, redoc_url=None)
honeypot = FastAPI(title="Demo-2 Deception Edge — honeypot", docs_url=None, redoc_url=None)
app = control  # convenient default target

_SECRET: Optional[str] = None  # resolved from env at startup


def _auth(x_edge_secret: Optional[str]) -> None:
    import os
    expected = os.environ.get("EDGE_SHARED_SECRET", "")
    if expected and x_edge_secret != expected:
        raise HTTPException(status_code=401, detail="bad edge secret")


# ---------------------------------------------------------------------------
# Enforcement state
# ---------------------------------------------------------------------------
blocked: Dict[str, Dict] = {}          # ip -> {reason, actor, since}
decoy: Dict[str, Optional[str]] = {"id": None, "name": None, "service": None, "actor": None}
serving: Dict[str, Optional[str]] = {"from": None, "since": None}
hits: Deque[Dict] = deque(maxlen=500)  # honeypot hit log (ingested by the range)
block_events: Deque[Dict] = deque(maxlen=200)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------
@control.post("/internal/block")
async def do_block(request: Request, x_edge_secret: Optional[str] = Header(None)):
    _auth(x_edge_secret)
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        raise HTTPException(422, "ip required")
    blocked[ip] = {"reason": body.get("reason") or "contained",
                   "actor": body.get("actor"), "since": _now()}
    block_events.append({"ip": ip, "action": "block", "at": _now(),
                         "reason": blocked[ip]["reason"]})
    return {"ok": True, "blocked": ip, "total": len(blocked)}


@control.post("/internal/unblock")
async def do_unblock(request: Request, x_edge_secret: Optional[str] = Header(None)):
    _auth(x_edge_secret)
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    removed = blocked.pop(ip, None)
    if removed:
        block_events.append({"ip": ip, "action": "unblock", "at": _now()})
    return {"ok": True, "removed": bool(removed)}


@control.post("/internal/decoy")
async def do_decoy(request: Request, x_edge_secret: Optional[str] = Header(None)):
    _auth(x_edge_secret)
    body = await request.json()
    if not body.get("id"):
        decoy.update(id=None, name=None, service=None, actor=None)
        return {"ok": True, "decoy": None}
    decoy.update(id=body.get("id"), name=body.get("name") or body.get("id"),
                 service=body.get("service") or "Application Server",
                 actor=body.get("actor"))
    return {"ok": True, "decoy": decoy["id"]}


@control.post("/internal/serving")
async def do_serving(request: Request, x_edge_secret: Optional[str] = Header(None)):
    _auth(x_edge_secret)
    body = await request.json()
    serving.update(from_=body.get("from"), since=_now())
    serving["from"] = body.get("from")
    return {"ok": True, "serving_from": serving["from"]}


@control.get("/internal/state")
async def state(x_edge_secret: Optional[str] = Header(None)):
    _auth(x_edge_secret)
    return {
        "blocked": list(blocked.keys()),
        "blocked_detail": blocked,
        "decoy": decoy,
        "serving": serving,
        "honeypot_hits": len(hits),
        "block_events": list(block_events)[-20:],
        "recent_hits": list(hits)[-20:],
    }


@control.post("/internal/collect")
async def collect(x_edge_secret: Optional[str] = Header(None)):
    """Drain the honeypot hit log into the range evidence ledger."""
    _auth(x_edge_secret)
    drained = list(hits)
    hits.clear()
    return {"ok": True, "hits": drained}


@control.post("/internal/reset")
async def reset_edge(x_edge_secret: Optional[str] = Header(None)):
    """Range reset/purge: lift every block, retire the decoy identity."""
    _auth(x_edge_secret)
    n_blocked = len(blocked)
    blocked.clear()
    decoy.update(id=None, name=None, service=None, actor=None)
    serving.update(from_=None, since=None)
    block_events.append({"action": "reset", "at": _now(), "lifted": n_blocked})
    return {"ok": True, "lifted": n_blocked}


# ---------------------------------------------------------------------------
# :8090 — production surface (real 403 enforcement)
# ---------------------------------------------------------------------------
_PROD_PAGE = """<!doctype html><html><head><title>{domain}</title>
<style>body{{font-family:system-ui;background:#0b1220;color:#e5e7eb;display:grid;place-items:center;height:100vh;margin:0}}
.c{{text-align:center}}h1{{font-size:2.4rem;margin:.2em 0}}p{{color:#94a3b8}}
.s{{display:inline-block;padding:.35em .9em;border-radius:999px;border:1px solid #34d39955;color:#34d399;font-size:.85rem}}</style>
</head><body><div class="c"><span class="s">serving by {serving_from}</span>
<h1>{domain}</h1><p>{tagline}</p></div></body></html>"""


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@production.get("/", response_class=HTMLResponse)
async def production_surface(request: Request):
    ip = _client_ip(request)
    if ip in blocked:
        block_events.append({"ip": ip, "action": "refused_403", "at": _now()})
        return JSONResponse(
            {"detail": "Your connection has been refused by the defender."},
            status_code=403,
            headers={"Connection": "close", "Cache-Control": "no-store"})
    domain = "app.payg.in"
    return HTMLResponse(_PROD_PAGE.format(
        domain=domain, serving_from=serving.get("from") or "primary",
        tagline="Payment gateway — operational"))


@control.get("/healthz")
async def edge_health():
    return {"ok": True, "listeners": ["8090", "8091", "8099"],
            "blocked": len(blocked), "decoy": decoy["id"]}


# ---------------------------------------------------------------------------
# :8091 — the live honeypot decoy (a real HTTP service)
# ---------------------------------------------------------------------------
_HP_PAGE = """<!doctype html><html><head><title>{name}</title>
<style>body{{font-family:system-ui;background:#101017;color:#e5e7eb;display:grid;place-items:center;height:100vh;margin:0}}
.c{{text-align:center}}h1{{font-size:2rem}}code{{background:#1f2937;padding:.2em .5em;border-radius:6px;font-size:.85rem}}</style>
</head><body><div class="c"><h1>{name}</h1>
<p>{service}</p><p>Admin console: <code>/admin/login</code></p></div></body></html>"""


def _record_hit(request: Request, path: str) -> None:
    hits.append({
        "ts": _now(),
        "source_ip": _client_ip(request),
        "method": request.method,
        "path": path,
        "user_agent": (request.headers.get("user-agent") or "")[:120],
        "decoy": decoy["id"],
        "actor": decoy["actor"],
    })


@honeypot.get("/{path:path}", response_class=HTMLResponse)
async def honeypot_catch_all(request: Request, path: str = ""):
    """Every request to the decoy is a genuine hit — logged for attribution."""
    _record_hit(request, "/" + path)
    name = decoy.get("name") or "app.payg.in"
    service = decoy.get("service") or "Application Server"
    return HTMLResponse(_HP_PAGE.format(name=name, service=service))


if __name__ == "__main__":
    pass  # use serve.py
