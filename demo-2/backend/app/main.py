"""
Demo cyber-range API application.

Separate FastAPI process mounting the demo routers under /api/demo.
Demo state lives in the `demo` Postgres schema only; the world model is the
real flow-wm-v3.0.0 loaded from /ml-engine.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import settings
from app.core.db import init_db, db_ready, engine as demo_engine
from sqlalchemy import text
from app.api.routes import router as public_router
from app.api.admin import router as admin_router

log = logging.getLogger("demo")

_maint_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await init_db()
    except Exception as exc:
        log.exception("Demo schema initialization failed; starting in degraded mode: %s", exc)
    else:
        log.info(
            "Demo schema ready=%s (no assets pre-created); world model at %s",
            db_ready(),
            settings.ML_ENGINE_PATH,
        )
    global _maint_task
    try:
        from app.services.simulation_engine import run_maintenance_supervisor
        _maint_task = asyncio.create_task(run_maintenance_supervisor())
    except Exception:
        log.exception("Maintenance supervisor did not start; continuing without it")
        _maint_task = None
    yield
    if _maint_task:
        _maint_task.cancel()


app = FastAPI(
    title="Predictive Cyber Defence — Demo-2 Live Cyber-Range",
    version="0.1.0",
    description="Controlled, isolated demonstration environment. Simulation only.",
    lifespan=lifespan,
)

class MutationRateLimitMiddleware:
    """Per-IP sliding-window limiter for state-changing requests.

    Implements the previously unused DEMO_RATE_LIMIT setting (requests per
    minute per client IP). Heartbeats and the SSE stream are exempt: they are
    the telemetry lifeline and throttling them would break live devices.
    """

    def __init__(self, app: ASGIApp, limit: int, window_seconds: float = 60.0):
        self.app = app
        self.limit = max(1, limit)
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path.endswith("/heartbeat") or path.endswith("/stream"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        ip = client[0] if client else "unknown"
        now = time.monotonic()
        hits = self._hits[ip]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(self._hits) > 2048:  # bounded memory; drop idle windows
            for key in [k for k, v in self._hits.items() if not v]:
                self._hits.pop(key, None)
        if len(hits) >= self.limit:
            response = JSONResponse(
                {"detail": "Too many requests; slow down."}, status_code=429)
            response.headers["Retry-After"] = str(int(self.window))
            await response(scope, receive, send)
            return
        hits.append(now)
        await self.app(scope, receive, send)


# CORS: broad by design for the event floor (tablets, phones, TVs). No secrets
# travel over these endpoints; demo is browser-context only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(MutationRateLimitMiddleware, limit=settings.DEMO_RATE_LIMIT)


@app.get("/api/demo/health")
async def health():
    db_ok = db_ready()
    if db_ok:
        try:
            async with demo_engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception:
            db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "simulation": True,
        "name": settings.DEMO_NAME,
        "database": db_ok,
    }


app.include_router(public_router, prefix=settings.DEMO_PREFIX)
app.include_router(admin_router, prefix=settings.DEMO_PREFIX)
