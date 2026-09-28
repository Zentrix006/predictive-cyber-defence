"""Shared helpers for backend + ml-engine tests (sync, loop-isolated).

The Starlette TestClient drives the app on its own event loop, so the app's
module-global async_session_maker pool is bound to that loop. All DB work here
instead runs through ``db_run``: a dedicated engine that is created, used, and
destroyed inside a single asyncio loop per call, so no connection ever crosses
an event loop boundary or the app's shared pool.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# API contract tests intentionally exercise the isolated local-development path.
# Compose may define secure production defaults in the parent environment, so
# set (rather than setdefault) the isolated test process values before the app
# settings object is imported.
os.environ["DEBUG"] = "true"
os.environ["DEV_AUTH_BYPASS"] = "true"

from app.main import app

ML_ENGINE = Path(__file__).resolve().parents[2] / "ml-engine"
if str(ML_ENGINE) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE))


def db_run(fn):
    """Run async ``fn(session)`` on a dedicated engine inside one fresh loop."""
    from app.core.config import settings
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    async def _inner():
        engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with factory() as session:
                return await fn(session)
        finally:
            await engine.dispose()

    return asyncio.run(_inner())


@pytest.fixture(scope="session")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def make_wm_ml(current_stage: str = "command_and_control", with_details: bool = True) -> dict:
    """A world-model forecast payload as produced by try_world_model_forecast."""
    timeline = [
        {"window_offset": i + 1, "stage": current_stage, "probability": 0.5 + 0.1 * i,
         "confidence": 0.5 + 0.1 * i, "eta_seconds": 30.0 * (i + 1)}
        for i in range(4)
    ]
    thinking = {
        "branches": 5,
        "consensus_target": "db-02",
        "consensus_stage": current_stage,
        "consensus_confidence": 0.7,
        "consensus_agreement": 0.88,
        "chain_of_thought": ["cot"],
        "worst_case": {"branch": 3, "terminal_stage": "impact", "peak_infil_risk": 0.9},
    }
    if with_details:
        thinking["branch_details"] = [
            {"branch": 0, "terminal_stage": "reconnaissance", "peak_infil_risk": 0.10},
            {"branch": 1, "terminal_stage": "command_and_control", "peak_infil_risk": 0.31},
            {"branch": 2, "terminal_stage": "lateral_movement", "peak_infil_risk": 0.44},
            {"branch": 3, "terminal_stage": "impact", "peak_infil_risk": 0.90},
            {"branch": 4, "terminal_stage": "exfiltration", "peak_infil_risk": 0.73},
        ]
    return {
        "current_stage": current_stage,
        "current_confidence": 0.7,
        "timeline": timeline,
        "predicted_stages": [current_stage] * 4,
        "thinking": thinking,
        "recommended_action": "patch_mitigate",
        "recommended_actions": [{"step": 1, "action": "patch_mitigate"}],
        "model_version": "flow-wm-v3.0.0-test",
        "explanation": {"natural_language": "nl"},
    }
