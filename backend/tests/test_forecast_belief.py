"""Forecast detail belief-state tests (branch_details, worst_case shapes)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete

from tests.conftest import db_run, make_wm_ml


async def _scenario(session, ml):
    from app.models.incident import Incident
    from app.services.forecast_service import build_forecast_detail

    inc = Incident(
        title="belief test", description="pytest", severity="medium",
        created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
    )
    session.add(inc)
    await session.flush()
    fd = await build_forecast_detail(session, inc.id, 4, ml=ml)
    return fd, inc.id


async def _teardown(session, incident_id):
    from app.models.incident import Incident
    await session.execute(delete(Incident).where(Incident.id == incident_id))
    await session.commit()


def test_branch_details_drive_belief_branches():
    ml = make_wm_ml(current_stage="command_and_control", with_details=True)
    fd, inc_id = db_run(lambda s: _scenario(s, ml))
    try:
        assert fd.belief is not None
        assert len(fd.belief.branches) == 5
        details = ml["thinking"]["branch_details"]
        for br, d in zip(fd.belief.branches, details):
            assert br.branch == d["branch"] + 1
            assert br.stage == d["terminal_stage"]
            assert abs(br.risk - round(d["peak_infil_risk"] * 100, 2)) < 0.01
        assert fd.belief.worst_case == {"terminal_stage": "impact", "peak_infil_risk": 0.9}
    finally:
        db_run(lambda s: _teardown(s, inc_id))


def test_int_branches_fallback_uses_worst_case():
    ml = make_wm_ml(current_stage="lateral_movement", with_details=False)
    fd, inc_id = db_run(lambda s: _scenario(s, ml))
    try:
        assert len(fd.belief.branches) == 5
        for br in fd.belief.branches:
            assert br.risk == 90.0
        # First branch is augmented with the worst-case stage; the rest are
        # consensus-staged representatives.
        assert fd.belief.branches[0].stage == "impact"
        for br in fd.belief.branches[1:]:
            assert br.stage == "lateral_movement"
        assert fd.belief.worst_case == {"terminal_stage": "impact", "peak_infil_risk": 0.9}
    finally:
        db_run(lambda s: _teardown(s, inc_id))


def test_unknown_current_stage_round_trips():
    ml = make_wm_ml(current_stage="unknown", with_details=True)
    fd, inc_id = db_run(lambda s: _scenario(s, ml))
    try:
        assert fd.current_stage == "unknown"
    finally:
        db_run(lambda s: _teardown(s, inc_id))


def test_legacy_bare_string_worst_case():
    ml = make_wm_ml(current_stage="execution", with_details=True)
    ml["thinking"]["worst_case"] = "impact"
    fd, inc_id = db_run(lambda s: _scenario(s, ml))
    try:
        assert fd.belief is not None
        assert fd.belief.worst_case == {"terminal_stage": "impact"}
    finally:
        db_run(lambda s: _teardown(s, inc_id))