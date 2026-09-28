"""
Report API — generate structured incident reports as JSON or Markdown.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.services.report_service import build_report, report_to_markdown

router = APIRouter()


class ReportJson(BaseModel):
    format: str = "json"
    include_timeline: bool = True


@router.get("/{incident_id}/json")
async def report_json(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        return await build_report(db, incident_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Incident not found")


@router.get("/{incident_id}/markdown")
async def report_markdown(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        report = await build_report(db, incident_id)
        return report_to_markdown(report)
    except LookupError:
        raise HTTPException(status_code=404, detail="Incident not found")


@router.get("/{incident_id}/policy-brief")
async def policy_brief(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        report = await build_report(db, incident_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Incident not found")
    brief = {
        "incident_id": report["incident_id"],
        "title": report["title"],
        "risk_summary": report.get("summary"),
        "actors": [a["display_id"] for a in report.get("threat_actors", [])],
        "assets_at_risk": [a["hostname"] for a in report.get("assets", [])],
        "policy_decisions": report.get("policy_decisions", []),
        "response_actions": report.get("response_actions", []),
        "verdict": "Action required" if report.get("policy_decisions") and report["policy_decisions"][0].get("requires_human_approval") else "Monitor only",
    }
    return brief