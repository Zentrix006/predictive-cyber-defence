"""
Audit API — immutable, queryable audit trail of platform actions.
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.response import AuditEvent
from app.schemas.response import AuditEventResponse
from app.services.audit_service import list_audit

router = APIRouter()


@router.get("", response_model=List[AuditEventResponse])
async def get_audit(
    limit: int = Query(100, ge=1, le=500),
    action: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    rows = await list_audit(db, limit=limit, action=action, actor=actor, entity_type=entity_type)
    return [AuditEventResponse.model_validate(r) for r in rows]


@router.get("/summary", response_model=dict)
async def audit_summary(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    total = await db.scalar(select(func.count()).select_from(AuditEvent))
    by_action = {}
    rows = (await db.execute(
        select(AuditEvent.action, func.count()).group_by(AuditEvent.action)
    )).all()
    for action, count in rows:
        by_action[str(action)] = count
    return {"total": total or 0, "by_action": by_action}