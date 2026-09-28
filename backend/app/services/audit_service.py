"""
Audit Log Service

Every significant action (login, model run, prediction, policy decision,
approval, containment, deception activation, config change, rollback, evidence
collection, report generation) is written to the audit log.
"""
from typing import Optional, Dict, List
from uuid import UUID

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.response import AuditEvent
from app.ws.manager import ws_manager


async def log_audit(
    db: AsyncSession,
    actor: str = "system",
    action: str = "ACTION",
    target_type: Optional[str] = None,
    target_id: Optional[UUID] = None,
    summary: str = "",
    details: Optional[Dict] = None,
    ip_address: Optional[str] = None,
) -> AuditEvent:
    """Persist an audit event (and broadcast it on the realtime channel)."""
    event = AuditEvent(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        summary=summary[:512],
        details=details or {},
        ip_address=ip_address,
    )
    db.add(event)
    await db.flush()
    try:
        await ws_manager.broadcast(
            "audit_created",
            {
                "audit_id": str(event.id),
                "action": action,
                "summary": event.summary,
                "timestamp": event.timestamp.isoformat(),
            },
            incident_id=None,
        )
    except Exception:
        pass
    return event


async def list_audit(
    db: AsyncSession,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    entity_type: Optional[str] = None,
    limit: int = 100,
) -> List[AuditEvent]:
    query = select(AuditEvent)
    if action:
        query = query.where(AuditEvent.action == action)
    if actor:
        query = query.where(AuditEvent.actor == actor)
    if entity_type:
        query = query.where(AuditEvent.target_type == entity_type)
    query = query.order_by(desc(AuditEvent.timestamp)).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())