"""
Discovery Lifecycle and Stale Device Retirement Service.

Monitors device liveness and transitions states according to operational policy:
  * ACTIVE -> STALE: Device has not been observed across any protocol for > stale_threshold_seconds.
  * STALE -> RETIRED: Device has remained unresponsive for > retirement_threshold_seconds.
  * STALE / RETIRED -> ACTIVE: A new valid observation immediately restores the device to active status.

Automatically updates connected TopologyEdge records when devices are retired,
and creates immutable DeviceSnapshot records to preserve historical auditability.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovery_evidence import DeviceIdentity, TopologyEdge
from app.services.evidence_service import EvidenceService

logger = logging.getLogger(__name__)


@dataclass
class LifecycleAuditResult:
    total_evaluated: int
    marked_stale: List[str] = field(default_factory=list)
    marked_retired: List[str] = field(default_factory=list)
    edges_archived: int = 0
    snapshots_created: int = 0
    audited_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DiscoveryLifecycleService:
    """Audits and transitions device states based on protocol heartbeat and observation decay."""

    def __init__(
        self,
        default_stale_threshold_seconds: int = 900,       # 15 minutes
        default_retirement_threshold_seconds: int = 86400, # 24 hours
    ) -> None:
        self.stale_threshold_seconds = default_stale_threshold_seconds
        self.retirement_threshold_seconds = default_retirement_threshold_seconds

    async def audit_devices(
        self,
        db: AsyncSession,
        stale_threshold_seconds: Optional[int] = None,
        retirement_threshold_seconds: Optional[int] = None,
    ) -> LifecycleAuditResult:
        """
        Scans all DeviceIdentity records and updates states for unresponsive nodes.
        """
        stale_sec = stale_threshold_seconds or self.stale_threshold_seconds
        retire_sec = retirement_threshold_seconds or self.retirement_threshold_seconds
        now = datetime.now(timezone.utc)

        stale_cutoff = now - timedelta(seconds=stale_sec)
        retire_cutoff = now - timedelta(seconds=retire_sec)

        result = await db.execute(select(DeviceIdentity))
        devices = result.scalars().all()

        marked_stale: List[str] = []
        marked_retired: List[str] = []
        edges_archived_count = 0
        snapshots_created_count = 0

        for dev in devices:
            last_seen = dev.last_seen
            if last_seen and last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)

            if not last_seen:
                continue

            current_status = dev.status

            # 1. Check for retirement (exceeded retirement threshold)
            if last_seen < retire_cutoff and current_status != "retired":
                dev.status = "retired"
                marked_retired.append(str(dev.id))

                # Archive connected edges
                edge_stmt = (
                    update(TopologyEdge)
                    .where(
                        (TopologyEdge.source_device_id == dev.id)
                        | (TopologyEdge.destination_device_id == dev.id)
                    )
                    .where(TopologyEdge.status == "active")
                    .values(status="archived", last_confirmed=now)
                )
                res = await db.execute(edge_stmt)
                edges_archived_count += res.rowcount

                # Snapshot the retirement event
                from app.schemas.discovery_evidence import DeviceSnapshotCreate
                snap = await EvidenceService.capture_device_snapshot(
                    db,
                    DeviceSnapshotCreate(
                        device_id=dev.id,
                        configuration_hash="lifecycle_retired",
                        interfaces=[],
                    ),
                )
                if snap:
                    snapshots_created_count += 1

            # 2. Check for stale state (exceeded stale threshold but not yet retired)
            elif last_seen < stale_cutoff and current_status == "active":
                dev.status = "stale"
                marked_stale.append(str(dev.id))

                from app.schemas.discovery_evidence import DeviceSnapshotCreate
                snap = await EvidenceService.capture_device_snapshot(
                    db,
                    DeviceSnapshotCreate(
                        device_id=dev.id,
                        configuration_hash="lifecycle_stale",
                        interfaces=[],
                    ),
                )
                if snap:
                    snapshots_created_count += 1

        if marked_stale or marked_retired:
            await db.commit()

        logger.info(
            "Lifecycle audit complete: evaluated=%s, stale=%s, retired=%s, edges_archived=%s",
            len(devices),
            len(marked_stale),
            len(marked_retired),
            edges_archived_count,
        )

        return LifecycleAuditResult(
            total_evaluated=len(devices),
            marked_stale=marked_stale,
            marked_retired=marked_retired,
            edges_archived=edges_archived_count,
            snapshots_created=snapshots_created_count,
            audited_at=now,
        )
