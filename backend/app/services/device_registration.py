"""
Shared device-registration logic.

Used by both the HTTP enrollment endpoint and the background network
discovery scanner so that a device joining the network is classified,
upserted as an Asset, written into the topology snapshot, and broadcast to
connected dashboards through one code path.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetStatus
from app.models.topology import TopologySnapshot
from app.services.device_classifier import classify_device
from app.ws.manager import ws_manager


def asset_to_node(asset: Asset) -> Dict:
    """Serialise an Asset into a TopologyNode-compatible dict."""
    return {
        "id": str(asset.id),
        "label": asset.hostname or asset.ip_address,
        "asset_id": str(asset.id),
        "asset_type": asset.asset_type.value,
        "zone": asset.zone.value,
        "status": asset.status.value,
        "threat_score": asset.threat_score,
        "criticality": asset.criticality.value,
        "position": None,
        "metadata": asset.metadata_ or {},
    }


async def rebuild_snapshot(
    db: AsyncSession,
    incident_id: Optional[UUID] = None,
) -> TopologySnapshot:
    """Persist a fresh TopologySnapshot containing every known asset."""
    result = await db.execute(select(Asset).order_by(Asset.hostname))
    assets = result.scalars().all()

    nodes = [asset_to_node(a) for a in assets]
    snapshot = TopologySnapshot(
        incident_id=incident_id,
        timestamp=datetime.utcnow(),
        nodes=nodes,
        edges=[],
        prediction_edges=[],
    )
    db.add(snapshot)
    return snapshot


async def register_device(
    db: AsyncSession,
    *,
    mac: Optional[str] = None,
    ip: Optional[str] = None,
    hostname: Optional[str] = None,
    user_agent: Optional[str] = None,
    vendor_class: Optional[str] = None,
    services: Optional[List[str]] = None,
    incident_id: Optional[UUID] = None,
    source: str = "enrollment",
) -> Dict:
    """Classify, upsert and broadcast a joining/joining device.

    Returns a dict with the asset node, whether it was newly created, and the
    rebuilt topology snapshot timestamp.
    """
    ip_address = ip or "0.0.0.0"
    hostname = hostname or "device-" + (ip_address or "unknown").replace(".", "-")

    asset_type, zone, criticality, meta = classify_device(
        mac=mac,
        ip=ip,
        hostname=hostname,
        user_agent=user_agent,
        vendor_class=vendor_class,
        services=services,
    )
    meta.setdefault("enrolled_by", source)
    if meta.get("enrolled_by") == "wifi_qr" and source != "wifi_qr":
        meta["enrolled_by"] = source

    # Upsert by MAC (preferred) or IP, else create new.
    existing = None
    if mac:
        result = await db.execute(select(Asset).where(Asset.mac_address == mac))
        existing = result.scalar_one_or_none()
    if existing is None and ip:
        result = await db.execute(select(Asset).where(Asset.ip_address == ip_address))
        existing = result.scalar_one_or_none()

    created = False
    if existing is None:
        existing = Asset(
            id=uuid4(),
            hostname=hostname,
            ip_address=ip_address,
            asset_type=asset_type,
            zone=zone,
            criticality=criticality,
            os=meta.get("os"),
            mac_address=mac,
            status=AssetStatus.NORMAL,
            threat_score=0.0,
            last_seen=datetime.utcnow(),
            tags=["discovered", source],
            metadata_=meta,
        )
        db.add(existing)
        created = True
    else:
        # Refresh identity for a returning device. Only upgrade the
        # classification when the incoming signal is at least as confident
        # as what we already stored, so weak re-joins don't downgrade a
        # previously-confident fingerprint.
        existing.hostname = hostname or existing.hostname
        if ip:
            existing.ip_address = ip_address
        existing.last_seen = datetime.utcnow()
        prev_confidence = existing.metadata_.get("confidence", 0) or 0
        new_confidence = meta.get("confidence", 0) or 0
        if new_confidence >= prev_confidence:
            existing.asset_type = asset_type
            existing.zone = zone
            existing.criticality = criticality
        existing.metadata_.update(meta)
        if source not in (existing.tags or []):
            existing.tags = list(existing.tags or []) + [source]

    await db.flush()
    snapshot = await rebuild_snapshot(db, incident_id)
    await db.commit()
    await db.refresh(snapshot)

    # Best-effort live update to any connected dashboards.
    try:
        await ws_manager.broadcast(
            event_type="node_added",
            payload={
                "node": asset_to_node(existing),
                "created": created,
                "source": source,
                "enrolled_at": datetime.utcnow().isoformat() + "Z",
            },
            incident_id=incident_id,
        )
    except Exception:
        pass

    return {
        "success": True,
        "created": created,
        "asset_id": str(existing.id),
        "node": asset_to_node(existing),
        "snapshot_timestamp": snapshot.timestamp.isoformat() + "Z",
    }
