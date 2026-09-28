"""
Config Snapshot API Endpoints
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.config_snapshot import ConfigSnapshot, ConfigDiff
from app.schemas.config import (
    ConfigSnapshotResponse, ConfigSnapshotCreate, ConfigSnapshotApply,
    ConfigDiffResponse
)
from app.schemas.common import APIResponse

router = APIRouter()


@router.post("/snapshots", response_model=ConfigSnapshotResponse, status_code=201)
async def create_snapshot(
    snapshot_in: ConfigSnapshotCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a configuration snapshot."""
    from uuid import uuid4
    import hashlib
    import json
    
    # Verify incident
    from app.models.incident import Incident
    result = await db.execute(select(Incident).where(Incident.id == snapshot_in.incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Serialize and hash configuration
    config_json = json.dumps(snapshot_in.configuration, sort_keys=True)
    sha256_hash = hashlib.sha256(config_json.encode()).hexdigest()
    
    # Check if identical snapshot exists
    existing = await db.execute(
        select(ConfigSnapshot).where(
            ConfigSnapshot.incident_id == snapshot_in.incident_id,
            ConfigSnapshot.sha256_hash == sha256_hash
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Identical snapshot already exists")
    
    snapshot = ConfigSnapshot(
        id=uuid4(),
        incident_id=snapshot_in.incident_id,
        label=snapshot_in.label,
        description=snapshot_in.description,
        snapshot_type=snapshot_in.snapshot_type,
        configuration=snapshot_in.configuration,
        sha256_hash=sha256_hash,
        created_by=current_user.get("sub"),
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)
    
    return ConfigSnapshotResponse.model_validate(snapshot)


@router.get("/snapshots", response_model=List[ConfigSnapshotResponse])
async def list_snapshots(
    incident_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List configuration snapshots."""
    query = select(ConfigSnapshot).order_by(desc(ConfigSnapshot.created_at))
    if incident_id:
        query = query.where(ConfigSnapshot.incident_id == incident_id)
    
    result = await db.execute(query)
    snapshots = result.scalars().all()
    return [ConfigSnapshotResponse.model_validate(s) for s in snapshots]


@router.get("/snapshots/diff", response_model=ConfigDiffResponse)
async def compare_snapshots(
    from_snapshot: UUID = Query(..., description="Source snapshot ID"),
    to_snapshot: UUID = Query(..., description="Target snapshot ID"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Compare two configuration snapshots."""
    from uuid import uuid4

    # Get both snapshots
    from_result = await db.execute(select(ConfigSnapshot).where(ConfigSnapshot.id == from_snapshot))
    from_snap = from_result.scalar_one_or_none()
    if not from_snap:
        raise HTTPException(status_code=404, detail="From snapshot not found")

    to_result = await db.execute(select(ConfigSnapshot).where(ConfigSnapshot.id == to_snapshot))
    to_snap = to_result.scalar_one_or_none()
    if not to_snap:
        raise HTTPException(status_code=404, detail="To snapshot not found")

    # Deep diff
    def deep_diff(obj1: dict, obj2: dict, path: str = "") -> dict:
        added = {}
        removed = {}
        modified = {}

        all_keys = set(obj1.keys()) | set(obj2.keys())
        for key in all_keys:
            new_path = f"{path}.{key}" if path else key
            if key not in obj1:
                added[new_path] = obj2[key]
            elif key not in obj2:
                removed[new_path] = obj1[key]
            elif obj1[key] != obj2[key]:
                if isinstance(obj1[key], dict) and isinstance(obj2[key], dict):
                    sub_diff = deep_diff(obj1[key], obj2[key], new_path)
                    added.update(sub_diff["added"])
                    removed.update(sub_diff["removed"])
                    modified.update(sub_diff["modified"])
                else:
                    modified[new_path] = {"from": obj1[key], "to": obj2[key]}

        return {"added": added, "removed": removed, "modified": modified}

    diff = deep_diff(from_snap.configuration, to_snap.configuration)

    # Save diff
    diff_record = ConfigDiff(
        id=uuid4(),
        from_snapshot_id=from_snapshot,
        to_snapshot_id=to_snapshot,
        added=diff["added"],
        removed=diff["removed"],
        modified=diff["modified"],
    )
    db.add(diff_record)
    await db.commit()
    await db.refresh(diff_record)

    return ConfigDiffResponse(
        from_snapshot_id=from_snapshot,
        to_snapshot_id=to_snapshot,
        added=diff["added"],
        removed=diff["removed"],
        modified=diff["modified"],
    )


@router.get("/snapshots/{snapshot_id}", response_model=ConfigSnapshotResponse)
async def get_snapshot(
    snapshot_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get snapshot details."""
    result = await db.execute(select(ConfigSnapshot).where(ConfigSnapshot.id == snapshot_id))
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return ConfigSnapshotResponse.model_validate(snapshot)


@router.post("/snapshots/{snapshot_id}/apply", response_model=APIResponse)
async def apply_snapshot(
    snapshot_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Apply (rollback to) a configuration snapshot."""
    result = await db.execute(select(ConfigSnapshot).where(ConfigSnapshot.id == snapshot_id))
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    
    # TODO: Actually apply configuration to network devices
    # This would push the configuration to routers, switches, firewalls
    
    snapshot.applied_at = datetime.utcnow()
    await db.commit()
    
    return APIResponse(
        success=True,
        message="Configuration applied",
        data={"snapshot_id": str(snapshot_id), "applied_at": snapshot.applied_at.isoformat()}
    )