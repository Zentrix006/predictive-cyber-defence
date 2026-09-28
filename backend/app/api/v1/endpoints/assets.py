"""
Assets API Endpoints
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user
from app.models.asset import Asset, AssetStatus, AssetType, ZoneType, CriticalityLevel, IsolationLevel
from app.schemas.asset import AssetResponse, AssetCreate, AssetUpdate, AssetStatusResponse, PaginatedAssets
from app.schemas.common import APIResponse

router = APIRouter()


@router.get("", response_model=PaginatedAssets)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[List[AssetStatus]] = Query(None),
    asset_type: Optional[List[AssetType]] = Query(None),
    zone: Optional[List[ZoneType]] = Query(None),
    criticality: Optional[List[CriticalityLevel]] = Query(None),
    search: Optional[str] = Query(None),
    incident_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List assets with filtering and pagination."""
    query = select(Asset)
    
    if status:
        query = query.where(Asset.status.in_(status))
    if asset_type:
        query = query.where(Asset.asset_type.in_(asset_type))
    if zone:
        query = query.where(Asset.zone.in_(zone))
    if criticality:
        query = query.where(Asset.criticality.in_(criticality))
    if incident_id:
        query = query.where(Asset.incident_id == incident_id)
    if search:
        query = query.where(
            or_(
                Asset.hostname.ilike(f"%{search}%"),
                Asset.ip_address.ilike(f"%{search}%"),
            )
        )
    
    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)
    
    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size).order_by(Asset.hostname)
    result = await db.execute(query)
    assets = result.scalars().all()
    
    return PaginatedAssets(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get asset details."""
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.interfaces))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}/status", response_model=AssetStatusResponse)
async def get_asset_status(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get real-time asset status."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # In production, this would query live telemetry
    return AssetStatusResponse(
        asset_id=asset.id,
        status=asset.status,
        threat_score=asset.threat_score,
        active_connections=0,
        suspicious_flows=0,
        blocked_flows=0,
        auth_failures_5min=0,
        cpu_usage=0.0,
        memory_usage=0.0,
        updated_at=datetime.utcnow(),
    )


@router.post("/{asset_id}/contain", response_model=APIResponse)
async def contain_asset(
    asset_id: UUID,
    isolation_level: IsolationLevel = IsolationLevel.QUARANTINE_VLAN,
    reason: str = "Manual containment",
    approved_by: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Contain an asset."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    old_status = asset.status
    asset.status = AssetStatus.CONTAINED
    asset.containment_level = isolation_level
    asset.updated_at = datetime.utcnow()
    
    await db.commit()
    
    # TODO: Execute actual network containment
    # await containment_engine.isolate_host(asset_id, isolation_level)
    
    # Broadcast WebSocket event
    # await ws_manager.broadcast(asset_id, "asset_status_changed", {...})
    
    return APIResponse(
        success=True,
        data={
            "asset_id": str(asset_id),
            "action": "contain",
            "success": True,
            "previous_status": old_status.value,
            "new_status": asset.status.value,
            "isolation_level": isolation_level.value,
            "executed_at": datetime.utcnow().isoformat(),
        }
    )


@router.post("/{asset_id}/restore", response_model=APIResponse)
async def restore_asset(
    asset_id: UUID,
    reason: str = "Incident resolved",
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Restore asset from containment."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    old_status = asset.status
    asset.status = AssetStatus.NORMAL
    asset.containment_level = IsolationLevel.NONE
    asset.threat_score = 0.0
    asset.incident_id = None
    asset.updated_at = datetime.utcnow()
    
    await db.commit()
    
    return APIResponse(
        success=True,
        data={
            "asset_id": str(asset_id),
            "action": "restore",
            "success": True,
            "previous_status": old_status.value,
            "new_status": asset.status.value,
        }
    )