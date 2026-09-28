"""
Topology API Endpoints
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.topology import TopologySnapshot
from app.schemas.topology import NetworkTopology, TopologyNode, TopologyEdge, PredictionEdge
from app.ws.manager import ws_manager

router = APIRouter()


@router.post('/pcap')
async def pcap_topology(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Build an offline replay, without modifying live assets or sending packets."""
    from app.services.pcap_topology import parse_topology
    if not (file.filename or '').lower().endswith(('.pcap', '.pcapng')):
        raise HTTPException(400, 'Upload a .pcap or .pcapng file')
    data = await file.read(50 * 1024 * 1024 + 1)
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, 'Capture too large (maximum 50 MB)')
    try:
        return await run_in_threadpool(parse_topology, data)
    except (ValueError, OverflowError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, 'Cannot parse this capture; check that it is a complete PCAP/PCAPNG file') from exc


@router.get("", response_model=NetworkTopology)
async def get_topology(
    incident_id: Optional[UUID] = Query(None),
    include_predictions: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get full network topology."""
    # Get latest topology snapshot
    query = select(TopologySnapshot)
    if incident_id:
        query = query.where(TopologySnapshot.incident_id == incident_id)
    query = query.order_by(TopologySnapshot.timestamp.desc()).limit(1)
    
    result = await db.execute(query)
    snapshot = result.scalar_one_or_none()
    
    if not snapshot:
        # Return empty topology
        return NetworkTopology(
            nodes=[],
            edges=[],
            prediction_edges=[],
            timestamp=datetime.utcnow(),
            incident_id=incident_id,
        )
    
    return NetworkTopology(
        nodes=[TopologyNode(**n) for n in snapshot.nodes],
        edges=[TopologyEdge(**e) for e in snapshot.edges],
        prediction_edges=[PredictionEdge(**e) for e in snapshot.prediction_edges] if include_predictions else [],
        timestamp=snapshot.timestamp,
        incident_id=snapshot.incident_id,
    )


@router.websocket("/live")
async def topology_websocket(
    websocket: WebSocket,
    incident_id: Optional[UUID] = None,
    token: Optional[str] = None,
):
    """WebSocket for real-time topology updates."""
    await ws_manager.connect(websocket, incident_id)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "subscribe":
                # Handle subscription
                pass
            elif data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, incident_id)


# Import datetime for topology endpoint
from datetime import datetime
