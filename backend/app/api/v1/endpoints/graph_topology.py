"""
Graph-Temporal World Model & Topology Snapshot API (Phase 4).
Exposes attributed multigraph state, lateral movement link prediction,
and graph-level Cyber-JEPA surprisal.
"""
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.services.graph_snapshot_pipeline import (
    TemporalGraphSnapshotPipeline,
    GraphSnapshotData,
    GraphPredictionResult,
)

router = APIRouter(prefix="/topology/world-model", tags=["topology-world-model"])


@router.get("/snapshot")
async def get_graph_snapshot(
    include_provisional: bool = Query(True, description="Include provisional devices in graph"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve the current attributed multigraph tensor snapshot extracted from verified discovery evidence.
    Includes explicit missing-value masks for unmeasured attributes.
    """
    try:
        snapshot: GraphSnapshotData = await TemporalGraphSnapshotPipeline.extract_graph_snapshot(
            db, include_provisional=include_provisional
        )
        return {
            "status": "success",
            "metadata": snapshot.metadata,
            "device_ids": [str(d) for d in snapshot.device_ids],
            "ip_addresses": snapshot.ip_addresses,
            "nodes_shape": list(snapshot.nodes.shape),
            "edge_index_shape": list(snapshot.edge_index.shape),
            "node_missing_mask_density": round(float(snapshot.node_mask.mean().item()), 4),
            "edge_missing_mask_density": round(float(snapshot.edge_mask.mean().item() if snapshot.edge_mask.numel() > 0 else 1.0), 4),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate graph snapshot: {str(e)}")


@router.get("/dynamics")
async def get_graph_dynamics(
    include_provisional: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Execute G-FLOWWM relational inference over the live graph:
    - Lateral movement link prediction
    - Per-node compromise probability
    - Graph-level Cyber-JEPA surprisal & Helmholtz free energy
    """
    try:
        snapshot = await TemporalGraphSnapshotPipeline.extract_graph_snapshot(
            db, include_provisional=include_provisional
        )
        result: GraphPredictionResult = TemporalGraphSnapshotPipeline.evaluate_graph_dynamics(snapshot)
        return {
            "status": "success",
            "node_count": len(snapshot.ip_addresses),
            "predicted_lateral_edges": result.predicted_lateral_edges,
            "node_risk_scores": result.node_risk_scores,
            "graph_surprisal": result.graph_surprisal,
            "helmholtz_free_energy": result.helmholtz_free_energy,
            "is_topological_anomaly": result.is_topological_anomaly,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to evaluate graph dynamics: {str(e)}")
