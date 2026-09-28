"""
Unit and Integration Tests for Graph Snapshot Pipeline & G-FLOWWM Integration (Phase 4).
"""
from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4
import pytest
import torch
from sqlalchemy import delete

from app.models.discovery_evidence import (
    DeviceIdentity,
    TopologyEdge,
    DeviceLifecycleStatus,
    EdgeRelationshipType,
    EdgeLifecycleStatus,
)
from app.services.evidence_service import EvidenceService
from app.services.graph_snapshot_pipeline import (
    TemporalGraphSnapshotPipeline,
    GraphSnapshotData,
    GraphPredictionResult,
)
from tests.conftest import db_run

# Add ml-engine to sys.path
ML_ENGINE = Path(__file__).resolve().parents[2] / "ml-engine"
if str(ML_ENGINE) not in sys.path:
    sys.path.insert(0, str(ML_ENGINE))

from models.graph_world_model import GraphFlowWorldModel


def test_extract_graph_snapshot_and_missing_masks():
    async def _run(session):
        uid1 = uuid4().hex[:6]
        uid2 = uuid4().hex[:6]
        uid3 = uuid4().hex[:6]

        # 1. Create 3 devices with various measured/unmeasured attributes
        sw = await EvidenceService.get_or_create_device_identity(
            session,
            ip=f"10.100.1.{uid1[:2]}",
            mac=f"02:10:00:{uid1[:2]}:{uid1[2:4]}:{uid1[4:6]}",
            hostname=f"sw-core-{uid1}",
            vendor="cisco",
            device_role="switch",
        )
        rtr = await EvidenceService.get_or_create_device_identity(
            session,
            ip=f"10.100.2.{uid2[:2]}",
            mac=f"02:10:01:{uid2[:2]}:{uid2[2:4]}:{uid2[4:6]}",
            hostname=f"rtr-border-{uid2}",
            vendor="juniper",
            device_role="router",
        )
        srv = await EvidenceService.get_or_create_device_identity(
            session,
            ip=f"10.100.3.{uid3[:2]}",
            mac=f"02:10:02:{uid3[:2]}:{uid3[2:4]}:{uid3[4:6]}",
            hostname=f"srv-db-{uid3}",
            vendor="dell",
            device_role="server",
        )

        # 2. Create topology edges: sw <-> rtr and sw <-> srv
        edge1 = TopologyEdge(
            source_device_id=sw.id,
            destination_device_id=rtr.id,
            relationship_type="trunk",
            vlan_id=100,
            confidence=0.95,
            evidence_source="lldp",
            status=EdgeLifecycleStatus.ACTIVE.value,
        )
        edge2 = TopologyEdge(
            source_device_id=sw.id,
            destination_device_id=srv.id,
            relationship_type="access",
            vlan_id=10,
            confidence=0.90,
            evidence_source="cdp",
            status=EdgeLifecycleStatus.ACTIVE.value,
        )
        session.add_all([edge1, edge2])
        await session.commit()

        # 3. Extract graph snapshot
        snapshot: GraphSnapshotData = await TemporalGraphSnapshotPipeline.extract_graph_snapshot(session)
        assert snapshot.nodes.shape[0] == 1
        assert snapshot.nodes.shape[1] >= 3
        assert snapshot.nodes.shape[2] == 24
        assert snapshot.node_mask.shape == snapshot.nodes.shape
        # Explicit missing masks density: must be between 0 and 1
        mask_density = float(snapshot.node_mask.mean().item())
        assert 0.0 < mask_density < 1.0

        # Adjacency matrix verification
        assert snapshot.adjacency_matrix.shape[0] >= 3
        assert snapshot.edge_index.size(-1) >= 2

        # 4. Evaluate Graph Dynamics & Lateral Link Prediction
        result: GraphPredictionResult = TemporalGraphSnapshotPipeline.evaluate_graph_dynamics(snapshot)
        assert result.graph_surprisal >= 0.0
        assert isinstance(result.helmholtz_free_energy, float)
        assert len(result.node_risk_scores) >= 3

        # rtr and srv are not directly connected, but connected via sw (2-hop).
        # Link prediction must identify rtr <-> srv lateral pivot candidate
        pivots = [e for e in result.predicted_lateral_edges if "rtr" in e["source_ip"] or "rtr" in e["destination_ip"] or "srv" in e["source_ip"] or "srv" in e["destination_ip"]]
        assert len(result.predicted_lateral_edges) >= 1

        # Teardown
        await session.execute(delete(TopologyEdge).where(TopologyEdge.id.in_([edge1.id, edge2.id])))
        await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id.in_([sw.id, rtr.id, srv.id])))
        await session.commit()

    db_run(_run)


def test_graph_flow_world_model_forward_pass():
    """Verify GraphFlowWorldModel processes attributed graph tensors with action conditioning."""
    model = GraphFlowWorldModel(
        node_dim=24,
        edge_dim=16,
        d_model=32,
        horizon=3,
        num_layers=2,
    )
    model.eval()

    b, n, e = 1, 5, 4
    nodes = torch.randn(b, n, 24)
    edges = torch.randn(b, e, 16)
    edge_index = torch.tensor([[[0, 1, 2, 3], [1, 2, 3, 4]]], dtype=torch.long)
    action = torch.tensor([2], dtype=torch.long)  # DECEPTION_DIVERT

    out = model(nodes, edge_index, edges, action_id=action)
    assert out.latent_state.shape == (1, 5, 32)
    assert out.predicted_latent_future.shape == (1, 3, 5, 32)
    assert out.node_risk_logits.shape == (1, 5)
    assert out.node_stage_logits.shape == (1, 5, 14)
    assert out.action_impact_score is not None
