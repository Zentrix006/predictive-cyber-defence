"""Live telemetry control and read-only observability endpoints."""
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_user
from app.services.live_telemetry import live_telemetry_service

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/status", response_model=dict)
async def telemetry_status(current_user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return management/capture health and collector counters."""
    return live_telemetry_service.status()


@router.get("/sources", response_model=dict)
async def telemetry_sources(current_user: dict = Depends(get_current_user)) -> dict[str, Any]:
    status = live_telemetry_service.status()
    counts = status.get("source_counts", {})
    trusted_counts = status.get("trusted_source_counts", {})
    provenance = status.get("provenance", {})
    return {
        "sources": [
            {
                "id": "zeek_file_tail",
                "kind": "span_tap",
                "enabled": status["enabled"],
                "interface": status["capture"]["interface"],
                "mode": status["capture"]["mode"],
                "records_seen": counts.get("zeek", 0),
                "trusted_records": trusted_counts.get("zeek", 0),
                "trusted_for_graph": bool(trusted_counts.get("zeek", 0)) and bool(provenance.get("trusted_graph_ready")),
                "read_only": True,
            },
            {
                "id": "flow_export_udp",
                "kind": "netflow_v1_v5_v9_ipfix_or_json",
                "enabled": status["flow_export"]["enabled"],
                "listen_addr": status["flow_export"]["listen_addr"],
                "listen_port": status["flow_export"]["listen_port"],
                "records_seen": counts.get("netflow_ipfix", 0) + counts.get("flow_export", 0),
                "trusted_records": trusted_counts.get("netflow_ipfix", 0) + trusted_counts.get("flow_export", 0),
                "trusted_for_graph": bool(trusted_counts.get("netflow_ipfix", 0) + trusted_counts.get("flow_export", 0)) and bool(provenance.get("trusted_graph_ready")),
                "read_only": True,
            },
        ],
        "provenance": provenance,
    }


@router.get("/records", response_model=dict)
async def telemetry_records(
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    records = live_telemetry_service.recent(limit)
    return {
        "available": bool(records),
        "records": records,
        "count": len(records),
        "status": live_telemetry_service.status(),
    }


@router.get("/graph", response_model=dict)
async def telemetry_graph(current_user: dict = Depends(get_current_user)) -> dict[str, Any]:
    status = live_telemetry_service.status()
    return {
        "available": bool(status.get("latest_graph")),
        "snapshot": status.get("latest_graph"),
        "status": status,
    }
