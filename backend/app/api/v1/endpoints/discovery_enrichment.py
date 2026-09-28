"""
Discovery Protocol Enrichment Endpoints.

Provides REST APIs for:
  * SNMPv3 query & FDB switch port ingestion
  * LLDP/CDP neighbor topology linking
  * Subnet CIDR rate-limited scanning
  * Stale device retirement & lifecycle audit
  * Topology links inspection
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import get_current_user
from app.models.discovery_evidence import TopologyEdge
from app.schemas.discovery_evidence import TopologyEdgeResponse
from app.services.cidr_scanner import SubnetCIDRScanner
from app.services.discovery_lifecycle import DiscoveryLifecycleService
from app.services.lldp_cdp_collector import LLDPCDPCollectorService
from app.services.snmp_collector import SNMPCollectorService, SNMPv3Credentials

# Discovery can change topology evidence and initiate network probes; require
# an authenticated operator for every route in this router.
router = APIRouter(
    prefix="/discovery",
    tags=["Discovery Protocol Enrichment"],
    dependencies=[Depends(get_current_user)],
)


class SNMPQueryRequest(BaseModel):
    ip: str = Field(..., description="Target IP of the managed network device")
    username: Optional[str] = Field("snmp-admin", description="SNMPv3 user")
    auth_key: Optional[str] = Field(None, description="Auth pass-phrase")
    priv_key: Optional[str] = Field(None, description="Privacy encryption key")
    mock_data: Optional[Dict[str, Any]] = Field(None, description="Mock MIB/interfaces payload for testing")


class LLDPCDPIngestRequest(BaseModel):
    protocol: str = Field("lldp", description="Protocol ('lldp' or 'cdp')")
    local_device_ip: str = Field(..., description="IP of the observing switch/router")
    neighbors: List[Dict[str, Any]] = Field(..., description="List of neighbor records")


class CIDRScanRequest(BaseModel):
    cidr: str = Field(..., description="CIDR block to scan, e.g. 192.168.1.0/24")
    probe_ports: Optional[List[int]] = Field(None, description="Ports to check for open services")
    max_hosts: int = Field(256, ge=1, le=1024, description="Maximum hosts to sweep")
    rate_limit_pps: float = Field(50.0, ge=1.0, le=500.0, description="Rate limit (packets/second)")
    mock_live_ips: Optional[Dict[str, List[int]]] = Field(None, description="Mock live IP map for tests")


class LifecycleAuditRequest(BaseModel):
    stale_threshold_seconds: Optional[int] = Field(900, description="Seconds without observation before stale")
    retirement_threshold_seconds: Optional[int] = Field(86400, description="Seconds before permanent retirement")


@router.post("/snmp/query")
async def query_and_ingest_snmp(
    req: SNMPQueryRequest,
    db: AsyncSession = Depends(get_db),
):
    """Executes SNMPv3 query against target device and ingests MIB-2, interface, and FDB records."""
    collector = SNMPCollectorService()
    creds = SNMPv3Credentials(username=req.username or "snmp-admin", auth_key=req.auth_key, priv_key=req.priv_key)
    res = await collector.query_device(ip=req.ip, credentials=creds, mock_data=req.mock_data)
    observations = await collector.ingest_snmp_result(db, res)
    return {
        "status": "success",
        "target_ip": req.ip,
        "sys_name": res.sys_name,
        "interfaces_count": len(res.interfaces),
        "fdb_entries_count": len(res.fdb_table),
        "observations_created": len(observations),
    }


@router.post("/lldp/ingest")
async def ingest_lldp_cdp_neighbors(
    req: LLDPCDPIngestRequest,
    db: AsyncSession = Depends(get_db),
):
    """Ingests LLDP/CDP neighbor tables and links adjacent devices via TopologyEdge."""
    collector = LLDPCDPCollectorService()
    if req.protocol.lower() == "cdp":
        parsed = collector.parse_snmp_cdp_cache_table(req.local_device_ip, req.neighbors)
    else:
        parsed = collector.parse_snmp_lldp_rem_table(req.local_device_ip, req.neighbors)

    edges = await collector.ingest_neighbors(db, parsed)
    return {
        "status": "success",
        "protocol": req.protocol,
        "local_device_ip": req.local_device_ip,
        "neighbors_parsed": len(parsed),
        "edges_established": len(edges),
    }


@router.post("/cidr/scan")
async def run_cidr_scan(
    req: CIDRScanRequest,
    db: AsyncSession = Depends(get_db),
):
    """Executes a token-bucket rate-limited scan across the given CIDR block."""
    scanner = SubnetCIDRScanner(rate_limit_pps=req.rate_limit_pps)
    report = await scanner.scan_cidr(
        cidr=req.cidr,
        probe_ports=req.probe_ports,
        max_hosts=req.max_hosts,
        mock_live_ips=req.mock_live_ips,
    )
    observations = await scanner.ingest_scan_report(db, report)
    return {
        "status": "success",
        "cidr": req.cidr,
        "scanned_hosts": report.scanned_hosts,
        "live_hosts": report.live_hosts,
        "duration_seconds": report.duration_seconds,
        "observations_created": len(observations),
    }


@router.post("/lifecycle/audit")
async def audit_device_lifecycle(
    req: LifecycleAuditRequest,
    db: AsyncSession = Depends(get_db),
):
    """Evaluates liveness decay and transitions unresponsive devices to stale or retired."""
    lifecycle = DiscoveryLifecycleService(
        default_stale_threshold_seconds=req.stale_threshold_seconds or 900,
        default_retirement_threshold_seconds=req.retirement_threshold_seconds or 86400,
    )
    result = await lifecycle.audit_devices(
        db,
        stale_threshold_seconds=req.stale_threshold_seconds,
        retirement_threshold_seconds=req.retirement_threshold_seconds,
    )
    return {
        "status": "success",
        "total_evaluated": result.total_evaluated,
        "marked_stale": len(result.marked_stale),
        "marked_retired": len(result.marked_retired),
        "edges_archived": result.edges_archived,
        "snapshots_created": result.snapshots_created,
    }


@router.get("/topology/links", response_model=List[TopologyEdgeResponse])
async def list_topology_links(
    edge_type: Optional[str] = Query(None, description="Filter by edge type (e.g. physical_link)"),
    status_filter: Optional[str] = Query("active", description="Filter by edge status"),
    db: AsyncSession = Depends(get_db),
):
    """Returns active physical and logical topology edges."""
    query = select(TopologyEdge)
    if edge_type:
        query = query.where(TopologyEdge.edge_type == edge_type)
    if status_filter:
        query = query.where(TopologyEdge.status == status_filter)

    res = await db.execute(query)
    return res.scalars().all()
