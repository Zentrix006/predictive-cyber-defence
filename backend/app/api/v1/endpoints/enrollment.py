"""
Autonomous Device Enrollment API Endpoints

When a device joins the network it is discovered (via the network discovery
scanner) or reported by the network/agent to GET /api/v1/enrollment/join. The
system classifies the device, auto-registers it as an Asset, writes it into the
topology snapshot, and broadcasts a ``node_added`` event so connected
dashboards update live.
"""
from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.services.device_registration import register_device

router = APIRouter()


@router.get("/join")
async def enroll_device(
    request: Request,
    mac: Optional[str] = Query(None, description="Device MAC address"),
    ip: Optional[str] = Query(None, description="Device IP address"),
    hostname: Optional[str] = Query(None, description="Device hostname"),
    user_agent: Optional[str] = Query(None, description="Device User-Agent header"),
    vendor_class: Optional[str] = Query(None, description="DHCP vendor class (option 60)"),
    services: Optional[List[str]] = Query(None, description="Advertised mDNS/DNS-SD service types"),
    incident_id: Optional[UUID] = Query(None, description="Incident to attach the asset to"),
    db: AsyncSession = Depends(get_db),
):
    """Auto-register a device into the network topology."""
    # When the device cannot supply a MAC (e.g. a phone opening the join URL),
    # it is identified by its SOURCE IP as seen by the server. The User-Agent
    # HTTP header is used for classification.
    client_ip = request.client.host if request.client else None
    ip_address = ip or client_ip or "0.0.0.0"

    if not user_agent:
        user_agent = request.headers.get("user-agent")

    hostname = hostname or "device-" + (ip_address or "unknown").replace(".", "-")

    if not (mac or ip or client_ip):
        raise HTTPException(status_code=400, detail="Device IP address could not be determined")

    result = await register_device(
        db,
        mac=mac,
        ip=ip_address,
        hostname=hostname,
        user_agent=user_agent,
        vendor_class=vendor_class,
        services=services,
        incident_id=incident_id,
        source="enrollment",
    )
    return result
