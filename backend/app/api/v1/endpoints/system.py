from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
import psutil
from app.api.deps import get_db, get_current_user, require_roles
from app.models.system_config import SystemConfig
from app.services.live_telemetry import live_telemetry_service

router = APIRouter()

class NetworkConfigUpdate(BaseModel):
    mgmt_iface: str
    capture_iface: str
    mgmt_subnet: str
    mgmt_vlan: int = 40
    mgmt_cidr: str = ""
    mgmt_gateway: str = ""
    capture_mode: str = "span_tap"
    flow_export_enabled: bool = False
    live_telemetry_enabled: bool = False

@router.get("/network-interfaces")
async def get_network_interfaces(current_user: dict = Depends(get_current_user)):
    """Return every interface visible to the collector and, in Docker, its host.

    The API process normally runs in its own network namespace, so psutil only
    sees the container's ``lo``/``eth0`` pair.  Compose mounts the host's
    ``/sys/class/net`` read-only at ``/host-sys/class/net``; merging both views
    lets operators select real interfaces such as wlan0, TAPs, VLANs, bridges,
    and physical NICs without hard-coded names.  The mount is optional so the
    endpoint remains usable outside Compose.
    """
    try:
        container_interfaces = set(psutil.net_if_addrs().keys())
        host_net_dir = Path("/host-sys/class/net")
        host_interfaces = {
            entry.name
            for entry in host_net_dir.iterdir()
            if entry.is_dir() or entry.is_symlink()
        } if host_net_dir.is_dir() else set()
        interfaces = sorted(container_interfaces | host_interfaces)
        return {
            "status": "success",
            "interfaces": interfaces,
            "container_interfaces": sorted(container_interfaces),
            "host_interfaces": sorted(host_interfaces),
            "host_visibility": bool(host_interfaces),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network-config")
async def get_network_config(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    keys = [
        "MGMT_IFACE", "CAPTURE_IFACE", "MGMT_SUBNET", "TELEMETRY_MGMT_VLAN",
        "TELEMETRY_MGMT_CIDR", "TELEMETRY_MGMT_GATEWAY", "TELEMETRY_CAPTURE_MODE",
        "FLOW_EXPORT_ENABLED",
        "LIVE_TELEMETRY_ENABLED",
    ]
    rows = (await db.execute(select(SystemConfig).where(SystemConfig.key.in_(keys)))).scalars().all()
    values = {row.key: row.value for row in rows}
    config = {key: values.get(key, "") for key in keys}
    return {"status": "success", "config": config, "restart_required": True}

@router.post("/network-config")
async def update_network_config(
    config: NetworkConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_roles("admin", "operator")),
):
    updates = {
        "MGMT_IFACE": config.mgmt_iface,
        "CAPTURE_IFACE": config.capture_iface,
        "MGMT_SUBNET": config.mgmt_subnet,
        "TELEMETRY_MGMT_VLAN": str(config.mgmt_vlan),
        "TELEMETRY_MGMT_CIDR": config.mgmt_cidr or config.mgmt_subnet,
        "TELEMETRY_MGMT_GATEWAY": config.mgmt_gateway,
        "TELEMETRY_CAPTURE_MODE": config.capture_mode,
        "FLOW_EXPORT_ENABLED": str(config.flow_export_enabled).lower(),
        "LIVE_TELEMETRY_ENABLED": str(config.live_telemetry_enabled).lower(),
    }
    for key, value in updates.items():
        record = (await db.execute(select(SystemConfig).where(SystemConfig.key == key))).scalar_one_or_none()
        if not record:
            record = SystemConfig(key=key, value=value)
            db.add(record)
        else:
            record.value = value
    await db.commit()
    await live_telemetry_service.set_enabled(config.live_telemetry_enabled)
    return {
        "status": "success",
        "message": "Live telemetry toggle applied. Other interface/exporter changes require a restart.",
        "restart_required": True,
        "updated_by": current_user.get("sub", "unknown"),
    }
