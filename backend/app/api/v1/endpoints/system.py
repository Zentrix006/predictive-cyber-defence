from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import List, Optional
import psutil
from app.api.deps import get_db
from app.models.system_config import SystemConfig

router = APIRouter()

class NetworkConfigUpdate(BaseModel):
    mgmt_iface: str
    capture_iface: str
    mgmt_subnet: str

@router.get("/network-interfaces")
async def get_network_interfaces():
    try:
        interfaces = list(psutil.net_if_addrs().keys())
        return {"status": "success", "interfaces": interfaces}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network-config")
async def get_network_config(db: Session = Depends(get_db)):
    keys = ["MGMT_IFACE", "CAPTURE_IFACE", "MGMT_SUBNET"]
    config = {}
    for key in keys:
        record = db.query(SystemConfig).filter(SystemConfig.key == key).first()
        config[key] = record.value if record else ""
    return {"status": "success", "config": config}

@router.post("/network-config")
async def update_network_config(config: NetworkConfigUpdate, db: Session = Depends(get_db)):
    updates = {
        "MGMT_IFACE": config.mgmt_iface,
        "CAPTURE_IFACE": config.capture_iface,
        "MGMT_SUBNET": config.mgmt_subnet
    }
    
    for key, value in updates.items():
        record = db.query(SystemConfig).filter(SystemConfig.key == key).first()
        if not record:
            record = SystemConfig(key=key, value=value)
            db.add(record)
        else:
            record.value = value
            
    db.commit()
    return {"status": "success", "message": "Network configuration updated successfully"}
