import asyncio
import logging
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from app.core.config import settings
from app.services.nmap_scanner import run_nmap_scan
from app.services.device_registration import register_device
from app.core.database import async_session_maker
from app.models.asset import AssetType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    target_subnet = "172.20.20.0/24"
    logger.info(f"Triggering LIVE Nmap Discovery on {target_subnet}...")
    
    devices = run_nmap_scan(target_subnet)
    logger.info(f"Discovered {len(devices)} devices!")
    
    async with async_session_maker() as session:
        for dev in devices:
            asset_type = AssetType.ROUTER if dev["device_type"] == "network_equipment" else AssetType.WORKSTATION
            logger.info(f"Registering {dev['ip']} (OS: {dev['os_version']}, Type: {asset_type.value})")
            
            # Using the existing register_device function from the backend
            result = await register_device(
                db=session,
                ip=dev['ip'],
                mac=dev['mac'],
                hostname=f"host-{dev['ip'].replace('.', '-')}",
                vendor_class=dev['os_version'],
                source="nmap-live-discovery",
                
            )
            logger.info(f"Result: {result}")
            
    logger.info("Live discovery complete!")

if __name__ == "__main__":
    asyncio.run(main())
