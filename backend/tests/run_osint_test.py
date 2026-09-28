import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.base import Base
from app.models.syntax_template import VendorSyntaxTemplate
from app.models.asset import Asset
from app.services.discovery_profiler import DiscoverySyntaxProfiler
from app.services.mitigation_executor import IncidentMitigationExecutor

engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

async def main():
    db = SessionLocal()
    
    print("[1] Simulating Discovery of Novel Hardware: Palo Alto Networks PAN-OS 10.1")
    asset = Asset(
        id="asset-1",
        ip_address="10.0.0.254",
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="pan-fw-01",
        vendor="Palo Alto Networks",
        os_version="PAN-OS 10.1",
        device_type="firewall"
    )
    db.add(asset)
    db.commit()
    
    profiler = DiscoverySyntaxProfiler(db)
    await profiler.handle_new_device_discovery(asset.vendor, asset.os_version)
    
    # Wait for background task
    await asyncio.sleep(2.5)
    
    cached = db.query(VendorSyntaxTemplate).filter_by(vendor=asset.vendor, os_version=asset.os_version).all()
    print(f"[2] DB Cache verified. Stored {len(cached)} OSINT templates for {asset.vendor}")
    
    print("[3] Simulating Incident Response Mitigations via fast-path...")
    executor = IncidentMitigationExecutor(db)
    result = await executor.execute_mitigation(
        asset_id="asset-1",
        intent="BLOCK_IP_INGRESS",
        context={"target_ip": "192.168.1.100"}
    )
    
    print(f"\n[OUTPUT PAYLOAD]\nStatus: {result['status']}\nScript:\n{result['compiled_script']}\n")
    
    # Try another intent
    result2 = await executor.execute_mitigation(
        asset_id="asset-1",
        intent="ASSIGN_QUARANTINE_VLAN",
        context={"interface": "ethernet1/1", "quarantine_vlan": "999"}
    )
    print(f"Status: {result2['status']}\nScript:\n{result2['compiled_script']}")

if __name__ == "__main__":
    asyncio.run(main())
