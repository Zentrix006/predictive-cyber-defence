import pytest
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.base import Base
from app.models.syntax_template import VendorSyntaxTemplate
from app.models.asset import Asset
from app.services.discovery_profiler import DiscoverySyntaxProfiler
from app.services.mitigation_executor import IncidentMitigationExecutor

# Setup test DB
engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.mark.asyncio
async def test_proactive_profiling_and_mitigation():
    db = SessionLocal()
    
    # 1. Simulate a new device discovery (Palo Alto)
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
    
    # 2. Trigger Discovery Profiler
    profiler = DiscoverySyntaxProfiler(db)
    await profiler.handle_new_device_discovery(asset.vendor, asset.os_version)
    
    # Check DB cache
    cached = db.query(VendorSyntaxTemplate).filter_by(vendor=asset.vendor, os_version=asset.os_version).all()
    assert len(cached) == 4
    
    # 3. Simulate an Incident Response execution
    executor = IncidentMitigationExecutor(db)
    result = await executor.execute_mitigation(
        asset_id="asset-1",
        intent="BLOCK_IP_INGRESS",
        context={"target_ip": "192.168.1.100"}
    )
    
    assert result["status"] == "success"
    assert "192.168.1.100" in result["compiled_script"]
    assert "deny" in result["compiled_script"]
    print(f"Compiled PAN-OS Script:\n{result['compiled_script']}")
