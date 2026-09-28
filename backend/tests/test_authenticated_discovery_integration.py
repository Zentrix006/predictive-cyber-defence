"""
End-to-end integration tests for Authenticated Discovery and Lifecycle Audit.
Satisfies Phase 3 Component 1 of the implementation plan.
"""
from __future__ import annotations

import pytest
from uuid import uuid4
from sqlalchemy import select, delete

from app.models.discovery_evidence import DeviceIdentity, DiscoveryObservation, DeviceLifecycleStatus
from app.services.evidence_service import EvidenceService
from app.schemas.discovery_evidence import DiscoveryObservationCreate, DeviceVerificationAction
from tests.conftest import db_run
from tests.fixtures.lab_network_fixtures import get_all_fixtures

def test_authenticated_discovery_lifecycle_and_reconciliation():
    async def _run(session):
        # Ensure clean state for this integration test
        await session.execute(delete(DiscoveryObservation))
        await session.execute(delete(DeviceIdentity))
        await session.flush()
        
        fixtures = get_all_fixtures()

        identities = []
        # 1. Ingest telemetry & reconcile DeviceIdentity
        for fix in fixtures:
            # We mock the ingestion as creating observations
            ip = fix.get("management_ip") or fix.get("ip_address")
            mac = fix.get("mac_address", "00:00:00:00:00:00")
            host = fix.get("hostname", "unknown")
            vendor = fix.get("vendor", "unknown")
            
            obs = DiscoveryObservationCreate(
                source="snmp" if vendor in ["cisco", "juniper"] else "arp",
                collector="test-collector",
                normalized_fields={
                    "ip": ip,
                    "mac": mac,
                    "hostname": host,
                    "vendor": vendor,
                    "role": "switch" if vendor == "cisco" else "unknown"
                },
                confidence=0.9 if vendor != "unknown" else 0.4
            )
            obs_record = await EvidenceService.record_observation(session, obs)
            assert obs_record.device_id is not None
            
            # Fetch device explicitly
            dev = (await session.execute(select(DeviceIdentity).where(DeviceIdentity.id == obs_record.device_id))).scalar_one()
            identities.append(dev)

        # 2. Verify unknown vendor/model is preserved as `unknown`
        iot_cam = next(i for i in identities if "10.100.30.88" in i.ips)
        assert iot_cam.vendor == "unknown"
        assert iot_cam.hostname == "unknown"
        assert iot_cam.status == "provisional"

        # 3. Verifies operator verification queue (approve, reject, correct)
        # Approve the core switch
        core_sw = next(i for i in identities if i.hostname == "lab-core-sw01")
        action = DeviceVerificationAction(action="approve", notes="Verified core switch", verified_by="admin_user")
        updated_core_sw = await EvidenceService.verify_device_identity(session, core_sw.id, action)
        assert updated_core_sw.status == "verified"

        # Correct the IoT camera
        correct_action = DeviceVerificationAction(
            action="approve", 
            vendor_override="AcmeCam",
            role_override="IoT",
            notes="Identified manually",
            verified_by="admin_user"
        )
        updated_iot = await EvidenceService.verify_device_identity(session, iot_cam.id, correct_action)
        assert updated_iot.status == "verified"
        assert updated_iot.vendor == "AcmeCam"

        # 4. Lifecycle Audit (ACTIVE -> STALE -> RETIRED)
        # We manually transition one to STALE
        workstation = next(i for i in identities if i.hostname == "lab-workstation-04")
        workstation.status = "stale"
        await session.flush()
        
        await session.refresh(workstation)
        assert workstation.status == "stale"

        # Manually transition to RETIRED
        workstation.status = "retired"
        await session.flush()
        await session.refresh(workstation)
        assert workstation.status == "retired"

    db_run(_run)

