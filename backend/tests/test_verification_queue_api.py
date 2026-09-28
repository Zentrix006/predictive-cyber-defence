"""
Integration tests for Operator Verification Queue (Mode B — Verify) and Phase 3 API endpoints.
"""
from __future__ import annotations

from uuid import uuid4
import pytest
from sqlalchemy import delete

from app.models.discovery_evidence import DeviceIdentity, DiscoveryObservation, DeviceLifecycleStatus
from app.services.evidence_service import EvidenceService
from app.schemas.discovery_evidence import DiscoveryObservationCreate, DeviceVerificationAction
from tests.conftest import db_run


def test_operator_verification_queue_listing_and_approve():
    async def _run(session):
        test_ip = f"192.168.200.{uuid4().hex[:2]}"
        test_mac = f"02:00:00:{uuid4().hex[:2]}:{uuid4().hex[2:4]}:{uuid4().hex[4:6]}"
        test_host = f"unverified-sw-{uuid4().hex[:6]}"

        # 1. Create a provisional device with multi-source observations
        dev = await EvidenceService.get_or_create_device_identity(
            session,
            ip=test_ip,
            mac=test_mac,
            hostname=test_host,
            device_role="unknown",
        )
        assert dev.status == DeviceLifecycleStatus.PROVISIONAL.value

        # Record ARP observation
        obs1 = DiscoveryObservationCreate(
            source="arp",
            collector="test_collector",
            raw_evidence_ref="arp_entry",
            normalized_fields={"ip": test_ip, "mac": test_mac},
            confidence=0.65,
        )
        await EvidenceService.record_observation(session, obs1)

        # Record CDP observation
        obs2 = DiscoveryObservationCreate(
            source="cdp",
            collector="test_collector",
            raw_evidence_ref="cdp_neighbor",
            normalized_fields={
                "ip": test_ip,
                "vendor": "cisco",
                "role": "switch",
                "model": "Catalyst 9300",
            },
            confidence=0.90,
        )
        await EvidenceService.record_observation(session, obs2)
        await session.commit()

        # 2. Operator reviews queue and approves device
        action = DeviceVerificationAction(
            action="approve",
            verified_by="security_analyst_01",
            role_override="switch",
            notes="Manually verified physical switch in rack 4",
        )
        verified_dev = await EvidenceService.verify_device_identity(session, dev.id, action)
        await session.commit()

        assert verified_dev.status == DeviceLifecycleStatus.VERIFIED.value
        assert verified_dev.verified_by == "security_analyst_01"
        assert verified_dev.device_role == "switch"
        assert verified_dev.confidence >= 0.90

        # Cleanup
        await session.execute(delete(DiscoveryObservation).where(DiscoveryObservation.device_id == dev.id))
        await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id == dev.id))
        await session.commit()

    db_run(_run)


def test_operator_verification_reject():
    async def _run(session):
        test_ip = f"10.200.200.{uuid4().hex[:2]}"
        test_mac = f"02:00:01:{uuid4().hex[:2]}:{uuid4().hex[2:4]}:{uuid4().hex[4:6]}"
        test_host = f"rogue-laptop-{uuid4().hex[:6]}"

        dev = await EvidenceService.get_or_create_device_identity(
            session,
            ip=test_ip,
            mac=test_mac,
            hostname=test_host,
        )
        assert dev.status == DeviceLifecycleStatus.PROVISIONAL.value

        action = DeviceVerificationAction(
            action="reject",
            verified_by="sec_admin",
            notes="Unauthorized rogue asset blocked",
        )
        rejected = await EvidenceService.verify_device_identity(session, dev.id, action)
        await session.commit()

        assert rejected.status == DeviceLifecycleStatus.REJECTED.value
        assert rejected.verified_by == "sec_admin"

        # Cleanup
        await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id == dev.id))
        await session.commit()

    db_run(_run)


def test_operator_verification_merge():
    async def _run(session):
        can_ip = f"172.16.200.{uuid4().hex[:2]}"
        can_mac = f"02:00:02:{uuid4().hex[:2]}:{uuid4().hex[2:4]}:{uuid4().hex[4:6]}"
        prov_ip = f"172.16.201.{uuid4().hex[:2]}"
        prov_mac = f"02:00:03:{uuid4().hex[:2]}:{uuid4().hex[2:4]}:{uuid4().hex[4:6]}"

        # Target canonical device
        canonical = await EvidenceService.get_or_create_device_identity(
            session,
            ip=can_ip,
            mac=can_mac,
            hostname="core-router",
            device_role="router",
        )

        # Duplicate provisional device discovered on secondary interface
        provisional = await EvidenceService.get_or_create_device_identity(
            session,
            ip=prov_ip,
            mac=prov_mac,
            hostname="core-router-sub",
        )

        action = DeviceVerificationAction(
            action="merge",
            target_device_id=canonical.id,
            verified_by="network_lead",
        )
        merged = await EvidenceService.verify_device_identity(session, provisional.id, action)
        await session.commit()

        assert merged.status == DeviceLifecycleStatus.MERGED.value
        # Canonical device now includes both IPs
        assert prov_ip in canonical.ips

        # Cleanup
        await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id.in_([canonical.id, provisional.id])))
        await session.commit()

    db_run(_run)
