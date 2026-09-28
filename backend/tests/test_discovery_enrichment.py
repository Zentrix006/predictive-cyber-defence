"""
Unit and Integration Tests for Discovery Protocol Enrichment (Phase 2).

Tests:
  * SNMPv3 Collector Service (MIB-2, Interfaces, FDB switch port tables)
  * LLDP / CDP Neighbor Collector Service (neighbor parsing, frame parsing, TopologyEdge linking)
  * Subnet CIDR Scanner with Token Bucket Rate Limiting
  * Stale Device Retirement & Lifecycle Management
  * Discovery Enrichment API endpoints
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete

from app.models.discovery_evidence import DeviceIdentity, DiscoveryObservation, TopologyEdge
from app.services.cidr_scanner import SubnetCIDRScanner, TokenBucketRateLimiter
from app.services.discovery_lifecycle import DiscoveryLifecycleService
from app.services.lldp_cdp_collector import LLDPCDPCollectorService
from app.services.snmp_collector import SNMPCollectorService
from tests.conftest import db_run


def test_snmp_collector_mock_and_ingestion():
    """Test SNMPv3 query parsing and evidence ingestion."""
    async def _run(session):
        collector = SNMPCollectorService()
        mock_payload = {
            "sys_name": "switch-core-01",
            "sys_descr": "Cisco Catalyst 9300-48P IOS-XE 17.6.3",
            "sys_object_id": "1.3.6.1.4.1.9.1.2500",
            "uptime_ticks": 45000000,
            "interfaces": [
                {
                    "if_index": 1,
                    "descr": "GigabitEthernet1/0/1",
                    "phys_address": "00:11:22:33:44:55",
                    "speed_bps": 1000000000,
                    "vlan_id": 10,
                },
                {
                    "if_index": 2,
                    "descr": "GigabitEthernet1/0/2",
                    "phys_address": "00:11:22:33:44:56",
                    "speed_bps": 1000000000,
                    "vlan_id": 20,
                },
            ],
            "fdb_table": {
                "aa:bb:cc:dd:ee:01": 1,
                "aa:bb:cc:dd:ee:02": 2,
            },
            "vlans": [10, 20],
        }

        result = await collector.query_device("10.0.1.1", mock_data=mock_payload)
        assert result.sys_name == "switch-core-01"
        assert len(result.interfaces) == 2
        assert len(result.fdb_table) == 2

        # Ingest into EvidenceService
        obs_list = await collector.ingest_snmp_result(session, result)
        assert len(obs_list) == 3  # 1 switch host + 2 FDB endpoints

        switch_obs = obs_list[0]
        assert switch_obs.normalized_fields["ip"] == "10.0.1.1"
        assert switch_obs.confidence == 0.98
        assert switch_obs.source == "snmpv3"
        switch_dev = await session.get(DeviceIdentity, switch_obs.device_id)
        assert switch_dev is not None
        assert switch_dev.hostname == "switch-core-01"

        # Teardown
        dev_ids = [o.device_id for o in obs_list if o.device_id]
        if dev_ids:
            await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id.in_(dev_ids)))
            await session.commit()

    db_run(_run)


def test_lldp_cdp_collector_and_topology_linking():
    """Test LLDP and CDP parsing and TopologyEdge creation."""
    async def _run(session):
        collector = LLDPCDPCollectorService()

        raw_lldp = [
            {
                "lldpRemChassisId": "00:1c:73:00:00:01",
                "lldpRemPortId": "TenGigabitEthernet1/1/1",
                "lldpRemSysName": "dist-switch-01",
                "lldpRemManAddr": "10.0.2.1",
                "local_interface": "TenGigabitEthernet1/1/1",
                "capabilities": ["bridge", "router"],
            }
        ]

        neighbors = collector.parse_snmp_lldp_rem_table(
            local_device_ip="10.0.1.1",
            raw_table=raw_lldp,
        )
        assert len(neighbors) == 1
        assert neighbors[0].remote_system_name == "dist-switch-01"

        # Ingest neighbors and verify TopologyEdge
        edges = await collector.ingest_neighbors(session, neighbors)
        assert len(edges) == 1
        edge = edges[0]
        assert edge.relationship_type == "switched"
        assert edge.status == "active"
        assert edge.source_interface == "TenGigabitEthernet1/1/1"
        assert edge.destination_interface == "TenGigabitEthernet1/1/1"

        # Teardown
        await session.execute(delete(TopologyEdge).where(TopologyEdge.id == edge.id))
        await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id.in_([edge.source_device_id, edge.destination_device_id])))
        await session.commit()

    db_run(_run)


def test_raw_lldp_frame_parsing():
    """Test parsing raw IEEE 802.1AB TLV frame."""
    collector = LLDPCDPCollectorService()
    chassis_tlv = b"\x02\x07\x04\xaa\xbb\xcc\xdd\xee\xff"
    port_tlv = b"\x04\x05\x01eth0"
    ttl_tlv = b"\x06\x02\x00\x78"
    end_tlv = b"\x00\x00"

    raw_frame = chassis_tlv + port_tlv + ttl_tlv + end_tlv
    neighbor = collector.parse_raw_lldp_frame(raw_frame, local_ip="10.0.0.1", local_iface="eth1")
    assert neighbor is not None
    assert neighbor.remote_chassis_id == "aa:bb:cc:dd:ee:ff"
    assert neighbor.remote_port_id == "eth0"
    assert neighbor.ttl_seconds == 120


def test_cidr_scanner_rate_limiting_and_ingest():
    """Test CIDR scanner token bucket limiter and observation creation."""
    async def _run(session):
        limiter = TokenBucketRateLimiter(rate=100.0, capacity=5.0)
        t0 = asyncio.get_event_loop().time()
        await limiter.acquire(2.0)
        await limiter.acquire(2.0)
        elapsed = asyncio.get_event_loop().time() - t0
        assert elapsed < 0.1

        scanner = SubnetCIDRScanner(rate_limit_pps=200.0)
        mock_live = {
            "192.168.10.5": [22, 80],
            "192.168.10.12": [443, 8080],
        }
        report = await scanner.scan_cidr("192.168.10.0/28", mock_live_ips=mock_live)
        assert report.scanned_hosts > 0
        assert report.live_hosts == 2

        # Ingest
        obs_list = await scanner.ingest_scan_report(session, report)
        assert len(obs_list) == 2
        assert obs_list[0].source == "cidr_scan"
        assert obs_list[0].confidence == 0.88
        assert "open_ports" in obs_list[0].normalized_fields

        dev_ids = [o.device_id for o in obs_list if o.device_id]
        if dev_ids:
            await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id.in_(dev_ids)))
            await session.commit()

    db_run(_run)


def test_discovery_lifecycle_stale_and_retire():
    """Test lifecycle status transition to stale and retired and edge archival."""
    async def _run(session):
        now = datetime.now(timezone.utc)
        old_time_stale = now - timedelta(seconds=1200)  # 20 min ago (> 15 min stale threshold)
        old_time_retire = now - timedelta(seconds=90000)  # 25 hrs ago (> 24 hr retire threshold)

        dev_active = DeviceIdentity(
            id=uuid4(),
            primary_mac="00:aa:00:00:00:01",
            primary_ip="10.0.0.1",
            hostname="active-host",
            status="active",
            confidence=0.9,
            first_seen=now,
            last_seen=now,
        )
        dev_stale = DeviceIdentity(
            id=uuid4(),
            primary_mac="00:aa:00:00:00:02",
            primary_ip="10.0.0.2",
            hostname="stale-host",
            status="active",
            confidence=0.9,
            first_seen=old_time_stale,
            last_seen=old_time_stale,
        )
        dev_retire = DeviceIdentity(
            id=uuid4(),
            primary_mac="00:aa:00:00:00:03",
            primary_ip="10.0.0.3",
            hostname="retire-host",
            status="stale",
            confidence=0.9,
            first_seen=old_time_retire,
            last_seen=old_time_retire,
        )
        session.add_all([dev_active, dev_stale, dev_retire])
        await session.commit()
        await session.refresh(dev_active)
        await session.refresh(dev_stale)
        await session.refresh(dev_retire)

        # Add active edge to retiring device
        edge = TopologyEdge(
            id=uuid4(),
            source_device_id=dev_active.id,
            destination_device_id=dev_retire.id,
            relationship_type="switched",
            evidence_source="lldp",
            status="active",
            first_seen=now,
            last_confirmed=now,
        )
        session.add(edge)
        await session.commit()
        await session.refresh(edge)

        # Run audit
        lifecycle = DiscoveryLifecycleService(
            default_stale_threshold_seconds=900,
            default_retirement_threshold_seconds=86400,
        )
        audit_res = await lifecycle.audit_devices(session)

        assert str(dev_stale.id) in audit_res.marked_stale
        assert str(dev_retire.id) in audit_res.marked_retired
        assert audit_res.edges_archived >= 1

        await session.refresh(dev_stale)
        await session.refresh(dev_retire)
        await session.refresh(edge)

        assert dev_stale.status == "stale"
        assert dev_retire.status == "retired"
        assert edge.status == "archived"

        # Teardown
        await session.execute(delete(TopologyEdge).where(TopologyEdge.id == edge.id))
        await session.execute(delete(DeviceIdentity).where(DeviceIdentity.id.in_([dev_active.id, dev_stale.id, dev_retire.id])))
        await session.commit()

    db_run(_run)


def _admin_headers() -> dict[str, str]:
    from datetime import timedelta
    from app.core.security import create_access_token
    token = create_access_token(
        uuid4(),
        expires_delta=timedelta(minutes=5),
        additional_claims={"roles": ["admin"], "elevated": True},
    )
    return {"Authorization": f"Bearer {token}"}


def test_discovery_enrichment_api_endpoints(client):
    """Test REST API endpoints for discovery enrichment."""
    headers = _admin_headers()

    # 1. SNMP query endpoint
    res_snmp = client.post(
        "/api/v1/discovery/snmp/query",
        json={
            "ip": "10.0.100.1",
            "username": "snmp-test",
            "mock_data": {
                "sys_name": "api-switch-01",
                "sys_descr": "Catalyst Switch",
                "interfaces": [
                    {"if_index": 1, "descr": "gi1/0/1", "phys_address": "00:50:56:00:01:01"}
                ],
                "fdb_table": {"00:50:56:00:01:aa": 1},
            },
        },
        headers=headers,
    )
    assert res_snmp.status_code == 200
    snmp_data = res_snmp.json()
    assert snmp_data["status"] == "success"
    assert snmp_data["observations_created"] == 2

    # 2. LLDP ingest endpoint
    res_lldp = client.post(
        "/api/v1/discovery/lldp/ingest",
        json={
            "protocol": "lldp",
            "local_device_ip": "10.0.100.1",
            "neighbors": [
                {
                    "lldpRemChassisId": "00:50:56:00:02:01",
                    "lldpRemPortId": "ge-0/0/0",
                    "lldpRemSysName": "juniper-srx",
                    "local_interface": "gi1/0/1",
                }
            ],
        },
        headers=headers,
    )
    assert res_lldp.status_code == 200
    lldp_data = res_lldp.json()
    assert lldp_data["status"] == "success"
    assert lldp_data["edges_established"] == 1

    # 3. CIDR scan endpoint
    res_cidr = client.post(
        "/api/v1/discovery/cidr/scan",
        json={
            "cidr": "10.10.1.0/28",
            "rate_limit_pps": 100.0,
            "mock_live_ips": {"10.10.1.2": [22, 443]},
        },
        headers=headers,
    )
    assert res_cidr.status_code == 200
    cidr_data = res_cidr.json()
    assert cidr_data["status"] == "success"
    assert cidr_data["live_hosts"] == 1

    # 4. Topology links query
    res_links = client.get("/api/v1/discovery/topology/links?status_filter=active", headers=headers)
    assert res_links.status_code == 200
    links = res_links.json()
    assert len(links) >= 1
    assert links[0]["relationship_type"] == "switched"

    # 5. Lifecycle audit endpoint
    res_audit = client.post(
        "/api/v1/discovery/lifecycle/audit",
        json={"stale_threshold_seconds": 60, "retirement_threshold_seconds": 3600},
        headers=headers,
    )
    assert res_audit.status_code == 200
    assert res_audit.json()["status"] == "success"
