import uuid
from datetime import timedelta
import pytest
from app.core.security import create_access_token
from app.services.evidence_service import calculate_fusion_confidence


def _admin_headers() -> dict[str, str]:
    token = create_access_token(
        uuid.uuid4(),
        expires_delta=timedelta(minutes=5),
        additional_claims={"roles": ["admin"], "elevated": True},
    )
    return {"Authorization": f"Bearer {token}"}


def test_bayesian_confidence_fusion():
    """Verify multi-source confidence fusion calculates correct asymptotic confidence."""
    # Single source
    assert calculate_fusion_confidence([0.65]) == 0.65
    # Two corroborating sources (e.g. ARP 0.65 + DHCP 0.85)
    fused = calculate_fusion_confidence([0.65, 0.85])
    assert fused > 0.85
    assert fused == 0.9475  # 1 - (1 - 0.65)*(1 - 0.85) = 1 - 0.35*0.15 = 0.9475
    # Three sources
    fused_3 = calculate_fusion_confidence([0.65, 0.85, 0.95])
    assert fused_3 > 0.95
    assert fused_3 <= 0.99


def test_discovery_observation_and_device_resolution(client):
    headers = _admin_headers()
    mac = f"00:50:56:{uuid.uuid4().hex[:6]}"
    ip = f"10.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 250 + 2}"
    hostname = f"sw-{uuid.uuid4().hex[:6]}"

    # 1. Record initial ARP observation
    resp1 = client.post(
        "/api/v1/evidence/observations",
        json={
            "source": "arp",
            "collector": "eth0",
            "normalized_fields": {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "role": "switch",
                "zone": "management",
            },
            "confidence": 0.65,
            "raw_evidence_ref": "pcap://capture-dmz-01/frame-1029",
        },
        headers=headers,
    )
    assert resp1.status_code == 201
    data1 = resp1.json()
    assert data1["source"] == "arp"
    assert data1["device_id"] is not None
    device_id = data1["device_id"]

    # 2. Record corroborating SNMP observation on same device
    resp2 = client.post(
        "/api/v1/evidence/observations",
        json={
            "source": "snmpv3",
            "collector": "snmp-engine",
            "device_id": device_id,
            "normalized_fields": {
                "ip": ip,
                "mac": mac,
                "vendor": "Cisco",
                "model": "Catalyst 9300",
            },
            "confidence": 0.95,
            "auth_method": "authPriv",
        },
        headers=headers,
    )
    assert resp2.status_code == 201
    data2 = resp2.json()
    assert data2["device_id"] == device_id

    # 3. Verify Device Identity was updated and fused confidence increased
    dev_resp = client.get(f"/api/v1/evidence/devices/{device_id}", headers=headers)
    assert dev_resp.status_code == 200
    dev = dev_resp.json()
    assert dev["primary_ip"] == ip
    assert dev["primary_mac"] == mac.lower()
    assert dev["vendor"] == "Cisco"
    assert dev["status"] == "provisional"
    assert dev["confidence"] > 0.85  # Corroborated fused confidence


def test_operator_verification_workflow(client):
    headers = _admin_headers()
    mac = f"00:1a:2b:{uuid.uuid4().hex[:6]}"
    ip = f"10.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 200 + 10}.{uuid.uuid4().int % 250 + 2}"

    # Create observation to spawn device
    obs_resp = client.post(
        "/api/v1/evidence/observations",
        json={
            "source": "dhcp",
            "collector": "dhcp-sniffer",
            "normalized_fields": {"ip": ip, "mac": mac, "role": "server"},
            "confidence": 0.85,
        },
        headers=headers,
    )
    assert obs_resp.status_code == 201
    device_id = obs_resp.json()["device_id"]

    # Operator approves device
    ver_resp = client.post(
        "/api/v1/evidence/devices/{}/verify".format(device_id),
        json={
            "action": "approve",
            "verified_by": "secops-analyst-1",
            "vendor_override": "Dell",
            "role_override": "domain_controller",
            "notes": "Verified against enterprise CMDB inventory.",
        },
        headers=headers,
    )
    assert ver_resp.status_code == 200
    updated_dev = ver_resp.json()
    assert updated_dev["status"] == "verified"
    assert updated_dev["vendor"] == "Dell"
    assert updated_dev["device_role"] == "domain_controller"
    assert updated_dev["verified_by"] == "secops-analyst-1"
    assert updated_dev["confidence"] >= 0.90


def test_device_snapshot_and_topology_edge_reconciliation(client):
    headers = _admin_headers()
    mac1 = f"00:11:22:{uuid.uuid4().hex[:6]}"
    mac2 = f"00:33:44:{uuid.uuid4().hex[:6]}"

    # Spawn 2 devices
    dev1 = client.post(
        "/api/v1/evidence/observations",
        json={"source": "lldp", "collector": "eth0", "normalized_fields": {"ip": "10.0.1.1", "mac": mac1, "role": "switch"}},
        headers=headers,
    ).json()["device_id"]

    dev2 = client.post(
        "/api/v1/evidence/observations",
        json={"source": "lldp", "collector": "eth0", "normalized_fields": {"ip": "10.0.1.2", "mac": mac2, "role": "router"}},
        headers=headers,
    ).json()["device_id"]

    # 1. Capture snapshot for dev1
    snap_resp = client.post(
        "/api/v1/evidence/snapshots",
        json={
            "device_id": dev1,
            "interfaces": [{"name": "GigabitEthernet1/0/1", "oper_status": "up", "speed": 1000}],
            "link_state": {"admin_up": True, "duplex": "full"},
            "vlans_and_trunks": {"access_vlan": 10, "trunk_vlans": [10, 20, 30]},
            "routing_table": [{"destination": "0.0.0.0/0", "next_hop": "10.0.1.254"}],
            "neighbours": [{"chassis_id": mac2, "port": "Gi0/0"}],
            "configuration_hash": "sha256_mock_abc123",
            "source_observation_ids": [],
        },
        headers=headers,
    )
    assert snap_resp.status_code == 201
    assert snap_resp.json()["device_id"] == dev1

    # 2. Reconcile topology edge
    edge_resp = client.post(
        "/api/v1/evidence/topology-edges",
        json={
            "source_device_id": dev1,
            "destination_device_id": dev2,
            "relationship_type": "trunk",
            "source_interface": "Gi1/0/1",
            "destination_interface": "Gi0/0",
            "vlan_id": 10,
            "evidence_source": "lldp",
            "confidence": 0.92,
        },
        headers=headers,
    )
    assert edge_resp.status_code == 201
    edge = edge_resp.json()
    assert edge["relationship_type"] == "trunk"
    assert edge["status"] == "active"

    # 3. Query topology edges
    edges_resp = client.get("/api/v1/evidence/topology-edges?status=active", headers=headers)
    assert edges_resp.status_code == 200
    assert any(e["id"] == edge["id"] for e in edges_resp.json())


def test_reconcile_stale_records(client):
    headers = _admin_headers()
    resp = client.post("/api/v1/evidence/reconcile-stale?device_ttl_hours=72&edge_ttl_hours=48", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "retired_devices" in data
    assert "stale_edges" in data
