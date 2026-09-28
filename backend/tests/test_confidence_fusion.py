"""
Unit tests for Confidence Fusion & Passive Observer (Phase 3).
"""
import pytest

from app.services.confidence_fusion import (
    ConfidenceFusionEngine,
    DiscoveredSignal,
    lookup_oui,
    normalize_mac,
)
from app.services.passive_network_observer import PassiveNetworkObserver


def test_mac_normalization_and_oui():
    assert normalize_mac("000c29abcdef") == "00:0c:29:ab:cd:ef"
    assert normalize_mac("00-0C-29-AB-CD-EF") == "00:0c:29:ab:cd:ef"
    assert normalize_mac("001c.7312.3456") == "00:1c:73:12:34:56"
    assert normalize_mac("invalid") is None

    assert lookup_oui("00:0c:29:11:22:33") == "vmware"
    assert lookup_oui("00:1c:73:44:55:66") == "arista"
    assert lookup_oui("6c:03:b5:94:a0:72") == "ubiquiti"
    assert lookup_oui("28:c2:dd:8e:ef:87") == "intel"
    assert lookup_oui("ff:ff:ff:ff:ff:ff") is None


def test_bayesian_confidence_fusion_accumulation():
    # Single source (ARP)
    sig_arp = DiscoveredSignal(source="arp", confidence=0.65, ip="192.168.1.50")
    res1 = ConfidenceFusionEngine.fuse_signals([sig_arp])
    assert 0.60 <= res1.fused_confidence <= 0.70
    assert not res1.is_discrepant

    # Two corroborating sources (ARP + DHCP)
    sig_dhcp = DiscoveredSignal(source="dhcp", confidence=0.85, ip="192.168.1.50", hostname="workstation-01")
    res2 = ConfidenceFusionEngine.fuse_signals([sig_arp, sig_dhcp])
    # 1 - (1 - 0.65) * (1 - 0.85) = 1 - 0.35 * 0.15 = 1 - 0.0525 = 0.9475
    assert res2.fused_confidence >= 0.90
    assert res2.canonical_hostname == "workstation-01"

    # Three independent sources (ARP + DHCP + LLDP)
    sig_lldp = DiscoveredSignal(source="lldp", confidence=0.92, ip="192.168.1.50", vendor="cisco", role="switch")
    res3 = ConfidenceFusionEngine.fuse_signals([sig_arp, sig_dhcp, sig_lldp])
    assert res3.fused_confidence >= 0.95
    assert res3.recommended_action == "auto_promote"


def test_discrepancy_detection_oui_vs_protocol():
    # MAC OUI says Cisco, but protocol says Raspberry Pi
    sig_arp = DiscoveredSignal(source="arp", confidence=0.65, ip="10.0.0.5", mac="00:01:42:aa:bb:cc")
    sig_dhcp = DiscoveredSignal(source="dhcp", confidence=0.85, ip="10.0.0.5", vendor="raspberry_pi")

    fusion = ConfidenceFusionEngine.fuse_signals([sig_arp, sig_dhcp])
    assert fusion.is_discrepant is True
    assert len(fusion.discrepancy_reasons) > 0
    assert "contradicts" in fusion.discrepancy_reasons[0].lower()
    # Confidence must be penalized for safety
    assert fusion.fused_confidence < 0.50
    assert fusion.recommended_action == "flagged_discrepancy"


def test_discrepancy_detection_role_conflict():
    sig1 = DiscoveredSignal(source="snmp", confidence=0.90, role="switch")
    sig2 = DiscoveredSignal(source="mdns", confidence=0.70, role="workstation")

    fusion = ConfidenceFusionEngine.fuse_signals([sig1, sig2])
    assert fusion.is_discrepant is True
    assert any("switch vs workstation" in r for r in fusion.discrepancy_reasons)


def test_passive_network_observer_arp_parsing(monkeypatch):
    from unittest.mock import mock_open

    mock_arp = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         6c:03:b5:94:a0:72     *        wlan0
192.168.1.50     0x1         0x2         28:c2:dd:8e:ef:87     *        wlan0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
"""
    m = mock_open(read_data=mock_arp)
    monkeypatch.setattr("os.path.exists", lambda path: True if path == "/proc/net/arp" else False)
    monkeypatch.setattr("builtins.open", m)

    neighbors = PassiveNetworkObserver.read_arp_table()
    assert len(neighbors) == 2
    assert neighbors[0].ip == "192.168.1.1"
    assert neighbors[0].mac == "6c:03:b5:94:a0:72"
    assert neighbors[0].vendor == "ubiquiti"
    assert neighbors[1].ip == "192.168.1.50"
    assert neighbors[1].vendor == "intel"

