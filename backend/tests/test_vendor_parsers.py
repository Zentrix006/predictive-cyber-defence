"""
Unit tests for Multi-Vendor CLI Parsers (Phase 3).
Verifies parsing of show version, show cdp/lldp neighbors, show vlan, and show ip route
across Cisco IOS-XE, Juniper Junos, and Arista EOS fixtures.
"""
import pytest

from app.services.vendor_parsers import CiscoIosXeParser, JuniperJunosParser, AristaEosParser


CISCO_SHOW_VERSION_FIXTURE = """
Cisco IOS XE Software, Version 17.03.04a
Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.3.4a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2021 by Cisco Systems, Inc.

cisco C9300-48UXM (X86) processor (revision V02) with 1869818K/6147K bytes of memory.
Processor board ID FOC24180A1B
Model Number                    : C9300-48UXM
core-switch-01 uptime is 14 weeks, 2 days, 3 hours, 12 minutes
Uptime for this control processor is 14 weeks, 2 days, 3 hours, 14 minutes
"""

CISCO_SHOW_CDP_NEIGHBORS_FIXTURE = """
-------------------------
Device ID: dist-sw02.corp.net
Entry address(es): 
  IP address: 10.0.1.2
Platform: cisco WS-C3850-24P,  Capabilities: Router Switch IGMP 
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): TenGigabitEthernet1/1/1
Holdtime : 142 sec

-------------------------
Device ID: ap-floor2.corp.net
Entry address(es): 
  IP address: 10.0.10.45
Platform: cisco AIR-AP3802I-B-K9,  Capabilities: Trans-Bridge 
Interface: GigabitEthernet1/0/12,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 160 sec
"""

CISCO_SHOW_VLAN_FIXTURE = """
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/24, Gi1/0/25
10   CORP-DATA                        active    Gi1/0/1, Gi1/0/2, Gi1/0/3
20   VOICE                            active    Gi1/0/4, Gi1/0/5
99   MANAGEMENT                       active    Gi1/0/48
"""

CISCO_SHOW_ROUTE_FIXTURE = """
Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.0.0.1, GigabitEthernet0/0
C        10.0.0.0/24 is directly connected, GigabitEthernet0/0
L        10.0.0.254/32 is directly connected, GigabitEthernet0/0
O        192.168.10.0/24 [110/2] via 10.0.0.2, 00:14:22, GigabitEthernet0/1
"""

JUNIPER_SHOW_VERSION_FIXTURE = """
Hostname: edge-srx01.corp.internal
Model: srx340
Junos: 21.4R3-S5.4
JUNOS Software Release [21.4R3-S5.4]
"""

JUNIPER_SHOW_LLDP_FIXTURE = """
Local Interface    Parent Interface    Chassis Id          Port info          System Name
ge-0/0/0.0         -                   00:1c:73:01:02:03   xe-0/0/1           core-spine-01
ge-0/0/1.0         -                   00:0c:29:ab:cd:ef   eth0               backup-storage
"""

JUNIPER_SHOW_VLANS_FIXTURE = """
Name           Tag     Interfaces
default        1       ge-0/0/0.0*, ge-0/0/1.0
corp-vlan      100     ge-0/0/2.0*, ge-0/0/3.0*
dmz-vlan       200     ge-0/0/4.0*
"""

JUNIPER_SHOW_ROUTE_FIXTURE = """
inet.0: 4 destinations, 4 routes (4 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[Static/5] 03:12:44
                    > to 172.16.1.1 via ge-0/0/0.0
172.16.1.0/24      *[Direct/0] 03:12:44
                    > via ge-0/0/0.0
"""

ARISTA_SHOW_VERSION_FIXTURE = """
Arista DCS-7050SX3-48YC8-R
Hardware version: 11.01
Serial number: JPE18420199
System MAC address: 001c.7312.3456
Software image version: 4.28.2F
Architecture: i686
Uptime: 45 weeks, 1 days, 6 hours and 22 minutes
"""

ARISTA_SHOW_LLDP_FIXTURE = """
Port       Neighbor Device ID             Neighbor Port ID           TTL
Et1        leaf-02.corp.net               Ethernet1                  120
Et2        firewall-ha01                  mgmt0                      120
"""

ARISTA_SHOW_VLAN_FIXTURE = """
VLAN  Name                             Status    Ports
----- -------------------------------- --------- -------------------------------
1     default                          active    Et1, Et2
100   APP-TIER                         active    Et3, Et4, Et5
200   DB-TIER                          active    Et6, Et7
"""


def test_cisco_show_version_parser():
    facts = CiscoIosXeParser.parse_show_version(CISCO_SHOW_VERSION_FIXTURE)
    assert facts.vendor == "cisco"
    assert facts.model == "C9300-48UXM"
    assert facts.os_version == "17.03.04a"
    assert facts.serial_number == "FOC24180A1B"
    assert facts.hostname == "core-switch-01"


def test_cisco_show_cdp_neighbors_parser():
    neighbors = CiscoIosXeParser.parse_show_cdp_neighbors(CISCO_SHOW_CDP_NEIGHBORS_FIXTURE)
    assert len(neighbors) == 2
    assert neighbors[0].neighbor_device_id == "dist-sw02.corp.net"
    assert neighbors[0].neighbor_ip == "10.0.1.2"
    assert neighbors[0].local_interface == "GigabitEthernet1/0/1"
    assert "Switch" in neighbors[0].capabilities
    assert neighbors[1].neighbor_device_id == "ap-floor2.corp.net"


def test_cisco_show_vlan_parser():
    vlans = CiscoIosXeParser.parse_show_vlan(CISCO_SHOW_VLAN_FIXTURE)
    assert len(vlans) == 4
    assert vlans[1].vlan_id == 10
    assert vlans[1].name == "CORP-DATA"
    assert len(vlans[1].ports) == 3


def test_cisco_show_ip_route_parser():
    routes = CiscoIosXeParser.parse_show_ip_route(CISCO_SHOW_ROUTE_FIXTURE)
    assert len(routes) == 4
    assert routes[0].prefix == "0.0.0.0/0"
    assert routes[0].next_hop == "10.0.0.1"
    assert routes[0].protocol == "static"
    assert routes[1].prefix == "10.0.0.0/24"
    assert routes[1].protocol == "direct"
    assert routes[2].prefix == "10.0.0.254/32"
    assert routes[2].protocol == "direct"
    assert routes[3].protocol == "ospf"


def test_juniper_parsers():
    facts = JuniperJunosParser.parse_show_version(JUNIPER_SHOW_VERSION_FIXTURE)
    assert facts.vendor == "juniper"
    assert facts.model == "srx340"
    assert facts.os_version == "21.4R3-S5.4"
    assert facts.hostname == "edge-srx01.corp.internal"

    neighbors = JuniperJunosParser.parse_show_lldp_neighbors(JUNIPER_SHOW_LLDP_FIXTURE)
    assert len(neighbors) == 2
    assert neighbors[0].neighbor_device_id == "core-spine-01"
    assert neighbors[0].local_interface == "ge-0/0/0.0"

    vlans = JuniperJunosParser.parse_show_vlans(JUNIPER_SHOW_VLANS_FIXTURE)
    assert len(vlans) == 3
    assert vlans[1].vlan_id == 100
    assert vlans[1].name == "corp-vlan"

    routes = JuniperJunosParser.parse_show_route(JUNIPER_SHOW_ROUTE_FIXTURE)
    assert len(routes) == 2
    assert routes[0].prefix == "0.0.0.0/0"
    assert routes[0].next_hop == "172.16.1.1"


def test_arista_parsers():
    facts = AristaEosParser.parse_show_version(ARISTA_SHOW_VERSION_FIXTURE)
    assert facts.vendor == "arista"
    assert facts.model == "DCS-7050SX3-48YC8-R"
    assert facts.serial_number == "JPE18420199"
    assert facts.mac_address == "001c.7312.3456"
    assert facts.os_version == "4.28.2F"

    neighbors = AristaEosParser.parse_show_lldp_neighbors(ARISTA_SHOW_LLDP_FIXTURE)
    assert len(neighbors) == 2
    assert neighbors[0].neighbor_device_id == "leaf-02.corp.net"
    assert neighbors[0].local_interface == "Et1"

    vlans = AristaEosParser.parse_show_vlan(ARISTA_SHOW_VLAN_FIXTURE)
    assert len(vlans) == 3
    assert vlans[1].vlan_id == 100
    assert "Et3" in vlans[1].ports
