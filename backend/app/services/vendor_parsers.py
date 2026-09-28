"""
Multi-Vendor Read-Only Configuration & Telemetry Parsers (Phase 3)
Extracts operational facts, topology neighbors (CDP/LLDP), VLANs, and routing tables
from Cisco (IOS-XE/NX-OS), Juniper (Junos), and Arista (EOS) outputs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class VendorFacts:
    vendor: str
    model: Optional[str] = None
    os_version: Optional[str] = None
    serial_number: Optional[str] = None
    hostname: Optional[str] = None
    uptime: Optional[str] = None
    mac_address: Optional[str] = None
    raw_facts: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedNeighbor:
    local_interface: str
    neighbor_device_id: str
    neighbor_port_id: str
    protocol: str  # 'cdp' | 'lldp'
    capabilities: List[str] = field(default_factory=list)
    neighbor_ip: Optional[str] = None
    neighbor_platform: Optional[str] = None


@dataclass
class ParsedVlan:
    vlan_id: int
    name: str
    status: str = "active"
    ports: List[str] = field(default_factory=list)


@dataclass
class ParsedRoute:
    prefix: str
    next_hop: Optional[str]
    protocol: str  # 'direct', 'static', 'ospf', 'bgp', etc.
    outgoing_interface: Optional[str] = None
    metric: Optional[int] = None


class CiscoIosXeParser:
    """Parses standard Cisco IOS-XE and NX-OS CLI output."""

    @staticmethod
    def parse_show_version(text: str) -> VendorFacts:
        facts = VendorFacts(vendor="cisco")
        
        # Hostname from prompt or uptime line
        host_m = re.search(r"^(\S+)\s+uptime is", text, re.MULTILINE)
        if host_m:
            facts.hostname = host_m.group(1).strip()
            
        # Software version
        ver_m = re.search(r"Cisco IOS Software,.*?\s+Version\s+([^\s,]+)", text, re.IGNORECASE)
        if not ver_m:
            ver_m = re.search(r"Cisco IOS XE Software, Version\s+([^\s,]+)", text, re.IGNORECASE)
        if not ver_m:
            ver_m = re.search(r"NX-OS.*?version\s+([^\s,]+)", text, re.IGNORECASE)
        if ver_m:
            facts.os_version = ver_m.group(1).strip()

        # Model / Platform
        model_m = re.search(r"[Cc]isco\s+([A-Za-z0-9\-]+)\s+\([^\)]+\)\s+processor", text)
        if not model_m:
            model_m = re.search(r"Model Number\s*:\s*([A-Za-z0-9\-]+)", text, re.IGNORECASE)
        if not model_m:
            model_m = re.search(r"cisco\s+(Catalyst\s+[A-Za-z0-9\-]+)", text, re.IGNORECASE)
        if model_m:
            facts.model = model_m.group(1).strip()

        # Serial number
        sn_m = re.search(r"Processor board ID\s+([A-Za-z0-9]+)", text, re.IGNORECASE)
        if not sn_m:
            sn_m = re.search(r"System serial number\s*:\s*([A-Za-z0-9]+)", text, re.IGNORECASE)
        if sn_m:
            facts.serial_number = sn_m.group(1).strip()

        # Uptime
        up_m = re.search(r"uptime is\s+(.+)$", text, re.MULTILINE)
        if up_m:
            facts.uptime = up_m.group(1).strip()

        return facts

    @staticmethod
    def parse_show_cdp_neighbors(text: str) -> List[ParsedNeighbor]:
        neighbors: List[ParsedNeighbor] = []
        # Support detail format: "Device ID: host.domain ... Entry address(es): IP ... Platform: ... Interface: ..."
        entries = re.split(r"-{10,}|Device ID:\s*", text)
        for entry in entries:
            if not entry.strip():
                continue
            
            dev_id_m = re.search(r"^(?:Device ID:\s*)?([^\r\n,]+)", entry.strip())
            dev_id = dev_id_m.group(1).strip() if dev_id_m else ""
            if not dev_id or dev_id.lower().startswith("cisco") and "neighbors" in dev_id.lower():
                continue

            ip_m = re.search(r"(?:IP address|IPv4 Address):\s*([0-9\.]+)", entry)
            ip = ip_m.group(1).strip() if ip_m else None

            plat_m = re.search(r"Platform:\s*([^,\n]+)", entry)
            plat = plat_m.group(1).strip() if plat_m else None

            cap_m = re.search(r"Capabilities:\s*([^\n]+)", entry)
            caps = [c.strip() for c in cap_m.group(1).split()] if cap_m else []

            intf_m = re.search(r"Interface:\s*([^,\n]+),\s*Port ID \(outgoing port\):\s*([^\n]+)", entry)
            if intf_m:
                local_intf = intf_m.group(1).strip()
                remote_port = intf_m.group(2).strip()
                neighbors.append(ParsedNeighbor(
                    local_interface=local_intf,
                    neighbor_device_id=dev_id,
                    neighbor_port_id=remote_port,
                    protocol="cdp",
                    capabilities=caps,
                    neighbor_ip=ip,
                    neighbor_platform=plat,
                ))
            else:
                # Also handle table format: Device ID | Local Intrfce | Holdtme | Capability | Platform | Port ID
                lines = entry.splitlines()
                for line in lines:
                    match = re.match(r"^(\S+)\s+(\S+\s+\S+|\S+)\s+\d+\s+([RSTBCIsP\s]+)\s+(\S+)\s+(\S+)$", line.strip())
                    if match:
                        neighbors.append(ParsedNeighbor(
                            local_interface=match.group(2).strip(),
                            neighbor_device_id=match.group(1).strip(),
                            neighbor_port_id=match.group(5).strip(),
                            protocol="cdp",
                            capabilities=[c for c in match.group(3).split() if c],
                            neighbor_platform=match.group(4).strip(),
                        ))

        return neighbors

    @staticmethod
    def parse_show_vlan(text: str) -> List[ParsedVlan]:
        vlans: List[ParsedVlan] = []
        for line in text.splitlines():
            line_str = line.strip()
            # Match: "10   CORP-DATA   active   Gi0/1, Gi0/2, Gi0/3"
            m = re.match(r"^(\d+)\s+([A-Za-z0-9_\-]+)\s+(active|act/unsup|suspend)\s*(.*)$", line_str)
            if m:
                vlan_id = int(m.group(1))
                name = m.group(2).strip()
                status = m.group(3).strip()
                ports_raw = m.group(4).strip()
                ports = [p.strip() for p in re.split(r",\s*", ports_raw) if p.strip()]
                vlans.append(ParsedVlan(vlan_id=vlan_id, name=name, status=status, ports=ports))
        return vlans

    @staticmethod
    def parse_show_ip_route(text: str) -> List[ParsedRoute]:
        routes: List[ParsedRoute] = []
        for line in text.splitlines():
            # Direct: "C        192.168.1.0/24 is directly connected, GigabitEthernet0/0"
            m_direct = re.search(r"^[C|L]\s+([0-9\.]+/\d+)\s+is directly connected,\s*(\S+)", line.strip())
            if m_direct:
                routes.append(ParsedRoute(
                    prefix=m_direct.group(1),
                    next_hop=None,
                    protocol="direct",
                    outgoing_interface=m_direct.group(2),
                ))
                continue

            # Static / OSPF / BGP: "S*    0.0.0.0/0 [1/0] via 10.0.0.1" or "O        10.1.0.0/24 [110/2] via 10.0.0.2, 00:12:34, Gi0/1"
            m_route = re.search(r"^([S|O|B|D|i|R]\*?)\s+([0-9\.]+/\d+)\s+\[(\d+)/(\d+)\]\s+via\s+([0-9\.]+)(?:,\s*[^,]+,\s*(\S+))?", line.strip())
            if m_route:
                proto_code = m_route.group(1).replace("*", "")
                proto_map = {"S": "static", "O": "ospf", "B": "bgp", "D": "eigrp", "R": "rip"}
                proto = proto_map.get(proto_code, "other")
                routes.append(ParsedRoute(
                    prefix=m_route.group(2),
                    next_hop=m_route.group(5),
                    protocol=proto,
                    metric=int(m_route.group(4)),
                    outgoing_interface=m_route.group(6),
                ))
        return routes


class JuniperJunosParser:
    """Parses standard Juniper Junos CLI output."""

    @staticmethod
    def parse_show_version(text: str) -> VendorFacts:
        facts = VendorFacts(vendor="juniper")

        # Hostname
        h_m = re.search(r"Hostname:\s*([^\n\r]+)", text, re.IGNORECASE)
        if h_m:
            facts.hostname = h_m.group(1).strip()

        # Model: "Model: srx340" or "Model: ex4300-48t"
        m_m = re.search(r"Model:\s*([^\n\r]+)", text, re.IGNORECASE)
        if m_m:
            facts.model = m_m.group(1).strip()

        # Junos OS: "Junos: 21.4R3-S5.4" or "JUNOS Software Release [20.2R3.9]"
        v_m = re.search(r"Junos:\s*([^\n\r]+)", text, re.IGNORECASE)
        if not v_m:
            v_m = re.search(r"JUNOS Software Release\s*\[([^\]]+)\]", text, re.IGNORECASE)
        if v_m:
            facts.os_version = v_m.group(1).strip()

        return facts

    @staticmethod
    def parse_show_lldp_neighbors(text: str) -> List[ParsedNeighbor]:
        neighbors: List[ParsedNeighbor] = []
        # Format:
        # Local Interface    Parent Interface    Chassis Id          Port info          System Name
        # ge-0/0/0.0         -                   00:1c:73:01:02:03   xe-0/0/1           core-sw01
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Local Interface") or line_str.startswith("---"):
                continue
            parts = line_str.split()
            if len(parts) >= 5:
                neighbors.append(ParsedNeighbor(
                    local_interface=parts[0],
                    neighbor_device_id=parts[4],
                    neighbor_port_id=parts[3],
                    protocol="lldp",
                    neighbor_platform="juniper",
                ))
        return neighbors

    @staticmethod
    def parse_show_vlans(text: str) -> List[ParsedVlan]:
        vlans: List[ParsedVlan] = []
        # Format:
        # Name           Tag     Interfaces
        # default        1       ge-0/0/0.0*, ge-0/0/1.0
        # vlan-corp      100     ge-0/0/2.0*, ge-0/0/3.0*
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Name") or line_str.startswith("---") or line_str.startswith("Total"):
                continue
            parts = line_str.split(None, 2)
            if len(parts) >= 2 and parts[1].isdigit():
                name = parts[0]
                tag = int(parts[1])
                ports = [p.replace("*", "").strip() for p in parts[2].split(",") if p.strip()] if len(parts) > 2 else []
                vlans.append(ParsedVlan(vlan_id=tag, name=name, ports=ports))
        return vlans

    @staticmethod
    def parse_show_route(text: str) -> List[ParsedRoute]:
        routes: List[ParsedRoute] = []
        # Format:
        # 192.168.1.0/24     *[Direct/0] 01:23:45
        #                    > via ge-0/0/0.0
        # 0.0.0.0/0          *[Static/5] 02:10:00
        #                    > to 10.0.0.1 via ge-0/0/1.0
        current_prefix = None
        current_proto = "direct"
        
        for line in text.splitlines():
            line_str = line.strip()
            prefix_m = re.match(r"^([0-9\.]+/\d+)\s+\*?\[([A-Za-z0-9\-]+)/(\d+)\]", line_str)
            if prefix_m:
                current_prefix = prefix_m.group(1)
                current_proto = prefix_m.group(2).lower()
                continue
                
            if current_prefix:
                via_m = re.match(r"^>\s+(?:to\s+([0-9\.]+)\s+)?via\s+(\S+)", line_str)
                if via_m:
                    next_hop = via_m.group(1)
                    out_if = via_m.group(2)
                    routes.append(ParsedRoute(
                        prefix=current_prefix,
                        next_hop=next_hop,
                        protocol=current_proto,
                        outgoing_interface=out_if,
                    ))
                    current_prefix = None
        return routes


class AristaEosParser:
    """Parses standard Arista EOS CLI output."""

    @staticmethod
    def parse_show_version(text: str) -> VendorFacts:
        facts = VendorFacts(vendor="arista")

        # Model: "Arista DCS-7050SX3-48YC8-R"
        m_m = re.search(r"Arista\s+([A-Za-z0-9\-]+)", text, re.IGNORECASE)
        if m_m:
            facts.model = m_m.group(1).strip()

        # Software image version: "Software image version: 4.28.2F"
        v_m = re.search(r"Software image version:\s*([^\s\n]+)", text, re.IGNORECASE)
        if v_m:
            facts.os_version = v_m.group(1).strip()

        # Serial number: "Serial number: JPE16481234"
        s_m = re.search(r"Serial number:\s*([A-Za-z0-9]+)", text, re.IGNORECASE)
        if s_m:
            facts.serial_number = s_m.group(1).strip()

        # System MAC: "System MAC address: 001c.7312.3456"
        mac_m = re.search(r"System MAC address:\s*([0-9a-fA-F\.]+)", text, re.IGNORECASE)
        if mac_m:
            facts.mac_address = mac_m.group(1).strip()

        # Uptime
        u_m = re.search(r"Uptime:\s*([^\n\r]+)", text, re.IGNORECASE)
        if u_m:
            facts.uptime = u_m.group(1).strip()

        return facts

    @staticmethod
    def parse_show_lldp_neighbors(text: str) -> List[ParsedNeighbor]:
        neighbors: List[ParsedNeighbor] = []
        # Format:
        # Port       Neighbor Device ID             Neighbor Port ID           TTL
        # Et1        spine-01.corp.net              Ethernet1/1                120
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Port") or line_str.startswith("---") or line_str.startswith("Neighbor"):
                continue
            parts = line_str.split()
            if len(parts) >= 3:
                neighbors.append(ParsedNeighbor(
                    local_interface=parts[0],
                    neighbor_device_id=parts[1],
                    neighbor_port_id=parts[2],
                    protocol="lldp",
                    neighbor_platform="arista",
                ))
        return neighbors

    @staticmethod
    def parse_show_vlan(text: str) -> List[ParsedVlan]:
        vlans: List[ParsedVlan] = []
        for line in text.splitlines():
            line_str = line.strip()
            m = re.match(r"^(\d+)\s+([A-Za-z0-9_\-]+)\s+(active|suspended)\s*(.*)$", line_str)
            if m:
                vlan_id = int(m.group(1))
                name = m.group(2).strip()
                status = m.group(3).strip()
                ports = [p.strip() for p in re.split(r",\s*", m.group(4).strip()) if p.strip()]
                vlans.append(ParsedVlan(vlan_id=vlan_id, name=name, status=status, ports=ports))
        return vlans

    @staticmethod
    def parse_show_ip_route(text: str) -> List[ParsedRoute]:
        routes: List[ParsedRoute] = []
        # Format:
        # C        192.168.10.0/24 is directly connected, Ethernet1
        # S        0.0.0.0/0 [1/0] via 10.0.0.1, Ethernet2
        for line in text.splitlines():
            line_str = line.strip()
            m_direct = re.search(r"^C\s+([0-9\.]+/\d+)\s+is directly connected,\s*(\S+)", line_str)
            if m_direct:
                routes.append(ParsedRoute(
                    prefix=m_direct.group(1),
                    next_hop=None,
                    protocol="direct",
                    outgoing_interface=m_direct.group(2),
                ))
                continue
            m_route = re.search(r"^([S|O|B])\s+([0-9\.]+/\d+)\s+\[(\d+)/(\d+)\]\s+via\s+([0-9\.]+)(?:,\s*(\S+))?", line_str)
            if m_route:
                proto_map = {"S": "static", "O": "ospf", "B": "bgp"}
                routes.append(ParsedRoute(
                    prefix=m_route.group(2),
                    next_hop=m_route.group(5),
                    protocol=proto_map.get(m_route.group(1), "other"),
                    metric=int(m_route.group(4)),
                    outgoing_interface=m_route.group(6),
                ))
        return routes
