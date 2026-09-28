"""
LLDP (IEEE 802.1AB) and Cisco CDP Neighbor Collector Service.

Parses Layer 2 neighbor discovery protocols from:
  1. SNMP lldpRemTable / cdpCacheTable queries.
  2. Raw captured Ethernet frames (LLDP EtherType 0x88CC, CDP LLC SNAP 0x2000).

Generates TopologyEdge records in EvidenceService connecting adjacent network nodes,
including local interface, remote interface, link speed, and discovery protocol.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovery_evidence import TopologyEdge
from app.schemas.discovery_evidence import DiscoveryObservationCreate, TopologyEdgeCreate
from app.services.evidence_service import EvidenceService

logger = logging.getLogger(__name__)


@dataclass
class LLDPCDPNeighbor:
    protocol: str  # "lldp" or "cdp"
    local_device_ip: str
    local_interface: str
    remote_chassis_id: str
    remote_port_id: str
    remote_system_name: str
    remote_mgmt_ip: Optional[str] = None
    remote_capabilities: List[str] = field(default_factory=list)
    ttl_seconds: int = 120
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class LLDPCDPCollectorService:
    """Parses LLDP and CDP neighbor records and establishes physical topology edges."""

    @staticmethod
    def normalize_mac(mac: str) -> str:
        clean = "".join(c for c in mac if c in "0123456789abcdefABCDEF").lower()
        if len(clean) != 12:
            return mac.lower().replace("-", ":")
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))

    def parse_snmp_lldp_rem_table(
        self,
        local_device_ip: str,
        raw_table: List[Dict[str, Any]],
    ) -> List[LLDPCDPNeighbor]:
        """
        Parses entries from SNMP lldpRemTable (1.0.8802.1.1.2.1.4.1).
        """
        neighbors: List[LLDPCDPNeighbor] = []
        for entry in raw_table:
            chassis_id = str(entry.get("lldpRemChassisId", ""))
            if ":" in chassis_id or "-" in chassis_id or len(chassis_id) == 12:
                chassis_id = self.normalize_mac(chassis_id)

            neighbors.append(
                LLDPCDPNeighbor(
                    protocol="lldp",
                    local_device_ip=local_device_ip,
                    local_interface=entry.get("local_interface", "eth0"),
                    remote_chassis_id=chassis_id,
                    remote_port_id=str(entry.get("lldpRemPortId", "port1")),
                    remote_system_name=str(entry.get("lldpRemSysName", "unknown-neighbor")),
                    remote_mgmt_ip=entry.get("lldpRemManAddr"),
                    remote_capabilities=entry.get("capabilities", ["bridge", "router"]),
                    ttl_seconds=int(entry.get("lldpRemTTL", 120)),
                )
            )
        return neighbors

    def parse_snmp_cdp_cache_table(
        self,
        local_device_ip: str,
        raw_table: List[Dict[str, Any]],
    ) -> List[LLDPCDPNeighbor]:
        """
        Parses entries from SNMP cdpCacheTable (1.3.6.1.4.1.9.9.23.1.2.1.1).
        """
        neighbors: List[LLDPCDPNeighbor] = []
        for entry in raw_table:
            device_id = str(entry.get("cdpCacheDeviceId", ""))
            neighbors.append(
                LLDPCDPNeighbor(
                    protocol="cdp",
                    local_device_ip=local_device_ip,
                    local_interface=entry.get("local_interface", "GigabitEthernet0/1"),
                    remote_chassis_id=device_id,
                    remote_port_id=str(entry.get("cdpCacheDevicePort", "GigabitEthernet0/1")),
                    remote_system_name=device_id,
                    remote_mgmt_ip=entry.get("cdpCacheAddress"),
                    remote_capabilities=entry.get("capabilities", ["switch"]),
                    ttl_seconds=180,
                )
            )
        return neighbors

    def parse_raw_lldp_frame(self, frame_bytes: bytes, local_ip: str, local_iface: str) -> Optional[LLDPCDPNeighbor]:
        """
        Extracts TLVs from raw IEEE 802.1AB frame payload (skipping 14-byte Ethernet header).
        """
        try:
            offset = 14 if len(frame_bytes) > 14 and frame_bytes[12:14] == b"\x88\xcc" else 0
            chassis_id = ""
            port_id = ""
            sys_name = ""
            mgmt_ip = None
            ttl = 120

            while offset < len(frame_bytes) - 1:
                tlv_header = struct.unpack("!H", frame_bytes[offset : offset + 2])[0]
                tlv_type = tlv_header >> 9
                tlv_len = tlv_header & 0x01FF
                offset += 2

                if tlv_type == 0:  # End of LLDPDU
                    break

                val = frame_bytes[offset : offset + tlv_len]
                offset += tlv_len

                if tlv_type == 1:  # Chassis ID
                    subtype = val[0]
                    if subtype == 4 and len(val) >= 7:  # MAC address
                        chassis_id = ":".join(f"{b:02x}" for b in val[1:7])
                    else:
                        chassis_id = val[1:].decode("utf-8", errors="replace")
                elif tlv_type == 2:  # Port ID
                    port_id = val[1:].decode("utf-8", errors="replace")
                elif tlv_type == 3:  # Time To Live
                    ttl = struct.unpack("!H", val)[0]
                elif tlv_type == 5:  # System Name
                    sys_name = val.decode("utf-8", errors="replace")
                elif tlv_type == 8:  # Management Address
                    if len(val) >= 6:
                        mgmt_ip = ".".join(str(b) for b in val[2:6])

            if chassis_id and port_id:
                return LLDPCDPNeighbor(
                    protocol="lldp",
                    local_device_ip=local_ip,
                    local_interface=local_iface,
                    remote_chassis_id=chassis_id,
                    remote_port_id=port_id,
                    remote_system_name=sys_name or chassis_id,
                    remote_mgmt_ip=mgmt_ip,
                    ttl_seconds=ttl,
                )
        except Exception as exc:
            logger.warning("Failed parsing raw LLDP frame: %s", exc)
        return None

    async def ingest_neighbors(
        self,
        db: AsyncSession,
        neighbors: List[LLDPCDPNeighbor],
        collector_id: str = "lldp_collector_01",
    ) -> List[TopologyEdge]:
        """
        Ingests neighbor records:
          1. Records DiscoveryObservation for each neighbor.
          2. Resolves local and remote DeviceIdentity records.
          3. Upserts TopologyEdge linking the two devices with edge_type="physical_link".
        """
        created_edges: List[TopologyEdge] = []

        for n in neighbors:
            # 1. Emit observation for remote neighbor
            obs = DiscoveryObservationCreate(
                source=n.protocol,
                collector=collector_id,
                confidence=0.96,
                normalized_fields={
                    "mac": n.remote_chassis_id if ":" in n.remote_chassis_id else None,
                    "ip": n.remote_mgmt_ip,
                    "hostname": n.remote_system_name,
                    "role": "switch" if "bridge" in n.remote_capabilities else "router",
                    "protocol": n.protocol,
                    "local_device_ip": n.local_device_ip,
                    "local_interface": n.local_interface,
                    "remote_chassis_id": n.remote_chassis_id,
                    "remote_port_id": n.remote_port_id,
                    "remote_system_name": n.remote_system_name,
                    "capabilities": n.remote_capabilities,
                    "ttl_seconds": n.ttl_seconds,
                },
            )
            saved_obs = await EvidenceService.record_observation(db, obs)
            remote_dev_id = saved_obs.device_id

            # 2. Find or record local device observation to ensure local DeviceIdentity exists
            local_obs = DiscoveryObservationCreate(
                source="local_agent",
                collector=collector_id,
                confidence=0.99,
                normalized_fields={
                    "ip": n.local_device_ip,
                    "role": "switch",
                    "zone": "management",
                },
            )
            saved_local = await EvidenceService.record_observation(db, local_obs)
            local_dev_id = saved_local.device_id

            # 3. Create or update TopologyEdge
            edge_create = TopologyEdgeCreate(
                source_device_id=local_dev_id,
                destination_device_id=remote_dev_id,
                relationship_type="switched",
                source_interface=n.local_interface,
                destination_interface=n.remote_port_id,
                evidence_source=n.protocol,
                confidence=0.96,
            )
            edge = await EvidenceService.reconcile_topology_edge(db, edge_create)
            created_edges.append(edge)

        return created_edges
