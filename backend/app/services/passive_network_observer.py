"""
Passive Local Network Discovery & Observer (Mode A — Observe Only)
Safely inspects local ARP kernel tables, route tables, and performs non-intrusive
DNS reverse lookups for local endpoints on the active network interface.

GUARANTEES:
1. Zero active probing, zero remote access, zero credential guessing.
2. Only extracts locally available OS kernel neighbor states.
3. Automatically enqueues discovered endpoints into the Operator Verification Queue (Mode B).
"""
from __future__ import annotations

import logging
import os
import re
import socket
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovery_evidence import DeviceLifecycleStatus
from app.schemas.discovery_evidence import DiscoveryObservationCreate
from app.services.confidence_fusion import ConfidenceFusionEngine, DiscoveredSignal, lookup_oui, normalize_mac
from app.services.evidence_service import EvidenceService

logger = logging.getLogger(__name__)


@dataclass
class LocalNeighbor:
    ip: str
    mac: str
    interface: str
    flags: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    is_gateway: bool = False


class PassiveNetworkObserver:
    """Safely extracts network neighbors from local kernel state without network access."""

    @classmethod
    def read_arp_table(cls) -> List[LocalNeighbor]:
        neighbors: List[LocalNeighbor] = []
        arp_path = "/proc/net/arp"
        if not os.path.exists(arp_path):
            logger.warning("/proc/net/arp not found; cannot read local ARP table")
            return neighbors

        try:
            with open(arp_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            gateway_ip = cls.get_default_gateway_ip()

            # Skip header: IP address, HW type, Flags, HW address, Mask, Device
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0].strip()
                    flags = parts[2].strip()
                    mac = parts[3].strip()
                    iface = parts[5].strip()

                    # Filter out zeroed or invalid MACs (00:00:00:00:00:00 or incomplete 0x0)
                    if mac == "00:00:00:00:00:00" or flags == "0x0":
                        continue

                    mac_norm = normalize_mac(mac)
                    if not mac_norm:
                        continue

                    # Safe non-intrusive reverse DNS lookup with 0.5s timeout
                    hostname = cls._safe_reverse_lookup(ip)
                    vendor = lookup_oui(mac_norm)
                    is_gw = (ip == gateway_ip)

                    neighbors.append(LocalNeighbor(
                        ip=ip,
                        mac=mac_norm,
                        interface=iface,
                        flags=flags,
                        hostname=hostname,
                        vendor=vendor,
                        is_gateway=is_gw,
                    ))
        except Exception as exc:
            logger.error("Error reading ARP table: %s", exc)

        return neighbors

    @staticmethod
    def get_default_gateway_ip() -> Optional[str]:
        route_path = "/proc/net/route"
        if not os.path.exists(route_path):
            return None
        try:
            with open(route_path, "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == "00000000":  # Destination default
                        gw_hex = fields[2]
                        # Little-endian hex to dotted decimal
                        octets = [str(int(gw_hex[i:i+2], 16)) for i in (6, 4, 2, 0)]
                        return ".".join(octets)
        except Exception:
            pass
        return None

    @staticmethod
    def _safe_reverse_lookup(ip: str) -> Optional[str]:
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.5)
            try:
                name, _, _ = socket.gethostbyaddr(ip)
                return name.strip().lower()
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.herror, socket.gaierror, socket.timeout, Exception):
            return None

    @classmethod
    async def ingest_passive_neighbors(cls, db: AsyncSession) -> List[Dict[str, Any]]:
        """
        Reads local neighbors and creates append-only DiscoveryObservations and
        provisional DeviceIdentities via EvidenceService with multi-source fusion.
        """
        neighbors = cls.read_arp_table()
        results: List[Dict[str, Any]] = []

        for n in neighbors:
            role = "router" if n.is_gateway else "unknown"
            signals = [
                DiscoveredSignal(
                    source="arp",
                    confidence=0.65,
                    ip=n.ip,
                    mac=n.mac,
                    hostname=n.hostname,
                    vendor=n.vendor,
                    role=role,
                )
            ]
            if n.hostname:
                signals.append(
                    DiscoveredSignal(
                        source="reverse_dns",
                        confidence=0.75,
                        ip=n.ip,
                        hostname=n.hostname,
                    )
                )

            fusion = ConfidenceFusionEngine.fuse_signals(signals)

            obs = DiscoveryObservationCreate(
                source="arp",
                collector="passive_network_observer",
                raw_evidence_ref=f"kernel_arp_{n.interface}_{n.ip}",
                normalized_fields={
                    "ip": n.ip,
                    "mac": n.mac,
                    "hostname": fusion.canonical_hostname,
                    "vendor": fusion.canonical_vendor,
                    "role": fusion.canonical_role,
                    "interface": n.interface,
                    "is_gateway": n.is_gateway,
                    "is_discrepant": fusion.is_discrepant,
                },
                confidence=fusion.fused_confidence,
                operator_id="system_passive_observer",
            )

            observation = await EvidenceService.record_observation(db, obs)
            results.append({
                "ip": n.ip,
                "mac": n.mac,
                "hostname": fusion.canonical_hostname,
                "vendor": fusion.canonical_vendor,
                "role": fusion.canonical_role,
                "confidence": fusion.fused_confidence,
                "recommended_action": fusion.recommended_action,
                "observation_id": str(observation.id),
                "device_id": str(observation.device_id) if observation.device_id else None,
            })

        await db.commit()
        return results
