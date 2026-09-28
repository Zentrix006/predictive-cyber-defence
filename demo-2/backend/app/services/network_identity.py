"""Passive host-local identity enrichment for controlled demo participants."""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any, Dict
from urllib.request import urlopen

CONFIDENTIAL = {"value": "Confidential", "state": "confidential", "source": "restricted local-network telemetry"}


def _arp_mac(ip: str) -> str | None:
    try:
        for line in Path("/proc/net/arp").read_text(encoding="utf-8").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[0] == ip and fields[3] != "00:00:00:00:00:00":
                return fields[3].upper()
    except OSError:
        pass
    return None


def resolve_local_identity(ip: str | None) -> Dict[str, Dict[str, Any]]:
    """Resolve only a range participant's known IP; never probe the LAN."""
    profile: Dict[str, Dict[str, Any]] = {
        "source_ip": {"value": ip or "Confidential", "state": "observed" if ip else "confidential", "source": "Demo-2 connection telemetry" if ip else "restricted"},
        "dhcp_hostname": dict(CONFIDENTIAL),
        "mac_address": dict(CONFIDENTIAL),
        "reverse_dns": dict(CONFIDENTIAL),
    }
    if not ip:
        return profile
    mac = _arp_mac(ip)
    if mac:
        profile["mac_address"] = {"value": mac, "state": "observed", "source": "host ARP neighbour table"}
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        hostname = None
    if hostname:
        profile["reverse_dns"] = {"value": hostname, "state": "observed", "source": "local reverse DNS"}
        profile["dhcp_hostname"] = {"value": hostname, "state": "resolved", "source": "local DHCP/DNS identity resolution"}
    return profile


def resolve_network_identity(ip: str | None) -> Dict[str, Dict[str, Any]]:
    """Prefer the host-network collector; fall back to local passive data."""
    collector = os.getenv("LAN_IDENTITY_URL", "").rstrip("/")
    if collector and ip:
        try:
            with urlopen(f"{collector}/lookup?ip={ip}", timeout=1.5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                identity = payload.get("identity")
                if isinstance(identity, dict):
                    return identity
        except Exception:
            # A collector outage must never interrupt the demo attack flow.
            pass
    return resolve_local_identity(ip)
