"""
Network device discovery.

A background service that periodically discovers devices on the local network
and auto-registers them into the system (classification -> Asset upsert ->
topology snapshot -> ``node_added`` broadcast). Any device that joins the
network is automatically enrolled — no manual or QR step required.

Discovery methods (best-effort, guard-rail):
  * ARP scan of the local subnet -> active (ip, mac) pairs.
  * mDNS / DNS-SD queries for common service types -> hostname + services.
  * Reverse-DNS hostname resolution for any still-unnamed host.

scapy is synchronous, so each scan runs in a worker thread via
``asyncio.to_thread`` and is wrapped in ``try/except`` so a failure never
brings the application down.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    Ether,
    IP,
    UDP,
    conf,
    get_if_addr,
    send,
    srp,
)

from app.core.config import settings
from app.core.database import async_session_maker
from app.services.device_registration import register_device
from app.schemas.discovery_evidence import DiscoveryObservationCreate
from app.services.evidence_service import EvidenceService

logger = logging.getLogger(__name__)

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
MDNS_MAC = "01:00:5e:00:00:fb"

# Service types we ask the network about.
MDNS_SERVICE_TYPES: List[str] = [
    "_services._dns-sd._udp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_nfs._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_hap._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_onvif._tcp.local.",
    "_workstation._tcp.local.",
]


@dataclass
class DiscoveredDevice:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    services: List[str] = field(default_factory=list)


class NetworkDiscoveryService:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if not settings.NETWORK_DISCOVERY_ENABLED:
            logger.info("Network discovery disabled (NETWORK_DISCOVERY_ENABLED=false)")
            return
        self._task = asyncio.create_task(self._run_loop(), name="network-discovery")
        logger.info(
            "Network discovery started (interval=%ss, iface=%s, subnet=%s, mdns=%s)",
            settings.NETWORK_DISCOVERY_INTERVAL,
            settings.NETWORK_DISCOVERY_IFACE or "auto",
            settings.NETWORK_DISCOVERY_SUBNET or "auto",
            settings.NETWORK_DISCOVERY_MDNS,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        logger.info("Network discovery stopped")

    async def _run_loop(self) -> None:
        await self._scan_once()  # immediate first scan
        while True:
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.NETWORK_DISCOVERY_INTERVAL)
                return  # stop requested
            except asyncio.TimeoutError:
                pass
            await self._scan_once()

    # ------------------------------------------------------------------ #
    # Async orchestration
    # ------------------------------------------------------------------ #
    async def _scan_once(self) -> None:
        try:
            found = await asyncio.to_thread(
                self._discover, settings.NETWORK_DISCOVERY_TIMEOUT
            )
        except Exception as exc:
            logger.warning("Network discovery scan failed: %s", exc)
            return

        if not found:
            return

        known = await self._known_hosts()
        registered = 0
        for dev in found:
            if (dev.ip, dev.mac) in known:
                continue
            if await self._register(dev):
                registered += 1
        if registered:
            logger.info("Network discovery auto-registered %d new device(s)", registered)

    async def _known_hosts(self) -> Set[Tuple[str, Optional[str]]]:
        try:
            from sqlalchemy import select
            from app.models.asset import Asset
            async with async_session_maker() as db:
                rows = (await db.execute(select(Asset.ip_address, Asset.mac_address))).all()
            return {(ip, mac) for ip, mac in rows if ip}
        except Exception as exc:
            logger.warning("Could not load known assets for dedupe: %s", exc)
            return set()

    async def _register(self, dev: DiscoveredDevice) -> bool:
        try:
            async with async_session_maker() as db:
                # Infrastructure candidates are never silently enrolled into
                # the production topology.  Keep their raw evidence and place
                # them in the existing operator verification queue instead.
                role_hint = self._static_role_hint(dev)
                observation = DiscoveryObservationCreate(
                    source="network_discovery",
                    collector="network_discovery_service",
                    raw_evidence_ref=f"discovery:{dev.ip}:{dev.mac or 'unknown'}",
                    normalized_fields={
                        "ip": dev.ip,
                        "mac": dev.mac,
                        "hostname": dev.hostname,
                        "services": dev.services,
                        "role": role_hint or "unknown",
                        "requires_verification": bool(role_hint),
                    },
                    confidence=0.70 if role_hint else 0.60,
                )
                await EvidenceService.record_observation(db, observation)
                await db.commit()

                if role_hint:
                    logger.info(
                        "Queued static infrastructure candidate %s for operator verification (role=%s)",
                        dev.ip,
                        role_hint,
                    )
                    return True

            async with async_session_maker() as db:
                result = await register_device(
                    db,
                    mac=dev.mac,
                    ip=dev.ip,
                    hostname=dev.hostname,
                    user_agent=None,
                    vendor_class=None,
                    services=dev.services,
                    source="network-discovery",
                )
            if result.get("created"):
                logger.info(
                    "Auto-registered discovered device %s (host=%s svc=%s)",
                    dev.ip, dev.hostname, ",".join(dev.services),
                )
            return True
        except Exception as exc:
            logger.warning("Failed to auto-register discovered device %s: %s", dev.ip, exc)
            return False

    @staticmethod
    def _static_role_hint(dev: DiscoveredDevice) -> Optional[str]:
        """Return an infrastructure role only when discovery has a strong hint."""
        text = " ".join([
            dev.hostname or "",
            *(dev.services or []),
        ]).lower()
        if any(token in text for token in ("router", "gateway", "firewall", "_router")):
            return "router"
        if any(token in text for token in ("switch", "_switch", "bridge", "lldp", "cdp")):
            return "switch"
        if any(token in text for token in ("server", "_ssh", "_http", "_https", "database", "_smb")):
            return "server"
        return None

    # ------------------------------------------------------------------ #
    # Synchronous discovery (worker thread)
    # ------------------------------------------------------------------ #
    def _discover(self, timeout: float) -> List[DiscoveredDevice]:
        iface, subnet = self._resolve_interface_subnet()
        if not iface or not subnet:
            logger.warning("Network discovery: no usable interface/subnet")
            return []

        devs: Dict[str, DiscoveredDevice] = {}

        # 1. ARP scan -> active (ip, mac).
        for ip, mac in self._arp_scan(iface, subnet, timeout):
            devs.setdefault(ip, DiscoveredDevice(ip=ip, mac=mac))

        # 2. mDNS service discovery -> enrich hostnames + services.
        if settings.NETWORK_DISCOVERY_MDNS:
            for ip, md in self._mdns_scan(iface, timeout).items():
                dev = devs.setdefault(ip, DiscoveredDevice(ip=ip))
                if not dev.hostname:
                    dev.hostname = md.get("hostname")
                for svc in md.get("services", []):
                    if svc not in dev.services:
                        dev.services.append(svc)

        # 3. Reverse-DNS for anything still unnamed.
        for dev in devs.values():
            if not dev.hostname:
                dev.hostname = self._reverse_dns(dev.ip)

        exclusions = self._exclude_cidrs()
        return [
            dev for dev in devs.values()
            if not self._is_loopback(dev.ip)
            and not self._in_cidrs(dev.ip, exclusions)
            and not self._is_self(dev.ip)
        ]

    def _resolve_interface_subnet(self) -> Tuple[Optional[str], Optional[str]]:
        iface = settings.NETWORK_DISCOVERY_IFACE
        subnet = settings.NETWORK_DISCOVERY_SUBNET

        if not iface:
            iface = self._detect_iface()
        if not iface:
            return None, None

        if not subnet:
            try:
                local_ip = get_if_addr(iface)
                subnet = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
            except Exception:
                subnet = None
        return iface, subnet

    def _detect_iface(self) -> Optional[str]:
        """Pick the interface holding the default/private route."""
        try:
            tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tmp.connect(("8.8.8.8", 80))
            local_ip = tmp.getsockname()[0]
            tmp.close()
        except OSError:
            local_ip = None
        for name, addr in conf.ifaces.items():
            try:
                if not addr.ip:
                    continue
                if local_ip and addr.ip == local_ip:
                    return name
                if ipaddress.ip_address(addr.ip).is_private:
                    return name
            except Exception:
                continue
        return "eth0"

    def _arp_scan(self, iface: str, subnet: str, timeout: float) -> List[Tuple[str, str]]:
        try:
            ans, _unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=min(timeout, 5),
                iface=iface,
                verbose=0,
            )
            return [(recv.psrc, recv.hwsrc) for _sent, recv in ans]
        except Exception as exc:
            logger.warning("ARP scan on %s failed: %s", iface, exc)
            return []

    def _mdns_scan(self, iface: str, timeout: float) -> Dict[str, Dict]:
        """Send mDNS PTR queries and parse replies into {ip: info}."""
        out: Dict[str, Dict] = {}
        try:
            local_ip = get_if_addr(iface)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", MDNS_PORT))
            mreq = socket.inet_aton(MDNS_GROUP) + socket.inet_aton(local_ip)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(timeout)

            for qname in MDNS_SERVICE_TYPES:
                pkt = (
                    Ether(dst=MDNS_MAC)
                    / IP(dst=MDNS_GROUP)
                    / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
                    / DNS(id=0x0000, qr=0, opcode=0, qd=DNSQR(qname=qname, qtype="PTR"))
                )
                try:
                    send(pkt, iface=iface, verbose=0)
                except Exception:
                    pass

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                info = _parse_mdns(data, addr)
                if info:
                    out.update(info)
            sock.close()
        except Exception as exc:
            logger.warning("mDNS scan on %s failed: %s", iface, exc)
        return out

    def _reverse_dns(self, ip: str) -> Optional[str]:
        try:
            host = socket.gethostbyaddr(ip)[0]
            return host if host else None
        except Exception:
            return None

    @staticmethod
    def _is_loopback(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except Exception:
            return True

    @staticmethod
    def _is_self(ip: str) -> bool:
        """Exclude the host's own addresses (we don't want to register ourselves)."""
        try:
            for name, addr in conf.ifaces.items():
                if addr.ip == ip:
                    return True
        except Exception:
            pass
        return False

    def _exclude_cidrs(self) -> List["ipaddress.IPv4Network"]:
        nets = []
        for raw in (settings.NETWORK_DISCOVERY_EXCLUDE or "").split(","):
            raw = raw.strip()
            if raw:
                try:
                    nets.append(ipaddress.ip_network(raw, strict=False))
                except Exception:
                    pass
        return nets

    def _in_cidrs(self, ip: str, nets: List["ipaddress.IPv4Network"]) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except Exception:
            return True
        return any(a in n for n in nets)


def _parse_mdns(data: bytes, addr: Tuple[str, int]) -> Dict[str, Dict]:
    """Parse a raw mDNS UDP payload with scapy into {ip: {hostname, services}}."""
    out: Dict[str, Dict] = {}
    try:
        pkt = DNS(data)
        if not pkt:
            return out
        answers: List[str] = []
        for section in (pkt.an or []):
            try:
                t = int(section.type)
                rdata = str(section.rdata)
            except Exception:
                continue
            if t == 12:  # PTR -> service instance
                if ".local." in rdata:
                    answers.append(rdata.rstrip("."))
            elif t == 16:  # TXT
                pass
            elif t == 1:  # A -> maps name to IP
                ip = str(section.rdata)
                host = str(section.rrname).rstrip(".")
                m = out.setdefault(ip, {"hostname": None, "services": []})
                if not m["hostname"] and host:
                    m["hostname"] = host

        src_ip = addr[0]
        if answers and src_ip:
            m = out.setdefault(src_ip, {"hostname": None, "services": []})
            for svc in answers:
                if svc not in m["services"]:
                    m["services"].append(svc)
    except Exception:
        pass
    return out


discovery_service = NetworkDiscoveryService()
