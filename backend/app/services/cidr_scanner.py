"""
Subnet CIDR Scanner with Token Bucket Rate Limiting.

Performs controlled, interface-aware active scanning across specified CIDR blocks
(e.g., 10.0.0.0/24, 192.168.1.0/24). Includes:
  * Token bucket rate limiter to prevent switch buffer exhaustion and IDS alarms.
  * Multi-port service probe for management/infrastructure services (22, 80, 443, 445, 161, 8080).
  * Direct ingestion into EvidenceService as DiscoveryObservation records with protocol="cidr_scan".
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.discovery_evidence import DiscoveryObservationCreate
from app.services.evidence_service import EvidenceService

logger = logging.getLogger(__name__)

DEFAULT_PROBE_PORTS = [22, 80, 443, 445, 161, 8080]


class TokenBucketRateLimiter:
    """Asynchronous token bucket rate limiter for pacing outbound network probes."""

    def __init__(self, rate: float = 50.0, capacity: float = 10.0) -> None:
        self.rate = rate  # tokens added per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return

                needed = tokens - self.tokens
                wait_time = needed / self.rate
                await asyncio.sleep(wait_time)


@dataclass
class PortScanResult:
    port: int
    open: bool
    service: str
    banner: Optional[str] = None
    rtt_ms: float = 0.0


@dataclass
class HostScanResult:
    ip: str
    alive: bool
    rtt_ms: float
    open_ports: List[PortScanResult] = field(default_factory=list)
    hostname: Optional[str] = None
    os_hint: Optional[str] = None


@dataclass
class SubnetScanReport:
    cidr: str
    scanned_hosts: int
    live_hosts: int
    results: List[HostScanResult] = field(default_factory=list)
    duration_seconds: float = 0.0
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SubnetCIDRScanner:
    """Enterprise subnet scanner with rate-controlled probing."""

    PORT_SERVICE_MAP = {
        22: "ssh",
        80: "http",
        443: "https",
        445: "smb",
        161: "snmp",
        8080: "http-alt",
    }

    def __init__(
        self,
        rate_limit_pps: float = 50.0,
        port_timeout_seconds: float = 0.5,
    ) -> None:
        self.rate_limiter = TokenBucketRateLimiter(rate=rate_limit_pps, capacity=15.0)
        self.port_timeout_seconds = port_timeout_seconds

    async def scan_cidr(
        self,
        cidr: str,
        probe_ports: Optional[List[int]] = None,
        max_hosts: int = 256,
        mock_live_ips: Optional[Dict[str, List[int]]] = None,
    ) -> SubnetScanReport:
        """
        Scans a CIDR block. If mock_live_ips is provided ({ip: [open_ports]}),
        executes deterministic simulated scan for tests or isolated CI.
        """
        start_time = time.monotonic()
        network = ipaddress.ip_network(cidr, strict=False)
        ports = probe_ports or DEFAULT_PROBE_PORTS

        hosts = [str(ip) for ip in network.hosts()][:max_hosts]
        results: List[HostScanResult] = []

        if mock_live_ips is not None:
            for ip in hosts:
                if ip in mock_live_ips:
                    open_p = mock_live_ips[ip]
                    port_res = [
                        PortScanResult(
                            port=p,
                            open=True,
                            service=self.PORT_SERVICE_MAP.get(p, "unknown"),
                            rtt_ms=2.5,
                        )
                        for p in open_p
                    ]
                    results.append(
                        HostScanResult(
                            ip=ip,
                            alive=True,
                            rtt_ms=2.5,
                            open_ports=port_res,
                            hostname=f"host-{ip.replace('.', '-')}",
                        )
                    )
        else:
            # Active network probing
            tasks = [self._probe_host(ip, ports) for ip in hosts]
            host_results = await asyncio.gather(*tasks)
            results = [r for r in host_results if r.alive]

        duration = time.monotonic() - start_time
        return SubnetScanReport(
            cidr=cidr,
            scanned_hosts=len(hosts),
            live_hosts=len(results),
            results=results,
            duration_seconds=round(duration, 3),
        )

    async def _probe_host(self, ip: str, ports: List[int]) -> HostScanResult:
        """Rate-controlled host and port probe."""
        await self.rate_limiter.acquire(1.0)

        loop = asyncio.get_running_loop()
        open_ports: List[PortScanResult] = []
        is_alive = False
        min_rtt = float("inf")

        for port in ports:
            try:
                t0 = time.monotonic()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)

                try:
                    await asyncio.wait_for(
                        loop.sock_connect(sock, (ip, port)),
                        timeout=self.port_timeout_seconds,
                    )
                    rtt = (time.monotonic() - t0) * 1000.0
                    min_rtt = min(min_rtt, rtt)
                    is_alive = True
                    open_ports.append(
                        PortScanResult(
                            port=port,
                            open=True,
                            service=self.PORT_SERVICE_MAP.get(port, "unknown"),
                            rtt_ms=round(rtt, 2),
                        )
                    )
                except (asyncio.TimeoutError, OSError):
                    pass
                finally:
                    sock.close()
            except Exception:
                pass

        hostname = None
        if is_alive:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None

        return HostScanResult(
            ip=ip,
            alive=is_alive,
            rtt_ms=round(min_rtt if min_rtt != float("inf") else 0.0, 2),
            open_ports=open_ports,
            hostname=hostname,
        )

    async def ingest_scan_report(
        self,
        db: AsyncSession,
        report: SubnetScanReport,
        collector_id: str = "cidr_scanner_01",
    ) -> List[Any]:
        """Feeds discovered hosts and open ports into EvidenceService."""
        observations = []
        for host in report.results:
            obs = DiscoveryObservationCreate(
                source="cidr_scan",
                collector=collector_id,
                confidence=0.88,
                normalized_fields={
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "role": "server" if any(p.port in (80, 443, 8080) for p in host.open_ports) else "host",
                    "cidr": report.cidr,
                    "rtt_ms": host.rtt_ms,
                    "open_ports": [p.port for p in host.open_ports],
                    "services": [p.service for p in host.open_ports],
                    "port_details": [
                        {"port": p.port, "service": p.service, "rtt_ms": p.rtt_ms}
                        for p in host.open_ports
                    ],
                },
            )
            saved = await EvidenceService.record_observation(db, obs)
            observations.append(saved)
        return observations
