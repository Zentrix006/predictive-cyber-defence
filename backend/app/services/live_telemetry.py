"""Supervised live telemetry ingestion for the management/capture plane.

The collector deliberately keeps packet capture and management traffic separate:
the management interface is used by discovery/configuration adapters while the
capture interface is represented by Zeek/SPAN/TAP files or flow-export input.
Raw records are bounded in memory and the API only exposes normalized summaries;
durable evidence remains the responsibility of the configured sensor/object
storage pipeline.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Optional

from app.core.config import settings
from prometheus_client import Counter, Gauge
from features.streaming_telemetry import (
    ContinuousGraphStreamer,
    MultiSensorTelemetryNormalizer,
    NormalizedFlow,
    StreamingTelemetryBuffer,
)

logger = logging.getLogger(__name__)

TELEMETRY_INGESTED = Counter(
    "pcd_telemetry_ingested_total", "Normalized telemetry records accepted", ["source"]
)
TELEMETRY_DROPPED = Gauge("pcd_telemetry_dropped_total", "Telemetry records dropped by bounded buffers")
TELEMETRY_PARSE_ERRORS = Gauge("pcd_telemetry_parse_errors_total", "Telemetry parse/rejection count")
TELEMETRY_BUFFER_UTILIZATION = Gauge("pcd_telemetry_buffer_utilization_ratio", "Telemetry buffer utilization")
TELEMETRY_LAST_EVENT_AGE = Gauge("pcd_telemetry_last_event_age_seconds", "Seconds since the latest event")
TELEMETRY_ENABLED = Gauge("pcd_telemetry_enabled", "Whether the live collector is enabled")
TELEMETRY_RUNNING = Gauge("pcd_telemetry_running", "Whether the live collector task is running")
TELEMETRY_GRAPH_NODES = Gauge("pcd_telemetry_graph_nodes", "Nodes in the latest live graph window")
TELEMETRY_GRAPH_EDGES = Gauge("pcd_telemetry_graph_edges", "Edges in the latest live graph window")

try:
    from netflow import parse_packet as parse_flow_export_packet
except ImportError:  # pragma: no cover - optional in lightweight local installs
    parse_flow_export_packet = None


class _FlowExportProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: "LiveTelemetryService") -> None:
        self.service = service

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.service.sender_allowed(addr[0]):
            logger.warning("Rejected flow export datagram from unauthorized sender %s", addr[0])
            return
        # Never block the event-loop on parsing or broadcast work.
        asyncio.create_task(self.service.ingest_payload(data, addr))


class LiveTelemetryService:
    """Collect Zeek JSON and line-delimited flow exports with bounded state."""

    def __init__(self) -> None:
        capacity = settings.LIVE_TELEMETRY_BUFFER_CAPACITY
        self.normalizer = MultiSensorTelemetryNormalizer()
        self.buffer = StreamingTelemetryBuffer(capacity=capacity)
        self.streamer = ContinuousGraphStreamer(
            self.buffer,
            window_size_seconds=settings.LIVE_TELEMETRY_WINDOW_SECONDS,
        )
        self.records: Deque[dict[str, Any]] = deque(maxlen=capacity)
        self._offsets: Dict[str, int] = {}
        self._task: Optional[asyncio.Task] = None
        self._udp_transport: Optional[asyncio.DatagramTransport] = None
        self._stop = asyncio.Event()
        self._started_at: Optional[float] = None
        self._last_event_at: Optional[float] = None
        self._last_trusted_event_at: Optional[float] = None
        self._last_snapshot_at: float = 0.0
        self._last_snapshot: Optional[dict[str, Any]] = None
        self._source_counts: Dict[str, int] = {}
        self._trusted_source_counts: Dict[str, int] = {}
        self._untrusted_records = 0
        self._parse_errors = 0
        self._ingest_lock = asyncio.Lock()
        self._flow_templates: Dict[str, list] = {"netflow": [], "ipfix": []}
        self._enabled_override: Optional[bool] = None

    @property
    def enabled(self) -> bool:
        return settings.LIVE_TELEMETRY_ENABLED if self._enabled_override is None else self._enabled_override

    async def set_enabled(self, enabled: bool) -> None:
        """Apply the operator toggle immediately for this running process."""
        self._enabled_override = bool(enabled)
        if enabled:
            await self.start()
        else:
            await self.stop()

    async def start(self) -> None:
        if not self.enabled:
            logger.info("Live telemetry collector disabled (LIVE_TELEMETRY_ENABLED=false)")
            return
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._started_at = time.time()
        self._task = asyncio.create_task(self._run(), name="live-telemetry-collector")
        if settings.FLOW_EXPORT_ENABLED:
            try:
                loop = asyncio.get_running_loop()
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _FlowExportProtocol(self),
                    local_addr=(settings.FLOW_EXPORT_LISTEN_ADDR, settings.FLOW_EXPORT_LISTEN_PORT),
                )
                self._udp_transport = transport
                logger.info(
                    "Flow export listener started on %s:%s",
                    settings.FLOW_EXPORT_LISTEN_ADDR,
                    settings.FLOW_EXPORT_LISTEN_PORT,
                )
            except OSError as exc:
                logger.error("Flow export listener unavailable: %s", exc)
        logger.info(
            "Live telemetry collector started (mgmt=%s vlan=%s capture=%s source=%s)",
            settings.TELEMETRY_MGMT_IFACE,
            settings.TELEMETRY_MGMT_VLAN,
            settings.TELEMETRY_CAPTURE_IFACE,
            settings.TELEMETRY_CAPTURE_MODE,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Live telemetry collector stopped")

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._scan_files()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Live telemetry file scan failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=settings.LIVE_TELEMETRY_POLL_SECONDS
                )
            except asyncio.TimeoutError:
                continue

    async def _scan_files(self) -> None:
        root = Path(settings.LIVE_TELEMETRY_DIR).resolve()
        if not root.exists() or not root.is_dir():
            return
        for path in sorted(root.glob("*.log"), key=lambda p: p.stat().st_mtime):
            key = str(path)
            try:
                size = path.stat().st_size
                offset = self._offsets.get(key, 0)
                if size < offset:
                    offset = 0  # sensor rotated/truncated the file
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(offset)
                    lines = handle.readlines()
                    self._offsets[key] = handle.tell()
            except OSError:
                continue
            for line in lines:
                await self._ingest_line(line, source="zeek", source_file=path.name)

    async def _ingest_line(self, line: str, *, source: str, source_file: str = "") -> None:
        text = line.strip()
        if not text or text.startswith("#"):
            return
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            self._parse_errors += 1
            return
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    await self.ingest_record(item, source=source, source_file=source_file)
            return
        if isinstance(payload, dict):
            await self.ingest_record(payload, source=source, source_file=source_file)

    async def ingest_payload(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        """Accept JSON envelopes or binary NetFlow v1/v5/v9/IPFIX frames."""
        if data and parse_flow_export_packet is not None and not data.lstrip().startswith((b"{", b"[")):
            try:
                packet = parse_flow_export_packet(data, self._flow_templates)
                for flow in getattr(packet, "flows", []):
                    record = dict(getattr(flow, "data", {}) or {})
                    for field in ("IPV4_SRC_ADDR", "IPV4_DST_ADDR"):
                        if isinstance(record.get(field), int):
                            record[field] = str(ipaddress.ip_address(record[field]))
                    # NetFlow v5 calls this PROTO; the normalizer accepts both
                    # the canonical PROTOCOL field and this exporter spelling.
                    if "PROTO" in record and "PROTOCOL" not in record:
                        record["PROTOCOL"] = record["PROTO"]
                    if "SRC_PORT" in record and "L4_SRC_PORT" not in record:
                        record["L4_SRC_PORT"] = record["SRC_PORT"]
                    if "DST_PORT" in record and "L4_DST_PORT" not in record:
                        record["L4_DST_PORT"] = record["DST_PORT"]
                    if "IN_OCTETS" in record and "IN_BYTES" not in record:
                        record["IN_BYTES"] = record["IN_OCTETS"]
                    if "OUT_OCTETS" in record and "OUT_BYTES" not in record:
                        record["OUT_BYTES"] = record["OUT_OCTETS"]
                    await self.ingest_record(record, source="netflow_ipfix", source_file=f"udp:{addr[0]}" if addr else "udp")
                return
            except Exception:
                # Keep JSON fallback and expose the failure through status.
                self._parse_errors += 1
                logger.warning("Binary NetFlow/IPFIX payload could not be parsed", exc_info=True)
        try:
            text = data.decode("utf-8", errors="replace")
            for line in text.splitlines() or [text]:
                await self._ingest_line(line, source="flow_export", source_file=f"udp:{addr[0]}" if addr else "udp")
        except Exception:
            self._parse_errors += 1
            logger.exception("Flow export payload could not be decoded")

    @staticmethod
    def sender_allowed(address: str) -> bool:
        """Enforce an exporter allowlist before parsing untrusted UDP input."""
        configured = [item.strip() for item in settings.FLOW_EXPORT_ALLOWED_CIDRS.split(",") if item.strip()]
        if not configured:
            return False
        try:
            ip = ipaddress.ip_address(address)
            return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in configured)
        except ValueError:
            return False

    @staticmethod
    def _provenance(record: dict[str, Any], source: str, flow: NormalizedFlow) -> dict[str, Any]:
        """Classify evidence scope without inferring trust from IPs or filenames.

        A record can feed the trusted graph stream only in explicit production
        profile, from an allowlisted adapter/sensor, with at least one endpoint
        inside an explicitly approved network scope. Everything remains
        inspectable in the raw bounded record view.
        """
        profile = (settings.LIVE_TELEMETRY_PROFILE or "lab").strip().lower()
        approved_sources = {
            item.strip().lower()
            for item in settings.LIVE_TELEMETRY_APPROVED_SOURCE_IDS.split(",")
            if item.strip()
        }
        approved_cidrs = [
            item.strip()
            for item in settings.LIVE_TELEMETRY_APPROVED_CIDRS.split(",")
            if item.strip()
        ]
        source_id = str(
            record.get("sensor_id") or record.get("source_id") or record.get("exporter_id") or source
        ).strip()
        source_allowed = source_id.lower() in approved_sources
        matching_scope = None
        for address in (flow.src_ip, flow.dst_ip):
            try:
                endpoint = ipaddress.ip_address(address)
            except ValueError:
                continue
            for cidr in approved_cidrs:
                try:
                    if endpoint in ipaddress.ip_network(cidr, strict=False):
                        matching_scope = cidr
                        break
                except ValueError:
                    # Invalid operator configuration cannot confer trust.
                    continue
            if matching_scope:
                break
        if profile != "production":
            reason = "collector profile is not production"
        elif not approved_sources or not approved_cidrs:
            reason = "approved source IDs and network scopes are required"
        elif not source_allowed:
            reason = "source is not allowlisted"
        elif not matching_scope:
            reason = "neither endpoint matches an approved network scope"
        else:
            reason = "production source and endpoint scope verified"
        trusted = profile == "production" and source_allowed and matching_scope is not None
        return {
            "profile": profile,
            "source_id": source_id,
            "source_allowlisted": source_allowed,
            "scope_match": matching_scope,
            "trusted_for_graph": trusted,
            "reason": reason,
        }

    async def ingest_record(self, record: dict[str, Any], *, source: str, source_file: str = "") -> None:
        try:
            flow = self.normalizer.normalize(record)
        except (TypeError, ValueError, KeyError) as exc:
            self._parse_errors += 1
            logger.warning("Telemetry record rejected: %s", exc)
            return

        now = time.time()
        provenance = self._provenance(record, source, flow)
        normalized = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "forward_packets": flow.forward_packets,
            "reverse_packets": flow.reverse_packets,
            "forward_bytes": flow.forward_bytes,
            "reverse_bytes": flow.reverse_bytes,
            "duration_seconds": flow.duration_seconds,
            "timestamp": flow.timestamp,
            "sensor_source": source,
            "source_file": source_file or None,
            "provenance": provenance,
            "feature_vector": flow.to_feature_vector().tolist(),
        }
        item = {
            **record,
            "_source": source,
            "_source_file": source_file or None,
            "_provenance": provenance,
            "_ingested_at": datetime.now(timezone.utc).isoformat(),
            "normalized_flow": normalized,
        }
        async with self._ingest_lock:
            self.records.append(item)
            self._last_event_at = now
            self._source_counts[source] = self._source_counts.get(source, 0) + 1
            if provenance["trusted_for_graph"]:
                self.buffer.push(flow)
                self._last_trusted_event_at = now
                self._trusted_source_counts[source] = self._trusted_source_counts.get(source, 0) + 1
                TELEMETRY_INGESTED.labels(source=source).inc()
            else:
                self._untrusted_records += 1
            if provenance["trusted_for_graph"] and now - self._last_snapshot_at >= settings.LIVE_TELEMETRY_WINDOW_SECONDS:
                snapshot = self.streamer.generate_next_snapshot()
                if snapshot:
                    self._last_snapshot = {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "node_count": snapshot.num_nodes,
                        "edge_count": snapshot.num_edges,
                        "nodes": list(snapshot.node_to_idx.keys()),
                        "edges": [
                            {"source": snapshot.idx_to_node.get(int(src), str(src)), "target": snapshot.idx_to_node.get(int(dst), str(dst))}
                            for src, dst in zip(
                                snapshot.edge_index[0, 0].tolist() if snapshot.num_edges else [],
                                snapshot.edge_index[0, 1].tolist() if snapshot.num_edges else [],
                            )
                        ],
                    }
                    self._last_snapshot_at = now
        try:
            from app.ws.manager import ws_manager
            await ws_manager.broadcast("telemetry_event", {"record": item, "source": source})
        except Exception:
            # Telemetry must not fail because a browser/WebSocket is unavailable.
            logger.debug("Telemetry WebSocket broadcast skipped", exc_info=True)

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(self.records)[-max(1, min(limit, settings.LIVE_TELEMETRY_MAX_API_RECORDS)):]

    def status(self) -> dict[str, Any]:
        now = time.time()
        age = None if self._last_event_at is None else round(max(0.0, now - self._last_event_at), 3)
        stale = age is None or age > settings.LIVE_TELEMETRY_STALE_SECONDS
        trusted_age = None if self._last_trusted_event_at is None else round(max(0.0, now - self._last_trusted_event_at), 3)
        trusted_stale = trusted_age is None or trusted_age > settings.LIVE_TELEMETRY_STALE_SECONDS
        status = {
            "enabled": self.enabled,
            "running": bool(self._task and not self._task.done()),
            "started_at": datetime.fromtimestamp(self._started_at, timezone.utc).isoformat() if self._started_at else None,
            "last_event_at": datetime.fromtimestamp(self._last_event_at, timezone.utc).isoformat() if self._last_event_at else None,
            "last_event_age_seconds": age,
            "stale": stale,
            "last_trusted_event_at": datetime.fromtimestamp(self._last_trusted_event_at, timezone.utc).isoformat() if self._last_trusted_event_at else None,
            "last_trusted_event_age_seconds": trusted_age,
            "trusted_feed_stale": trusted_stale,
            "management": {
                "interface": settings.TELEMETRY_MGMT_IFACE,
                "vlan": settings.TELEMETRY_MGMT_VLAN,
                "cidr": settings.TELEMETRY_MGMT_CIDR,
                "gateway": settings.TELEMETRY_MGMT_GATEWAY,
            },
            "capture": {
                "interface": settings.TELEMETRY_CAPTURE_IFACE,
                "mode": settings.TELEMETRY_CAPTURE_MODE,
                "passive": True,
            },
            "flow_export": {
                "enabled": settings.FLOW_EXPORT_ENABLED,
                "listen_addr": settings.FLOW_EXPORT_LISTEN_ADDR,
                "listen_port": settings.FLOW_EXPORT_LISTEN_PORT,
                "allowed_cidrs": [item.strip() for item in settings.FLOW_EXPORT_ALLOWED_CIDRS.split(",") if item.strip()],
            },
            "buffer": self.buffer.metrics(),
            "parse_errors": self._parse_errors,
            "source_counts": dict(self._source_counts),
            "trusted_source_counts": dict(self._trusted_source_counts),
            "untrusted_records": self._untrusted_records,
            "provenance": {
                "profile": (settings.LIVE_TELEMETRY_PROFILE or "lab").strip().lower(),
                "approved_source_ids": [item.strip() for item in settings.LIVE_TELEMETRY_APPROVED_SOURCE_IDS.split(",") if item.strip()],
                "approved_cidrs": [item.strip() for item in settings.LIVE_TELEMETRY_APPROVED_CIDRS.split(",") if item.strip()],
                "trusted_graph_ready": bool(self._trusted_source_counts) and not trusted_stale,
                "inventory_promotion": False,
                "note": "Telemetry never enrolls devices automatically; discovery evidence and operator review are separate workflows.",
            },
            "latest_graph": self._last_snapshot,
        }
        TELEMETRY_ENABLED.set(1 if self.enabled else 0)
        TELEMETRY_RUNNING.set(1 if self._task and not self._task.done() else 0)
        TELEMETRY_DROPPED.set(self.buffer.total_dropped)
        TELEMETRY_PARSE_ERRORS.set(self._parse_errors)
        TELEMETRY_BUFFER_UTILIZATION.set(self.buffer.metrics()["utilization_pct"] / 100.0)
        TELEMETRY_LAST_EVENT_AGE.set(age if age is not None else -1)
        TELEMETRY_GRAPH_NODES.set((self._last_snapshot or {}).get("node_count", 0))
        TELEMETRY_GRAPH_EDGES.set((self._last_snapshot or {}).get("edge_count", 0))
        return status


live_telemetry_service = LiveTelemetryService()
