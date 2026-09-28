"""Bounded offline PCAP/PCAPNG topology extraction for the Demo-2 range."""
import io
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import IP, IPv6, TCP, UDP, PcapReader


def parse_pcap(data: bytes) -> dict:
    if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
        raise ValueError("Invalid PCAP/PCAPNG header")
    nodes, edges, packets = {}, {}, []
    with PcapReader(io.BytesIO(data)) as reader:
        for index, packet in enumerate(reader):
            if index >= 200_000:
                raise ValueError("Capture exceeds 200,000 packets; split it before upload")
            layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if layer is None:
                continue
            ts = float(packet.time)
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
            transport = packet.getlayer(TCP) or packet.getlayer(UDP)
            port = int(transport.dport) if transport else 0
            for address in (layer.src, layer.dst):
                nodes.setdefault(address, {"id": address, "asset_id": address, "label": address,
                    "asset_type": "pcap-host", "zone": "pcap-replay", "status": "normal",
                    "criticality": "low", "threatScore": 0, "metadata": {"ip": address, "source": "offline_pcap"}})
            key = (layer.src, layer.dst, proto, port)
            edge = edges.setdefault(key, {"id": f"pcap-{len(edges)}", "source": layer.src, "target": layer.dst,
                "protocol": proto, "port": port, "packet_count": 0, "bytes_transferred": 0,
                "is_predicted": False, "kind": "pcap"})
            edge["packet_count"] += 1; edge["bytes_transferred"] += len(packet)
            packets.append((ts, edge["id"]))
            if len(nodes) > 500 or len(edges) > 2000:
                raise ValueError("Capture exceeds 500 hosts or 2,000 connections; filter it first")
    if not packets:
        raise ValueError("Capture contains no IPv4 or IPv6 packets")
    start, end = min(x[0] for x in packets), max(x[0] for x in packets)
    neighbors = defaultdict(set)
    for edge in edges.values(): neighbors[edge["source"]].add(edge["target"]); neighbors[edge["target"]].add(edge["source"])
    for node in nodes.values(): node["metadata"]["connectionCount"] = len(neighbors[node["id"]])
    return {"nodes": list(nodes.values()), "edges": list(edges.values()), "packet_count": len(packets),
            "duration_seconds": max(0, end - start), "mode": "offline_replay"}
