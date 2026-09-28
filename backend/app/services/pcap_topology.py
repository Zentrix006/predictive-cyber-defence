"""Bounded, offline packet capture to topology/replay conversion. No traffic is sent."""
import io
import math
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import IP, IPv6, TCP, UDP, PcapReader


def parse_topology(data: bytes) -> dict:
    nodes, edges, packets = {}, {}, []
    # Check magic as well as the filename; Scapy also accepts gzip streams.
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                        b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
        raise ValueError('Invalid PCAP/PCAPNG header')
    with PcapReader(io.BytesIO(data)) as reader:
        for index, packet in enumerate(reader):
            if index >= 200_000:
                raise ValueError('Capture exceeds 200,000 packets; split it into smaller captures')
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip is None:
                continue
            timestamp = float(packet.time)
            if not math.isfinite(timestamp):
                raise ValueError('Invalid packet timestamp')
            transport = packet.getlayer(TCP) or packet.getlayer(UDP)
            protocol = 'TCP' if TCP in packet else 'UDP' if UDP in packet else str(ip.payload.name)
            port = int(transport.dport) if transport else 0
            for address in (ip.src, ip.dst):
                nodes.setdefault(address, {
                    'id': address, 'asset_id': address, 'label': address,
                    'asset_type': 'unknown', 'zone': 'internet', 'status': 'normal',
                    'criticality': 'low', 'threatScore': 0,
                    'metadata': {'ip': address, 'source': 'pcap', 'os': 'Unknown'},
                })
            key = (ip.src, ip.dst, protocol, port)
            if key not in edges:
                edges[key] = {'id': f'pcap-edge-{len(edges)}', 'source': ip.src, 'target': ip.dst,
                              'protocol': protocol, 'port': port, 'packet_count': 0,
                              'bytes_transferred': 0, 'is_predicted': False,
                              'first_seen': timestamp, 'last_seen': timestamp}
            edge = edges[key]
            edge['packet_count'] += 1
            edge['bytes_transferred'] += len(packet)
            edge['first_seen'] = min(edge['first_seen'], timestamp)
            edge['last_seen'] = max(edge['last_seen'], timestamp)
            packets.append((timestamp, edge['id'], len(packet)))
            if len(nodes) > 500 or len(edges) > 2000:
                raise ValueError('Capture exceeds 500 hosts or 2,000 connections; filter it before uploading')
    if not packets:
        raise ValueError('Capture contains no IPv4 or IPv6 packets')
    start, end = min(p[0] for p in packets), max(p[0] for p in packets)
    duration = end - start
    bins = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for timestamp, edge_id, size in packets:
        frame = min(119, int((timestamp - start) / duration * 119)) if duration else 0
        bins[frame][edge_id][0] += 1
        bins[frame][edge_id][1] += size
    neighbors = defaultdict(set)
    for edge in edges.values():
        neighbors[edge['source']].add(edge['target'])
        neighbors[edge['target']].add(edge['source'])
        for field in ('first_seen', 'last_seen'):
            edge[field] = datetime.fromtimestamp(edge[field], timezone.utc).isoformat()
    for node in nodes.values():
        node['metadata']['connectionCount'] = len(neighbors[node['id']])
    return {
        'nodes': list(nodes.values()), 'edges': list(edges.values()),
        'packet_count': len(packets), 'duration_seconds': duration,
        'frames': [{'offset_seconds': frame * duration / 119,
                    'edges': [{'id': eid, 'packets': counts[0], 'bytes': counts[1]}
                              for eid, counts in bins[frame].items()]}
                   for frame in sorted(bins)],
    }
