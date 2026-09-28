import io
import struct

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, ARP, PcapWriter
from app.services.pcap_topology import parse_topology


def capture_bytes(packets):
    buf = io.BytesIO()
    writer = PcapWriter(buf, sync=True)
    for packet in packets:
        writer.write(packet)
    return buf.getvalue()


def test_ipv4_ipv6_aggregation_and_replay():
    packets = [Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(dport=443),
               Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(dport=443),
               Ether()/IPv6(src='2001:db8::1', dst='2001:db8::2')/UDP(dport=53)]
    for p, t in zip(packets, [103, 100, 102]):
        p.time = t
    result = parse_topology(capture_bytes(packets))
    assert len(result['nodes']) == 4
    assert len(result['edges']) == 2
    assert result['duration_seconds'] == 3
    assert result['edges'][0]['packet_count'] == 2
    assert sum(e['packets'] for f in result['frames'] for e in f['edges']) == 3
    assert sum(e['bytes'] for f in result['frames'] for e in f['edges']) == sum(map(len, packets))
    assert result['frames'][0]['offset_seconds'] == 0
    assert result['frames'][-1]['offset_seconds'] == 3


def test_pcapng_and_zero_duration():
    def block(kind, body):
        length = len(body) + 12
        return struct.pack('<II', kind, length) + body + struct.pack('<I', length)
    packet = bytes(Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/UDP(dport=53))
    data = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    data += block(1, struct.pack('<HHI', 1, 0, 65535))
    data += block(6, struct.pack('<IIIII', 0, 0, 1000000, len(packet), len(packet)) + packet + b'\0' * (-len(packet) % 4))
    result = parse_topology(data)
    assert result['packet_count'] == 1
    assert result['duration_seconds'] == 0
    assert len(result['frames']) == 1


@pytest.mark.parametrize('data', [b'', b'not a capture', capture_bytes([Ether()/ARP()])])
def test_invalid_and_non_ip_capture(data):
    with pytest.raises(ValueError):
        parse_topology(data)
