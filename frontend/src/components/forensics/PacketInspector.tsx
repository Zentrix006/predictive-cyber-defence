"use client";

import React, { useState, useMemo } from "react";
import { cn } from "@/utils/classnames";

interface PacketRecord {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  protocol: "TCP" | "UDP" | "ICMP" | "DNS" | "HTTP";
  length: number;
  info: string;
  hexPayload: string;
  asciiPayload: string;
  dnsQuery?: string;
}

const SAMPLE_PACKETS: PacketRecord[] = [
  {
    id: "PKT-001",
    timestamp: "16:55:02.104",
    source: "192.168.1.105:54320",
    destination: "10.0.0.5:445",
    protocol: "TCP",
    length: 128,
    info: "SMB2 Session Setup Request, NTLMSSP Negotiate",
    hexPayload: "fe 53 4d 42 40 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 4e 54 4c 4d 53 53 50 00",
    asciiPayload: ".SMB@...........NTLMSSP.",
  },
  {
    id: "PKT-002",
    timestamp: "16:55:02.118",
    source: "192.168.1.105:58921",
    destination: "10.0.0.2:53",
    protocol: "DNS",
    length: 184,
    info: "Standard query 0x1a4b TXT a9f83b2e71d4c09a8e6b12f45da812ef.tunnel.evilc2.org",
    hexPayload: "1a 4b 01 00 00 01 00 00 00 00 00 00 20 61 39 66 38 33 62 32 65 37 31 64 34 63 30 39 61 38 65 36",
    asciiPayload: ".K.......... a9f83b2e71d4c09a8e6",
    dnsQuery: "a9f83b2e71d4c09a8e6b12f45da812ef.tunnel.evilc2.org",
  },
  {
    id: "PKT-003",
    timestamp: "16:55:02.145",
    source: "192.168.1.105:54320",
    destination: "10.0.0.5:445",
    protocol: "TCP",
    length: 256,
    info: "SMB2 Tree Connect Request Tree: \\\\10.0.0.5\\IPC$",
    hexPayload: "fe 53 4d 42 09 00 00 00 00 00 00 00 03 00 01 00 5c 00 5c 00 31 00 30 00 2e 00 30 00 2e 00 30 00",
    asciiPayload: ".SMB............\\.\\.1.0...0...0.",
  },
  {
    id: "PKT-004",
    timestamp: "16:55:02.210",
    source: "192.168.1.105:59102",
    destination: "10.0.0.2:53",
    protocol: "DNS",
    length: 212,
    info: "Standard query 0x7b8c TXT dGVzdF9kYXRhX2V4ZmlsdHJhdGlvbl9wYXlsb2Fk.data.ns1.cx",
    hexPayload: "7b 8c 01 00 00 01 00 00 00 00 00 00 27 64 47 56 7a 64 46 39 6b 59 58 52 68 58 32 56 34 5a 6d 6c",
    asciiPayload: "{...........'dGVzdF9kYXRhX2V4Zml",
    dnsQuery: "dGVzdF9kYXRhX2V4ZmlsdHJhdGlvbl9wYXlsb2Fk.data.ns1.cx",
  },
  {
    id: "PKT-005",
    timestamp: "16:55:02.320",
    source: "192.168.1.105:60114",
    destination: "10.0.0.5:80",
    protocol: "HTTP",
    length: 98,
    info: "GET /api/v1/auth HTTP/1.1 (Slowloris Partial Header - No CRLF)",
    hexPayload: "47 45 54 20 2f 61 70 69 2f 76 31 2f 61 75 74 68 20 48 54 54 50 2f 31 2e 31 0d 0a 58 2d 61 3a 20",
    asciiPayload: "GET /api/v1/auth HTTP/1.1..X-a: ",
  },
];

// Client-side Shannon entropy calculator
function computeShannonEntropy(str: string): number {
  if (!str) return 0.0;
  const counts: Record<string, number> = {};
  for (const ch of str) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  let entropy = 0.0;
  const len = str.length;
  for (const key in counts) {
    const p = counts[key] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(2));
}

interface PacketInspectorProps {
  className?: string;
  onClose?: () => void;
}

export function PacketInspector({ className, onClose }: PacketInspectorProps) {
  const [selectedPkt, setSelectedPkt] = useState<PacketRecord>(SAMPLE_PACKETS[1]);
  const [filterProto, setFilterProto] = useState<string>("ALL");

  const filteredPackets = useMemo(() => {
    if (filterProto === "ALL") return SAMPLE_PACKETS;
    return SAMPLE_PACKETS.filter((p) => p.protocol === filterProto);
  }, [filterProto]);

  const activeQuery = selectedPkt.dnsQuery || selectedPkt.asciiPayload;
  const labelToTest = selectedPkt.dnsQuery ? selectedPkt.dnsQuery.split(".")[0] : activeQuery;
  const entropy = computeShannonEntropy(labelToTest);
  const isHighEntropy = entropy >= 3.6;

  return (
    <div
      className={cn(
        "rounded-xl border border-cyan-500/25 bg-slate-950/95 flex flex-col overflow-hidden shadow-2xl backdrop-blur-md",
        className
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-cyan-500/20">
        <div className="flex items-center gap-2">
          <span className="text-sm font-mono font-bold text-cyan-300">
            DPI LIVE PACKET & SHANNON ENTROPY INSPECTOR
          </span>
          <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-cyan-950/70 border border-cyan-500/30 text-cyan-400">
            Wireshark Core Decoded
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* Protocol Filter Tabs */}
          <div className="flex items-center gap-1 bg-slate-950 p-0.5 rounded border border-slate-800 text-[11px] font-mono">
            {["ALL", "DNS", "TCP", "HTTP"].map((proto) => (
              <button
                key={proto}
                onClick={() => setFilterProto(proto)}
                className={cn(
                  "px-2 py-0.5 rounded transition-colors",
                  filterProto === proto ? "bg-cyan-500/20 text-cyan-300 font-bold" : "text-slate-400 hover:text-slate-200"
                )}
              >
                {proto}
              </button>
            ))}
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 text-sm font-mono px-1.5 py-0.5"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* Packet Stream Table */}
      <div className="h-44 overflow-y-auto border-b border-slate-800/80 font-mono text-xs">
        <table className="w-full text-left border-collapse">
          <thead className="bg-slate-900/60 sticky top-0 text-[11px] text-slate-400 border-b border-slate-800">
            <tr>
              <th className="py-1.5 px-3">Time</th>
              <th className="py-1.5 px-3">Source</th>
              <th className="py-1.5 px-3">Destination</th>
              <th className="py-1.5 px-2">Proto</th>
              <th className="py-1.5 px-2">Len</th>
              <th className="py-1.5 px-3">Info</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {filteredPackets.map((pkt) => (
              <tr
                key={pkt.id}
                onClick={() => setSelectedPkt(pkt)}
                className={cn(
                  "cursor-pointer transition-colors hover:bg-cyan-950/30",
                  selectedPkt.id === pkt.id ? "bg-cyan-950/50 text-cyan-200 font-medium" : "text-slate-300"
                )}
              >
                <td className="py-1 px-3 text-slate-400">{pkt.timestamp}</td>
                <td className="py-1 px-3">{pkt.source}</td>
                <td className="py-1 px-3">{pkt.destination}</td>
                <td className="py-1 px-2">
                  <span
                    className={cn(
                      "px-1.5 py-0.2 rounded text-[10px] font-bold",
                      pkt.protocol === "DNS"
                        ? "bg-purple-950/70 text-purple-300 border border-purple-500/30"
                        : pkt.protocol === "TCP"
                        ? "bg-blue-950/70 text-blue-300 border border-blue-500/30"
                        : "bg-emerald-950/70 text-emerald-300 border border-emerald-500/30"
                    )}
                  >
                    {pkt.protocol}
                  </span>
                </td>
                <td className="py-1 px-2 text-slate-400">{pkt.length}B</td>
                <td className="py-1 px-3 truncate max-w-xs">{pkt.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Deep Inspection Panel & Shannon Entropy Bar */}
      <div className="p-3 bg-slate-950 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
        {/* Left: Entropy Analysis */}
        <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-2.5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-slate-400 font-bold">Lexical Shannon Entropy Meter:</span>
              <span
                className={cn(
                  "px-2 py-0.5 rounded text-[10px] font-bold",
                  isHighEntropy
                    ? "bg-red-950 text-red-300 border border-red-500/40 animate-pulse"
                    : "bg-emerald-950 text-emerald-300 border border-emerald-500/40"
                )}
              >
                {entropy} bits / symbol ({isHighEntropy ? "COVERT TUNNEL" : "NORMAL ASCII"})
              </span>
            </div>

            {/* Entropy Progress Bar */}
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden mb-2">
              <div
                className={cn(
                  "h-full transition-all duration-300 rounded-full",
                  isHighEntropy ? "bg-gradient-to-r from-amber-500 to-red-500" : "bg-emerald-400"
                )}
                style={{ width: `${Math.min(100, (entropy / 5.0) * 100)}%` }}
              />
            </div>

            <div className="text-[11px] text-slate-400 truncate">
              Evaluated Token: <span className="text-slate-200 font-bold">{labelToTest}</span>
            </div>
          </div>

          <div className="text-[10px] text-slate-500 mt-2">
            Threshold: H &gt; 3.6 indicates base64/hex cryptographic obfuscation or DNS tunneling.
          </div>
        </div>

        {/* Right: Hex & ASCII Decode Dump */}
        <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-2.5 overflow-hidden">
          <div className="text-slate-400 font-bold mb-1">Payload Hex Stream:</div>
          <div className="text-[11px] text-cyan-400/90 break-all leading-tight font-mono select-all">
            {selectedPkt.hexPayload}
          </div>
          <div className="text-slate-400 font-bold mt-2 mb-1">Decoded ASCII:</div>
          <div className="text-[11px] text-emerald-400/90 truncate font-mono select-all">
            {selectedPkt.asciiPayload}
          </div>
        </div>
      </div>
    </div>
  );
}
