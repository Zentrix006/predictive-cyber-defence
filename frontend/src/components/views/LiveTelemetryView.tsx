"use client";

import { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, Cpu, Database, Network, RefreshCw, Router, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";

type TelemetryStatus = {
  enabled?: boolean;
  running?: boolean;
  stale?: boolean;
  last_event_age_seconds?: number | null;
  last_trusted_event_age_seconds?: number | null;
  trusted_feed_stale?: boolean;
  management?: { interface?: string; vlan?: number; cidr?: string; gateway?: string };
  capture?: { interface?: string; mode?: string; passive?: boolean };
  flow_export?: { enabled?: boolean; listen_addr?: string; listen_port?: number };
  buffer?: { current_depth?: number; capacity?: number; utilization_pct?: number; total_ingested?: number; total_dropped?: number; zero_loss_status?: boolean };
  parse_errors?: number;
  source_counts?: Record<string, number>;
  trusted_source_counts?: Record<string, number>;
  untrusted_records?: number;
  provenance?: { profile?: string; approved_source_ids?: string[]; approved_cidrs?: string[]; trusted_graph_ready?: boolean; inventory_promotion?: boolean; note?: string };
  latest_graph?: { node_count?: number; edge_count?: number; generated_at?: string } | null;
};

type TelemetryResponse = { records?: any[]; status?: TelemetryStatus };

function Metric({ label, value, tone = "text-[var(--text-primary)]" }: { label: string; value: string | number; tone?: string }) {
  return <div className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-4"><p className="text-xs uppercase tracking-wide text-[var(--text-muted)]">{label}</p><p className={`mt-2 text-2xl font-semibold tabular-nums ${tone}`}>{value}</p></div>;
}

export function LiveTelemetryView() {
  const [data, setData] = useState<TelemetryResponse>({});
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const result = await api.get<TelemetryResponse>("/telemetry/records?limit=60");
      setData(result);
      setError(null);
    } catch (err: any) {
      setError(err?.message || "Telemetry service is unavailable");
    }
  }, []);

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, [load]);

  const status = data.status || {};
  const records = data.records || [];
  const buffer = status.buffer || {};
  const graph = status.latest_graph || {};
  const sources = status.source_counts || {};

  return <div className="h-full overflow-auto p-4 sm:p-6 space-y-5">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><p className="text-xs uppercase tracking-wider text-[var(--accent-blue)]">Management + data plane</p><h1 className="mt-1 flex items-center gap-2 text-2xl font-semibold"><Activity className="h-6 w-6 text-[var(--accent-blue)]" />Live Telemetry</h1><p className="mt-1 max-w-3xl text-sm text-[var(--text-secondary)]">Passive source visibility is shown separately from authenticated management-plane discovery. Source identity and network scope must be explicitly verified before records enter trusted graph analytics.</p></div>
      <button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-primary)] px-3 py-2 text-sm hover:bg-[var(--bg-tertiary)]"><RefreshCw className="h-4 w-4" />Refresh</button>
    </div>
    {error && <div className="flex items-center gap-2 rounded-lg border border-[var(--accent-yellow)]/30 bg-[var(--accent-yellow)]/10 p-3 text-sm text-[var(--accent-yellow)]"><AlertTriangle className="h-4 w-4" />{error}</div>}
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Metric label="Collector" value={status.enabled ? (status.running ? "Running" : "Stopped") : "Disabled"} tone={status.running ? "text-[var(--accent-green)]" : "text-[var(--accent-yellow)]"} />
      <Metric label="Latest trusted event" value={status.last_trusted_event_age_seconds == null ? "—" : `${status.last_trusted_event_age_seconds}s`} tone={status.trusted_feed_stale ? "text-[var(--accent-yellow)]" : "text-[var(--accent-green)]"} />
      <Metric label="Trusted graph flows" value={buffer.total_ingested ?? 0} tone={status.provenance?.trusted_graph_ready ? "text-[var(--accent-green)]" : "text-[var(--accent-yellow)]"} />
      <Metric label="Dropped events" value={buffer.total_dropped ?? 0} tone={buffer.total_dropped ? "text-[var(--accent-red)]" : "text-[var(--accent-green)]"} />
    </div>
    <section role="status" className={`rounded-xl border p-4 ${status.provenance?.trusted_graph_ready ? 'border-[var(--accent-green)]/30 bg-[var(--accent-green)]/5' : 'border-[var(--accent-yellow)]/30 bg-[var(--accent-yellow)]/5'}`}>
      <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-medium">Source trust & scope</h2><p className="mt-1 text-sm text-[var(--text-secondary)]">Profile: <span className="font-medium capitalize text-[var(--text-primary)]">{status.provenance?.profile || 'lab'}</span> · {status.provenance?.trusted_graph_ready ? 'allowlisted source and endpoint scope observed' : 'trusted graph feed is not configured or has no matching live records'}</p></div><span className={`rounded-full px-2.5 py-1 text-xs font-medium ${status.provenance?.trusted_graph_ready ? 'bg-[var(--accent-green)]/15 text-[var(--accent-green)]' : 'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]'}`}>{status.provenance?.trusted_graph_ready ? 'Scoped feed active' : 'Inspection only'}</span></div>
      <div className="mt-3 flex flex-wrap gap-2 text-xs text-[var(--text-secondary)]"><span className="rounded-full bg-[var(--bg-secondary)] px-2.5 py-1">Approved sources: {status.provenance?.approved_source_ids?.join(', ') || 'none'}</span><span className="rounded-full bg-[var(--bg-secondary)] px-2.5 py-1">Approved scopes: {status.provenance?.approved_cidrs?.join(', ') || 'none'}</span><span className="rounded-full bg-[var(--bg-secondary)] px-2.5 py-1">Unverified retained: {status.untrusted_records ?? 0}</span></div>
      <p className="mt-3 text-xs text-[var(--text-muted)]">{status.provenance?.note || 'Unverified and lab records remain visible for inspection but are excluded from trusted graph windows. This collector does not auto-enroll devices.'}</p>
    </section>
    <div className="grid gap-5 xl:grid-cols-3">
      <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-4"><h2 className="flex items-center gap-2 font-medium"><Router className="h-4 w-4 text-[var(--accent-blue)]" />Management plane</h2><div className="mt-4 space-y-2 text-sm text-[var(--text-secondary)]"><p>Interface <b className="float-right text-[var(--text-primary)]">{status.management?.interface || "—"}</b></p><p>VLAN <b className="float-right text-[var(--text-primary)]">{status.management?.vlan ?? "—"}</b></p><p>Subnet <b className="float-right text-[var(--text-primary)]">{status.management?.cidr || "—"}</b></p><p>Gateway <b className="float-right text-[var(--text-primary)]">{status.management?.gateway || "not configured"}</b></p></div><p className="mt-4 flex items-center gap-2 text-xs text-[var(--accent-green)]"><ShieldCheck className="h-3.5 w-3.5" />Control traffic is isolated from packet capture</p></section>
      <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-4"><h2 className="flex items-center gap-2 font-medium"><Network className="h-4 w-4 text-[var(--accent-blue)]" />Capture and flow sources</h2><div className="mt-4 space-y-2 text-sm text-[var(--text-secondary)]"><p>Capture interface <b className="float-right text-[var(--text-primary)]">{status.capture?.interface || "—"}</b></p><p>Mode <b className="float-right text-[var(--text-primary)]">{status.capture?.mode || "—"}</b></p><p>Flow export <b className="float-right text-[var(--text-primary)]">{status.flow_export?.enabled ? `${status.flow_export.listen_port}/udp` : "disabled"}</b></p><p>Trusted graph buffer <b className="float-right text-[var(--text-primary)]">{buffer.current_depth ?? 0}/{buffer.capacity ?? 0}</b></p></div><div className="mt-4 flex flex-wrap gap-2">{Object.entries(sources).map(([key, count]) => <span key={key} className="rounded-full bg-[var(--bg-tertiary)] px-2 py-1 text-xs">{key}: {count}</span>)}</div></section>
      <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-4"><h2 className="flex items-center gap-2 font-medium"><Cpu className="h-4 w-4 text-[var(--accent-blue)]" />Trusted graph window</h2><div className="mt-4 grid grid-cols-2 gap-3"><Metric label="Nodes" value={graph.node_count ?? "—"} /><Metric label="Edges" value={graph.edge_count ?? "—"} /></div><p className="mt-4 text-xs text-[var(--text-muted)]">Parse errors: {status.parse_errors ?? 0}. Only source-allowlisted flows matching an approved CIDR in production profile enter this graph window.</p></section>
    </div>
    <section className="overflow-hidden rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)]"><div className="flex items-center justify-between border-b border-[var(--border-primary)] px-4 py-3"><div><h2 className="font-medium">Latest normalized observations</h2><p className="text-xs text-[var(--text-muted)]">Unverified records are visible here but excluded from trusted graph windows.</p></div><span className="text-xs text-[var(--text-muted)]">{records.length} retained</span></div><div className="max-h-[28rem] overflow-auto"><table className="w-full min-w-[760px] text-left text-xs"><thead className="sticky top-0 bg-[var(--bg-tertiary)] text-[var(--text-muted)]"><tr><th className="px-4 py-2">Source</th><th className="px-4 py-2">Flow</th><th className="px-4 py-2">Protocol</th><th className="px-4 py-2">Packets</th><th className="px-4 py-2">Scope</th><th className="px-4 py-2">Observed</th></tr></thead><tbody>{records.slice().reverse().map((record: any, index: number) => { const flow = record.normalized_flow || {}; const trust = record._provenance || flow.provenance; return <tr key={`${record._ingested_at || "record"}-${index}`} className="border-t border-[var(--border-primary)]"><td className="px-4 py-2 text-[var(--accent-blue)]">{record._source || flow.sensor_source || "unknown"}</td><td className="px-4 py-2 font-mono">{flow.src_ip || "—"}:{flow.src_port || 0} → {flow.dst_ip || "—"}:{flow.dst_port || 0}</td><td className="px-4 py-2">{flow.protocol || "—"}</td><td className="px-4 py-2">{(flow.forward_packets || 0) + (flow.reverse_packets || 0)}</td><td className="px-4 py-2"><span title={trust?.reason || 'Scope not verified'} className={trust?.trusted_for_graph ? 'text-[var(--accent-green)]' : 'text-[var(--accent-yellow)]'}>{trust?.trusted_for_graph ? `trusted${trust.scope_match ? ` · ${trust.scope_match}` : ''}` : 'unverified'}</span></td><td className="px-4 py-2 text-[var(--text-muted)]">{record._ingested_at ? new Date(record._ingested_at).toLocaleTimeString() : "—"}</td></tr>; })}</tbody></table>{!records.length && <p className="p-8 text-center text-sm text-[var(--text-secondary)]">No live records yet. Enable the collector and connect a Zeek/SPAN/TAP or flow-export source.</p>}</div></section>
  </div>;
}
