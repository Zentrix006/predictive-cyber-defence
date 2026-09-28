"use client";

import { useEffect, useState } from 'react';
import { Activity, Copy, MapPin, Network, ShieldCheck, X } from 'lucide-react';
import { demoApiBase } from '@/lib/demo-api';

export function DemoNodePanel({ node, onClose }: { node: any; onClose: () => void }) {
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setDetail(null); setError(null);
    fetch(`${demoApiBase()}/asset/${encodeURIComponent(node.asset_id || node.id)}/state`)
      .then(async response => { if (!response.ok) throw new Error('Device details are unavailable'); return response.json(); })
      .then(data => { if (!cancelled) setDetail(data); })
      .catch((reason: Error) => { if (!cancelled) setError(reason.message); });
    return () => { cancelled = true; };
  }, [node.asset_id, node.id]);

  const data = detail || node.metadata || node;
  const fields = [
    ['LAN address', data.ip || 'Confidential'], ['Role', data.role || node.asset_type || 'device'],
    ['Status', data.status || node.status], ['Last heartbeat', data.last_seen ? new Date(data.last_seen).toLocaleString() : 'Awaiting heartbeat'],
    ['Service', typeof data.service === 'object' ? data.service.domain || data.service.status : data.service || '—'],
    ['Zone', data.zone || 'LAN'],
  ];

  return <aside aria-label="Live device details" className="absolute inset-y-0 right-0 z-40 flex w-full max-w-sm flex-col border-l border-[var(--border-primary)] bg-[var(--bg-secondary)] shadow-2xl">
    <div className="flex items-start justify-between border-b border-[var(--border-primary)] p-4">
      <div className="flex min-w-0 gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-[var(--accent-blue)]/12 text-[var(--accent-blue)]"><Network className="h-5 w-5" /></span><div className="min-w-0"><h3 className="truncate font-semibold text-[var(--text-primary)]">{data.hostname || node.label}</h3><p className="mt-0.5 text-xs text-[var(--text-secondary)]">Live QR-joined device · {node.asset_id || node.id}</p></div></div>
      <button type="button" onClick={onClose} className="rounded-lg p-2 hover:bg-[var(--bg-tertiary)]" aria-label="Close device details"><X className="h-5 w-5" /></button>
    </div>
    <div className="flex-1 space-y-4 overflow-auto p-4">
      {error && <div className="rounded-lg border border-[var(--accent-yellow)]/30 bg-[var(--accent-yellow)]/10 p-3 text-xs text-[var(--accent-yellow)]">{error}</div>}
      <div className="grid grid-cols-2 gap-2">{fields.map(([label, value]) => <div key={label} className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-3"><p className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{label}</p><p className="mt-1 truncate text-sm font-medium text-[var(--text-primary)]" title={String(value)}>{String(value)}</p></div>)}</div>
      <section className="rounded-xl border border-[var(--border-primary)] p-3"><div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-[var(--accent-green)]" /><h4 className="font-medium text-[var(--text-primary)]">Range state</h4></div><div className="mt-3 space-y-2 text-sm text-[var(--text-secondary)]"><p>Registered: <b className="text-[var(--text-primary)]">{data.registered ? 'Yes' : 'No'}</b></p><p>Predicted target: <b className="text-[var(--text-primary)]">{data.predicted_target ? 'Yes' : 'No'}</b></p><p>Containment: <b className="text-[var(--text-primary)]">{data.contained ? 'Active' : 'Not active'}</b></p>{data.actor && <p>Associated actor: <b className="font-mono text-[var(--accent-red)]">{data.actor}</b></p>}</div></section>
      {data.maintenance && <section className="rounded-xl border border-[var(--accent-yellow)]/30 bg-[var(--accent-yellow)]/10 p-3 text-sm text-[var(--text-secondary)]"><div className="flex items-center gap-2 font-medium text-[var(--accent-yellow)]"><Activity className="h-4 w-4" />Maintenance in progress</div><p className="mt-2">Recovery is using the last known clean state.</p></section>}
      <button type="button" onClick={() => navigator.clipboard?.writeText(node.asset_id || node.id)} className="flex w-full items-center justify-center gap-2 rounded-lg border border-[var(--border-primary)] px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]"><Copy className="h-4 w-4" />Copy device ID</button>
    </div>
  </aside>;
}
