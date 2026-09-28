"use client";

import { useRef, useState } from 'react';
import { FileSearch, RotateCcw, Upload } from 'lucide-react';
import { demoApiBase } from '@/lib/demo-api';

export function DemoPcapAnalyzer({ onReplay, onInvestigation, onReturnLive, replay }: { onReplay: (capture: any) => void; onInvestigation: (result: any) => void; onReturnLive: () => void; replay: any }) {
  const input = useRef<HTMLInputElement>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [name, setName] = useState('');
  const upload = async (file?: File) => {
    if (!file) return; setError('');
    if (file.size > 50 * 1024 * 1024) { setError('Maximum capture size is 50 MB.'); return; }
    setBusy(true); try { const body = new FormData(); body.append('file', file); const response = await fetch(`${demoApiBase()}/pcap/investigate`, { method: 'POST', body }); const data = await response.json(); if (!response.ok) throw new Error(data.detail || 'PCAP investigation failed'); setName(file.name); onReplay(data.topology); onInvestigation(data); } catch (reason: any) { setError(reason.message || 'PCAP investigation failed'); } finally { setBusy(false); }
  };
  return <div className="flex flex-wrap items-center gap-2"><input ref={input} className="sr-only" type="file" accept=".pcap,.pcapng" onChange={e => { upload(e.target.files?.[0]); e.target.value = ''; }} />
    <button type="button" onClick={() => input.current?.click()} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-tertiary)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] hover:bg-[var(--bg-primary)] disabled:opacity-60"><Upload className="h-3.5 w-3.5" />{busy ? 'Analyzing PCAP…' : 'Analyze PCAP'}</button>
    {replay && <><span className="text-xs text-[var(--accent-blue)]"><FileSearch className="mr-1 inline h-3.5 w-3.5" />{name} · {replay.nodes?.length || 0} hosts · {replay.edges?.length || 0} flows · {replay.packet_count || 0} packets</span><button type="button" onClick={onReturnLive} className="inline-flex items-center gap-1 rounded-lg border border-[var(--border-primary)] px-2 py-1.5 text-xs hover:bg-[var(--bg-tertiary)]"><RotateCcw className="h-3.5 w-3.5" />Live LAN</button></>}
    {error && <p role="alert" className="basis-full text-xs text-[var(--accent-red)]">{error}</p>}
  </div>;
}
