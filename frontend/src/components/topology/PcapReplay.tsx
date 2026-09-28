"use client";
import { useEffect, useRef, useState } from 'react';
import { authHeaders } from '@/lib/api';
import { TopologyEdge, TopologyNode } from '@/types';

export interface Capture {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  packet_count: number;
  duration_seconds: number;
  frames: { offset_seconds: number; edges: {id: string; packets: number; bytes: number}[] }[];
}
export function PcapReplay({ capture, onCapture, frame, onFrame, onLive }: {
  capture: Capture | null; onCapture: (capture: Capture) => void;
  frame: number; onFrame: (frame: number) => void; onLive: () => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [filename, setFilename] = useState('');
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  useEffect(() => {
    if (!playing || !capture) return;
    if (frame >= capture.frames.length - 1) { setPlaying(false); return; }
    const delta = capture.frames[frame + 1].offset_seconds - capture.frames[frame].offset_seconds;
    const timer = setTimeout(() => onFrame(frame + 1), Math.max(50, delta * 1000 / speed));
    return () => clearTimeout(timer);
  }, [playing, capture, frame, speed, onFrame]);
  const button = 'rounded border border-[var(--border-primary)] px-2 py-1.5 text-xs hover:bg-[var(--bg-tertiary)] disabled:opacity-40';
  return <div className="shrink-0 space-y-2 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] p-2 text-[var(--text-primary)]">
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" className={button} disabled={busy} onClick={() => input.current?.click()}>{busy ? 'Reading capture…' : 'Simulate from PCAP'}</button>
      <input ref={input} type="file" accept=".pcap,.pcapng" className="sr-only" aria-label="Upload topology capture" disabled={busy} onChange={async event => {
        const file = event.target.files?.[0]; event.target.value = ''; if (!file) return;
        setError(''); setPlaying(false);
        if (file.size > 50 * 1024 * 1024) { setError('Maximum capture size is 50 MB.'); return; }
        setBusy(true); const controller = new AbortController(); request.current = controller;
        try {
          const body = new FormData(); body.append('file', file);
          const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || '/api/v1'}/topology/pcap`, { method: 'POST', headers: authHeaders(), body, signal: controller.signal });
          const result = await res.json();
          if (!res.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Capture upload failed');
          onCapture(result); setFilename(file.name); onFrame(0);
        } catch (e) { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : 'Capture upload failed'); }
        finally { if (!controller.signal.aborted) setBusy(false); }
      }} />
      {capture ? <>
        <button type="button" className={button} onClick={() => { setPlaying(false); onLive(); }}>Return to live</button>
        <span className="min-w-0 break-all text-xs">PCAP replay · {filename} · {capture.nodes.length} hosts · {capture.edges.length} connections · {capture.packet_count} packets</span>
      </> : <span className="text-xs text-[var(--text-secondary)]">Live topology · PCAP uploads require an administrator session.</span>}
    </div>
    {error && <p role="alert" className="text-sm text-[var(--accent-red)]">{error}</p>}
    {capture && <>
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={button} disabled={capture.frames.length < 2} onClick={() => { if (frame === capture.frames.length - 1) onFrame(0); setPlaying(!playing); }}>{playing ? 'Pause replay' : 'Play replay'}</button>
        <button type="button" className={button} onClick={() => { setPlaying(false); onFrame(0); }}>Reset replay</button>
        <input className="min-w-24 flex-1" type="range" aria-label="Replay position" min={0} max={capture.frames.length - 1} value={frame} onChange={e => { setPlaying(false); onFrame(Number(e.target.value)); }} />
        <span className="text-xs tabular-nums">{capture.frames[frame]?.offset_seconds.toFixed(2)} / {capture.duration_seconds.toFixed(2)} s</span>
        <select aria-label="Replay speed" className="rounded border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-1 text-xs" value={speed} onChange={e => setSpeed(Number(e.target.value))}>{[0.5, 1, 2, 10, 100].map(n => <option key={n} value={n}>{n}×</option>)}</select>
      </div>
      <p className="text-xs text-[var(--text-secondary)]">Offline visualization only. Highlighted connections carry traffic in the current frame; node positions remain stable during playback.</p>
    </>}
  </div>;
}
