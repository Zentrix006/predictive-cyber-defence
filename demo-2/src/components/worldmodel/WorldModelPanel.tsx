"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, Brain, CheckCircle2, FileSearch, Loader2, Maximize2,
  Network, Radar, Shield, ShieldAlert, Upload, X,
  BarChart3,
} from 'lucide-react';
import { cn } from '@/utils/classnames';
import { useUIStore } from '@/store/uiStore';
import { authHeaders } from '@/lib/api';

interface TopFeature {
  feature: string;
  contribution: number;
  description: string;
}

interface FlaggedFlow {
  src: string;
  dst: string;
  service: string;
  host: string;
  path: string;
  packets: number;
  indicators: string[];
}

interface PcapSummary {
  total_flows: number;
  flagged_flows: number;
  anomaly_score: number;
  protocols: { name: string; count: number }[];
  services: { name: string; count: number }[];
  top_hosts: { host: string; connections: number }[];
  indicators: string[];
  flagged_flow_details: FlaggedFlow[];
}

interface PcapParse {
  format: string;
  packets_total: number;
  ip_packets: number;
  ipv4_packets: number;
  ipv6_packets: number;
  non_ip_packets: number;
  extracted_flows: number;
}

interface Thinking {
  branches: number;
  consensus_agreement: number;
  worst_case: { branch: number; terminal_stage: string; peak_infil_risk: number };
}

interface AnalyzeResult {
  infiltration_timeline: number[];
  predicted_stages: string[];
  stage_probabilities: Record<string, number>[];
  current_stage: string;
  current_confidence: number;
  top_features: TopFeature[];
  natural_language: string;
  model_version: string;
  datasets_trained: string[];
  flagged_flow_indices: number[];
  num_flows: number;
  feature_count: number;
  flow_meta: unknown[];
  pcap_summary: PcapSummary | null;
  pcap_parse?: PcapParse | null;
  thinking?: Thinking | null;
  recommended_action?: string;
  recommended_actions?: {
    step: number;
    action: string;
    action_index: number;
    q_value: number;
    confidence: number;
  }[];
}

const API = process.env.NEXT_PUBLIC_API_URL || '/api/v1';

const STAGE_COLOR: Record<string, string> = {
  reconnaissance: 'var(--accent-blue)',
  initial_access: 'var(--accent-purple)',
  execution: 'var(--accent-yellow)',
  persistence: 'var(--accent-yellow)',
  privilege_escalation: 'var(--accent-red)',
  defense_evasion: 'var(--accent-red)',
  credential_access: 'var(--accent-red)',
  discovery: 'var(--accent-blue)',
  lateral_movement: 'var(--accent-red)',
  collection: 'var(--accent-purple)',
  command_and_control: 'var(--accent-red)',
  exfiltration: 'var(--accent-red)',
  impact: 'var(--accent-red)',
  unknown: 'var(--text-muted)',
};

function riskColor(score: number): string {
  if (score >= 0.5) return 'var(--accent-red)';
  if (score >= 0.2) return 'var(--accent-yellow)';
  return 'var(--accent-green)';
}

function RiskGauge({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score * 100));
  const color = riskColor(score);
  const C = 2 * Math.PI * 40;
  return (
    <div className="relative w-20 h-20 shrink-0">
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        <circle cx="50" cy="50" r="40" fill="none" stroke="var(--border-primary)" strokeWidth="10" />
        <circle
          cx="50" cy="50" r="40" fill="none"
          stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={C * (1 - pct / 100)}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-base font-bold" style={{ color }}>{Math.round(pct)}%</span>
      </div>
    </div>
  );
}

function MetricCard({
  icon, label, value, accent,
}: {
  icon: React.ReactNode; label: string; value: string; accent: string;
}) {
  return (
    <div className="rounded-lg bg-[var(--bg-tertiary)] p-2.5 flex items-center gap-2 min-w-0">
      <div className="w-8 h-8 rounded-md flex items-center justify-center shrink-0" style={{ backgroundColor: `color-mix(in srgb, ${accent} 13%, transparent)`, color: accent }}>
        {icon}
      </div>
      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] truncate">{label}</div>
        <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{value}</div>
      </div>
    </div>
  );
}

function EmptyState({ busy }: { busy: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 h-full text-center px-6">
      <div className={cn(
        "w-14 h-14 rounded-2xl flex items-center justify-center",
        busy ? "bg-[var(--accent-blue)]/15" : "bg-[var(--bg-tertiary)]"
      )}>
        {busy
          ? <Loader2 className="w-7 h-7 animate-spin text-[var(--accent-blue)]" />
          : <Radar className="w-7 h-7 text-[var(--accent-blue)]" />}
      </div>
      <div>
        <p className="text-sm font-medium text-[var(--text-primary)]">
          {busy ? 'Analysing capture…' : 'Analyse PCAP or CSV telemetry'}
        </p>
        <p className="text-xs text-[var(--text-secondary)] mt-1">
          {busy
            ? 'Extracting flows, mapping MITRE stages, simulating K-step dynamics.'
            : 'Drop a packet capture or flow CSV below for offline world-model inference.'}
        </p>
      </div>
    </div>
  );
}

export function WorldModelPanel() {
  const setActiveView = useUIStore((state) => state.setActiveView);
  const [ready, setReady] = useState(false);
  const [checking, setChecking] = useState(true);
  const [statusMsg, setStatusMsg] = useState('Checking model…');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [showDetail, setShowDetail] = useState(false);
  const analysisId = useRef(0);
  const closeDetail = useCallback(() => setShowDetail(false), []);

  useEffect(() => {
    let cancelled = false;
    let requestId = 0;
    const check = async () => {
      const id = ++requestId;
      setChecking(true);
      try {
        const response = await fetch(`${API}/analyze/status`, { headers: authHeaders() });
        if (!response.ok) throw new Error(response.status === 401 || response.status === 403
          ? 'Sign in to check model availability' : 'Model status unavailable');
        const d = await response.json();
        if (cancelled || id !== requestId) return;
        setReady(Boolean(d.ready));
        setStatusMsg(d.ready ? `Ready · ${(d.datasets_trained || []).length} checkpoint-reported datasets` : d.message || 'No serving checkpoint available');
      } catch (error) {
        if (cancelled || id !== requestId) return;
        setReady(false);
        setStatusMsg(error instanceof Error ? error.message : 'Backend unreachable');
      } finally {
        if (!cancelled && id === requestId) setChecking(false);
      }
    };
    const sessionChanged = () => { analysisId.current++; setBusy(false); setResult(null); setFileName(null); setError(null); setShowDetail(false); check(); };
    check();
    const interval = window.setInterval(check, 15000);
    window.addEventListener('pcd:session-changed', sessionChanged);
    return () => { cancelled = true; analysisId.current++; window.clearInterval(interval); window.removeEventListener('pcd:session-changed', sessionChanged); };
  }, []);

  const runAnalysis = useCallback(async (file: File) => {
    const id = ++analysisId.current;
    setBusy(true);
    setError(null);
    setResult(null);
    setFileName(file.name);
    try {
      const body = new FormData();
      body.append('file', file);
      const res = await fetch(`${API}/analyze/upload`, { method: 'POST', headers: authHeaders(), body });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || 'Upload failed');
      }
      const data = await res.json();
      if ((data as any).detail) throw new Error(data.detail);
      if (id !== analysisId.current) return;
      setResult(data);
    } catch (e: any) {
      if (id === analysisId.current) setError(e.message || String(e));
    } finally {
      if (id === analysisId.current) setBusy(false);
    }
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f && !busy) runAnalysis(f);
  }, [runAnalysis, busy]);

  const isPcap = fileName?.toLowerCase().endsWith('.pcap') || fileName?.toLowerCase().endsWith('.pcapng');
  const summary = result?.pcap_summary ?? null;
  const gaugeScore = summary ? summary.anomaly_score : (result?.infiltration_timeline.slice(-1)[0] ?? 0);

  const protocolTotal = useMemo(() => summary?.protocols.reduce((a, p) => a + p.count, 0) ?? 0, [summary]);

  return (
    <div className="h-full flex flex-col bg-[var(--bg-secondary)] border-t border-[var(--border-primary)] overflow-hidden">
      {/* Header */}
      <div className="px-3 h-12 shrink-0 border-b border-[var(--border-primary)] flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-[var(--accent-blue)]/15 flex items-center justify-center shrink-0">
            <Brain className="w-4 h-4 text-[var(--accent-blue)]" />
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-[var(--text-primary)] leading-tight truncate">World Model Analyse</h2>
            <p className="text-[10px] text-[var(--text-secondary)] truncate">{statusMsg}</p>
          </div>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            onClick={() => setActiveView('ai-intelligence')}
            className="flex items-center gap-1 text-[11px] px-2 py-1 rounded-md bg-[var(--accent-blue)]/10 hover:bg-[var(--accent-blue)]/18 text-[var(--accent-blue)]"
            title="Open AI Intelligence dashboard"
          >
            <BarChart3 className="w-3 h-3" /><span className="hidden sm:inline">AI dashboard</span>
          </button>
          {fileName && result && (
            <button
              onClick={() => setShowDetail(true)}
              className="flex items-center gap-1 text-[11px] px-2 py-1 rounded-md bg-[var(--text-primary)]/5 hover:bg-[var(--text-primary)]/10 text-[var(--text-primary)]"
              title="Open full analysis view"
            >
              <Maximize2 className="w-3 h-3" /> Detail
            </button>
          )}
          <span className={cn(
            "flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border",
            ready ? "bg-[var(--accent-green)]/10 text-[var(--accent-green)] border-[var(--accent-green)]/20" : "bg-[var(--accent-yellow)]/10 text-[var(--accent-yellow)] border-[var(--accent-yellow)]/20"
          )}>
            {ready ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
            {checking ? 'Checking' : ready ? 'Ready' : 'Unavailable'}
          </span>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-auto min-h-0">
        {/* Upload box */}
        <div className="p-2.5 border-b border-[var(--border-primary)]">
          <label
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            className={cn(
              "flex flex-col items-center justify-center gap-1.5 border border-dashed rounded-lg p-3 cursor-pointer transition-colors focus-within:outline focus-within:outline-2 focus-within:outline-[var(--accent-blue)]",
              dragOver ? "border-[var(--accent-blue)] bg-[var(--accent-blue)]/10" : "border-[var(--border-primary)]",
              busy && "opacity-60 pointer-events-none"
            )}
          >
            <div className="flex items-center gap-2">
              {busy
                ? <Loader2 className="w-4 h-4 animate-spin text-[var(--accent-blue)]" />
                : <Upload className="w-4 h-4 text-[var(--accent-blue)]" />}
              <span className="text-xs font-medium text-[var(--text-primary)]">Upload capture or CSV</span>
            </div>
            <span className="text-[10px] text-[var(--text-secondary)]">PCAP / PCAPNG · UNSW / CIC / NSL-KDD — drop or click</span>
            <input
              type="file"
              accept=".csv,.pcap,.pcapng"
              className="sr-only"
              disabled={busy}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) runAnalysis(f);
                e.target.value = '';
              }}
            />
          </label>
        </div>

        {/* Message area */}
        <div className="p-2.5 space-y-2.5">
          {error && (
            <div role="alert" className="text-xs text-[var(--accent-red)] bg-[var(--accent-red)]/10 border border-[var(--accent-red)]/30 rounded-md p-2 flex items-start gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {busy && !result && <EmptyState busy />}

          {!busy && !error && fileName === null && <EmptyState busy={false} />}

          {result && (
            <div className="space-y-3">
              {fileName && (
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-1.5 text-[11px] text-[var(--text-secondary)] min-w-0">
                    <FileSearch className="w-3.5 h-3.5 shrink-0" />
                    <span className="truncate">{fileName}</span>
                  </span>
                  <button aria-label="Clear analysis result" onClick={() => { setResult(null); setFileName(null); }}
                    className="text-[var(--text-muted)] hover:text-[var(--text-primary)] shrink-0">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

              {/* Risk headline */}
              <div className={cn(
                "rounded-lg p-2.5 flex items-center gap-3 border",
                summary && summary.flagged_flows > 0
                  ? "bg-red-500/10 border-red-500/25"
                  : "bg-[var(--bg-tertiary)] border-transparent"
              )}>
                <RiskGauge score={gaugeScore} />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-semibold text-[var(--text-primary)]">
                    {summary && summary.flagged_flows > 0
                      ? 'Suspicious indicators detected'
                      : result.current_stage === 'unknown'
                        ? 'Stage undetermined'
                        : `Stage: ${result.current_stage.replace(/_/g, ' ')}`}
                  </div>
                  <div className="text-[10px] text-[var(--text-secondary)] mt-0.5 leading-snug">
                    {isPcap
                      ? `${result.pcap_parse?.extracted_flows ?? summary?.total_flows ?? 0} flows extracted from ${result.pcap_parse?.ip_packets ?? 0} IP packets · ${summary?.flagged_flows ?? 0} IOC flags`
                      : `Infiltration risk over ${result.infiltration_timeline.length} steps ending at ${(result.infiltration_timeline.slice(-1)[0] * 100).toFixed(0)}%`}
                  </div>
                </div>
              </div>

              {/* Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                <MetricCard icon={<Network className="w-4 h-4" />} label="Flows" value={String(summary?.total_flows ?? result.num_flows)} accent="var(--accent-blue)" />
                <MetricCard icon={<Radar className="w-4 h-4" />} label="IP packets" value={String(result.pcap_parse?.ip_packets ?? '—')} accent="var(--accent-blue)" />
                <MetricCard icon={<ShieldAlert className="w-4 h-4" />} label="IOC flags" value={String(summary?.flagged_flows ?? result.flagged_flow_indices.length)} accent={summary && summary.flagged_flows ? 'var(--accent-red)' : 'var(--accent-green)'} />
                <MetricCard icon={<Shield className="w-4 h-4" />} label="Stage" value={result.current_stage.replace(/_/g, ' ')} accent="var(--accent-purple)" />
              </div>

              {/* Indicators */}
              {summary && summary.indicators.length > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Detection indicators</div>
                  <ul className="space-y-1">
                    {summary.indicators.slice(0, 5).map((ind, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-[11px] text-[var(--text-primary)]">
                        <ShieldAlert className="w-3 h-3 mt-0.5 shrink-0 text-[var(--accent-red)]" />
                        <span className="leading-snug">{ind}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* MITRE progression */}
              {result.infiltration_timeline.length > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Predicted MITRE progression</div>
                  <div className="flex gap-1">
                    {result.infiltration_timeline.map((p, i) => {
                      const s = result.predicted_stages[i] ?? 'unknown';
                      return (
                        <div key={i} className="flex-1 rounded-md overflow-hidden border border-[var(--border-primary)]">
                          <div className="h-1.5" style={{ backgroundColor: STAGE_COLOR[s] ?? 'var(--text-muted)' }} />
                          <div className="px-1 py-1 text-center bg-[var(--bg-tertiary)]">
                            <div className="text-[9px] text-[var(--text-muted)]">t+{i + 1}</div>
                            <div className="text-[9px] font-medium truncate" style={{ color: STAGE_COLOR[s] ?? 'var(--text-primary)' }}>{s.replace(/_/g, ' ')}</div>
                            <div className="text-[9px] text-[var(--text-secondary)]">{(p * 100).toFixed(0)}%</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Protocol breakdown (pcap) */}
              {summary && protocolTotal > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Protocol breakdown</div>
                  <div className="space-y-1">
                    {summary.protocols.slice(0, 4).map((p) => (
                      <div key={p.name} className="flex items-center gap-2 text-[11px]">
                        <span className="w-10 shrink-0 text-[var(--text-secondary)] capitalize">{p.name}</span>
                        <div className="flex-1 h-1.5 rounded-full bg-[var(--bg-tertiary)] overflow-hidden">
                          <div className="h-full rounded-full bg-[var(--accent-blue)]/80" style={{ width: `${(p.count / protocolTotal) * 100}%` }} />
                        </div>
                        <span className="w-8 text-right text-[var(--text-muted)]">{p.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Top hosts (pcap) */}
              {summary && summary.top_hosts.length > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Top destinations</div>
                  <div className="flex flex-wrap gap-1">
                    {summary.top_hosts.slice(0, 5).map((h) => (
                      <span key={h.host} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)] font-mono">
                        {h.host} <span className="text-[var(--text-muted)]">×{h.connections}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Top features */}
              <div className="space-y-1.5">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Driving features</div>
                <ul className="space-y-0.5">
                  {result.top_features.slice(0, 4).map((f) => (
                    <li key={f.feature} className="flex justify-between gap-2 text-[11px]">
                      <span className="text-[var(--text-primary)] truncate">{f.feature}</span>
                      <span className="text-[var(--text-secondary)] shrink-0">{(f.contribution * 100).toFixed(0)}%</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Structured forecast evidence, distinct from measured accuracy. */}
              {result.thinking && result.thinking.branches > 0 && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Forecast evidence</div>
                    <span className="flex items-center gap-1 text-[10px] text-[var(--text-secondary)]">
                      <Brain className="w-3 h-3" />
                      {result.thinking.branches} branches
                    </span>
                  </div>
                  <dl className="space-y-1 text-[11px]">
                    <div className="flex justify-between gap-2"><dt className="text-[var(--text-secondary)]">Stage confidence</dt><dd>{(result.current_confidence * 100).toFixed(0)}%</dd></div>
                    <div className="flex justify-between gap-2"><dt className="text-[var(--text-secondary)]">Branch agreement</dt><dd>{Math.round(result.thinking.consensus_agreement * 100)}%</dd></div>
                    <div className="flex justify-between gap-2"><dt className="text-[var(--text-secondary)]">Checkpoint</dt><dd className="break-all text-right">{result.model_version}</dd></div>
                  </dl>
                  <p className="text-[11px] leading-relaxed text-[var(--text-secondary)]">Agreement measures similarity between simulated futures. It is not validated prediction accuracy.</p>
                  {result.thinking.worst_case && result.thinking.worst_case.terminal_stage && (
                    <div className="text-[10px] text-[var(--text-secondary)] mt-0.5">
                      Highest-risk simulated branch ends at{' '}
                      <span className="text-[var(--accent-red)]">{result.thinking.worst_case.terminal_stage.replace(/_/g, ' ')}</span>{' '}
                      (terminal risk {(result.thinking.worst_case.peak_infil_risk * 100).toFixed(0)}%)
                    </div>
                  )}
                </div>
              )}

              {/* Recommended response (DQN policy) */}
              {result.recommended_actions && result.recommended_actions.length > 0 && (
                <div className="rounded-lg border border-[var(--accent-green)]/40 bg-[var(--accent-green)]/5 p-2.5 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent-green)]">Suggested response · not executed</div>
                    <span className="text-[10px] font-medium text-[var(--accent-green)]">{result.recommended_action?.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {result.recommended_actions.slice(0, 6).map((a, i) => (
                      <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-primary)]">
                        t+{a.step} <span className="text-[var(--accent-green)]">{a.action.replace(/_/g, ' ')}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <p className="text-[11px] text-[var(--text-primary)] leading-relaxed border-t border-[var(--border-primary)] pt-2">
                {result.natural_language}
              </p>
            </div>
          )}
        </div>
      </div>

      {showDetail && result && (
        <DetailModal result={result} filename={fileName} onClose={closeDetail} />
      )}
    </div>
  );
}

function DetailModal({
  result, filename, onClose,
}: {
  result: AnalyzeResult; filename: string | null; onClose: () => void;
}) {
  const summary = result.pcap_summary;
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const dialog = dialogRef.current;
    dialog?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); onClose(); }
      if (event.key !== 'Tab' || !dialog) return;
      const elements = dialog.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), [tabindex="0"]');
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (!first) { event.preventDefault(); return; }
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === dialog)) { event.preventDefault(); first.focus(); }
    };
    dialog?.addEventListener('keydown', onKeyDown);
    return () => { dialog?.removeEventListener('keydown', onKeyDown); previousFocus?.focus(); };
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70" onClick={onClose}>
      <div
        ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="analysis-detail-title" tabIndex={-1}
        className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-[var(--border-primary)] flex items-center justify-between">
          <div>
            <h3 id="analysis-detail-title" className="text-base font-semibold text-[var(--text-primary)]">Analysis detail</h3>
            <p className="text-xs text-[var(--text-secondary)]">{filename} · {result.num_flows} flows · {result.model_version}</p>
          </div>
          <button aria-label="Close analysis detail" onClick={onClose} className="p-2 rounded-md hover:bg-[var(--bg-tertiary)] text-[var(--text-muted)] hover:text-[var(--text-primary)]">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 overflow-auto space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-lg bg-[var(--bg-tertiary)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">Flows</div>
              <div className="text-xl font-bold text-[var(--text-primary)]">{summary?.total_flows ?? result.num_flows}</div>
            </div>
            <div className="rounded-lg bg-[var(--bg-tertiary)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">IOC flags</div>
              <div className="text-xl font-bold" style={{ color: summary && summary.flagged_flows ? 'var(--accent-red)' : 'var(--accent-green)' }}>{summary?.flagged_flows ?? result.flagged_flow_indices.length}</div>
            </div>
            <div className="rounded-lg bg-[var(--bg-tertiary)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">Current stage</div>
              <div className="text-base font-bold capitalize" style={{ color: STAGE_COLOR[result.current_stage] }}>{result.current_stage.replace(/_/g, ' ')}</div>
            </div>
            <div className="rounded-lg bg-[var(--bg-tertiary)] p-3">
              <div className="text-[10px] uppercase text-[var(--text-muted)]">Confidence</div>
              <div className="text-xl font-bold text-[var(--text-primary)]">{(result.current_confidence * 100).toFixed(0)}%</div>
            </div>
          </div>

          {/* Infiltration timeline bars */}
          <div>
            <div className="text-xs font-semibold text-[var(--text-secondary)] mb-1">K-step infiltration probability</div>
            <div className="flex gap-1 h-24 items-end">
              {result.infiltration_timeline.map((p, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full rounded-t" style={{ height: `${Math.max(8, p * 100)}%`, backgroundColor: riskColor(p) }} title={`t+${i + 1}: ${(p * 100).toFixed(1)}%`} />
                  <span className="text-[10px] text-[var(--text-secondary)]">t+{i + 1}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Stage probabilities per step */}
          <div>
            <div className="text-xs font-semibold text-[var(--text-secondary)] mb-2">Stage probabilities</div>
            <div className="space-y-2">
              {result.stage_probabilities.map((probs, step) => {
                const top = Object.entries(probs).sort((a, b) => b[1] - a[1]).slice(0, 3);
                return (
                  <div key={step} className="rounded-lg bg-[var(--bg-tertiary)] p-2">
                    <div className="text-[10px] uppercase text-[var(--text-muted)] mb-1">t+{step + 1}</div>
                    {top.map(([k, v]) => (
                      <div key={k} className="flex items-center gap-2 text-[11px]">
                        <span className="w-32 truncate capitalize" style={{ color: STAGE_COLOR[k] }}>{k.replace(/_/g, ' ')}</span>
                        <div className="flex-1 h-1.5 rounded-full bg-[var(--bg-primary)]/40 overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${v * 100}%`, backgroundColor: STAGE_COLOR[k] }} />
                        </div>
                        <span className="w-12 text-right text-[var(--text-muted)]">{(v * 100).toFixed(1)}%</span>
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Indicators */}
          {summary && summary.indicators.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-[var(--text-secondary)] mb-1">Detection indicators</div>
              <ul className="space-y-1">
                {summary.indicators.map((ind, i) => (
                  <li key={i} className="text-xs text-[var(--text-primary)] flex items-start gap-1.5 bg-red-500/5 border border-red-500/15 rounded-md p-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 mt-0.5 text-[var(--accent-red)] shrink-0" /> {ind}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Flagged flows table */}
          {summary && summary.flagged_flow_details.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-[var(--text-secondary)] mb-1">Flagged flows</div>
              <div className="overflow-x-auto rounded-lg border border-[var(--border-primary)]">
                <table className="w-full text-left text-[11px]">
                  <thead>
                    <tr className="bg-[var(--bg-tertiary)] text-[var(--text-muted)]">
                      <th className="px-2 py-1.5 font-medium">Source</th>
                      <th className="px-2 py-1.5 font-medium">Dest / Host</th>
                      <th className="px-2 py-1.5 font-medium">Path</th>
                      <th className="px-2 py-1.5 font-medium">Indicator</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.flagged_flow_details.map((f, i) => (
                      <tr key={i} className="border-t border-[var(--border-primary)]">
                        <td className="px-2 py-1.5 font-mono text-[var(--text-secondary)]">{f.src}</td>
                        <td className="px-2 py-1.5 font-mono text-[var(--text-primary)]">{f.host || f.dst}</td>
                        <td className="px-2 py-1.5 font-mono text-[var(--text-secondary)]">{f.path || '—'}</td>
                        <td className="px-2 py-1.5 text-[var(--accent-red)]">{f.indicators[0]}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* All hosts */}
          {summary && summary.top_hosts.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-[var(--text-secondary)] mb-1">Traffic destinations</div>
              <div className="flex flex-wrap gap-1.5">
                {summary.top_hosts.map((h) => (
                  <span key={h.host} className="text-[11px] px-2 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)] font-mono">
                    {h.host} <span className="text-[var(--text-muted)]">×{h.connections}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Features */}
          <div>
            <div className="text-xs font-semibold text-[var(--text-secondary)] mb-1">Driving features (attribution)</div>
            <ul className="space-y-1">
              {result.top_features.map((f) => (
                <li key={f.feature} className="flex justify-between text-xs">
                  <span className="text-[var(--text-primary)]">{f.feature} <span className="text-[var(--text-muted)]">· {f.description}</span></span>
                  <span className="text-[var(--text-secondary)]">{(f.contribution * 100).toFixed(1)}%</span>
                </li>
              ))}
            </ul>
          </div>

          <p className="text-xs text-[var(--text-primary)] leading-relaxed border-t border-[var(--border-primary)] pt-2">{result.natural_language}</p>
        </div>
      </div>
    </div>
  );
}
