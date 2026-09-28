"use client";

import { useCallback, useEffect, useRef, useState } from 'react';
import api, { getConsoleSession, toArray } from '@/lib/api';
import { Panel, Spinner, EmptyState, StatCard, RiskBadge } from '@/components/ui/Panel';
import { Cpu, GitBranch, Target, Gauge } from 'lucide-react';
import { cn } from '@/utils/classnames';
import { format } from 'date-fns';

interface WMetrics {
  model_version?: string;
  stage_accuracy?: number;
  infiltration_accuracy?: number;
  lead_time?: { mean_seconds?: number; median_seconds?: number };
  calibration?: { miscalibration?: number; brier_score?: number };
  [k: string]: any;
}

interface Comparison {
  id?: string;
  run_type: string;
  model_version?: string;
  created_at?: string;
  baselines?: { label: string; accuracy: number | null; samples?: number | null; type?: string }[];
  world_model?: { label: string; accuracy: number | null; samples?: number | null; type?: string };
  systems?: { system: string; stage_accuracy: number | null; samples: number }[];
  error?: string;
}

export function ModelLabView() {
  const [metrics, setMetrics] = useState<WMetrics | null>(null);
  const [history, setHistory] = useState<Record<string, any>>({});
  const [evaluations, setEvaluations] = useState<any[]>([]);
  const [comparisons, setComparisons] = useState<Comparison[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [canRun, setCanRun] = useState(false);
  const requestId = useRef(0);

  const load = useCallback(async () => {
    const id = ++requestId.current;
    setLoading(true);
    setError(null);
    setCanRun(Boolean(getConsoleSession()?.roles.includes('admin')));
    try {
      const [m, h, ev, comp] = await Promise.all([
        api.get<WMetrics>('/model-lab/metrics'),
        api.get<Record<string, any>>('/model-lab/checkpoint/history'),
        api.get<any[]>('/model-lab/evaluations'),
        api.get<Comparison[]>('/model-lab/comparisons'),
      ]);
      if (id !== requestId.current) return;
      setMetrics(m);
      setHistory(h);
      setEvaluations(toArray(ev));
      setComparisons(toArray<Comparison>(comp));
    } catch (e: any) {
      if (id !== requestId.current) return;
      if (e?.status === 401 || e?.status === 403) { setMetrics(null); setHistory({}); setEvaluations([]); setComparisons([]); setCanRun(false); }
      setError(e?.status === 401 || e?.status === 403 ? 'Sign in as an administrator to view Model Lab and run evaluations.' : e?.message || 'Failed to load model lab');
    } finally {
      if (id === requestId.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const sessionChanged = () => { setMetrics(null); setHistory({}); setEvaluations([]); setComparisons([]); load(); };
    window.addEventListener('pcd:session-changed', sessionChanged);
    return () => { requestId.current++; window.removeEventListener('pcd:session-changed', sessionChanged); };
  }, [load]);

  const run = async (type: 'baseline' | 'ablation', maxRows: number) => {
    setRunning(type);
    setError(null);
    try {
      const result = await api.post<Comparison>(`/model-lab/${type}`, { max_rows: maxRows });
      setComparisons((prev) => [result, ...prev]);
    } catch (e: any) {
      setError(e?.message || `${type} run failed`);
    } finally {
      setRunning(null);
    }
  };

  const fmtPct = (v: number | null | undefined) => v == null ? '—' : `${(v * 100).toFixed(2)}%`;

  return (
    <div className="p-6 h-full overflow-auto space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="text-xl font-semibold text-[var(--text-primary)]">Model Lab</h2>
          <p className="text-sm text-[var(--text-secondary)]">
            Benchmarking, baselines and ablations of the world-model forecasting stack
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => run('baseline', 1500)}
            disabled={running !== null || !canRun || loading}
            className="px-3 py-1.5 rounded-md text-sm bg-[var(--bg-tertiary)] border border-[var(--border-primary)] hover:bg-[var(--bg-secondary)] transition-colors disabled:opacity-60"
          >
            {running === 'baseline' ? 'Running…' : 'Run baseline'}
          </button>
          <button
            onClick={() => run('ablation', 3000)}
            disabled={running !== null || !canRun || loading}
            className="px-3 py-1.5 rounded-md text-sm font-medium bg-[var(--accent-purple)] text-white hover:opacity-90 transition-colors disabled:opacity-60"
          >
            {running === 'ablation' ? 'Running…' : 'Run ablation'}
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="p-3 rounded-lg bg-[var(--accent-red)]/10 border border-[var(--accent-red)] text-sm text-[var(--accent-red)]">{error}<button onClick={load} disabled={loading} className="ml-3 underline disabled:opacity-60">Retry</button></div>
      )}

      {loading && !metrics && !error && <Spinner />}

      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard label="Model Version" value={history.model_version || metrics.model_version || '—'} icon={<Cpu className="w-5 h-5" />} />
          <StatCard label="Stage Accuracy" value={fmtPct(history.stage_accuracy ?? metrics.stage_accuracy)} tone="green" icon={<Target className="w-5 h-5" />} />
          <StatCard
            label="Mean Lead Time"
            value={metrics.lead_time?.mean_seconds == null ? '—' : `${Math.round(metrics.lead_time.mean_seconds)}s`}
            hint={metrics.lead_time?.median_seconds == null ? 'Median unavailable' : `median ${Math.round(metrics.lead_time.median_seconds)}s`}
            tone="blue"
            icon={<Gauge className="w-5 h-5" />}
          />
          <StatCard
            label="Calibration (ECE)"
            value={fmtPct(metrics.calibration?.miscalibration)}
            tone={metrics.calibration?.miscalibration && metrics.calibration.miscalibration > 0.2 ? 'yellow' : 'green'}
            icon={<GitBranch className="w-5 h-5" />}
          />
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        {/* Checkpoint history */}
        <Panel title="Checkpoint Training History" subtitle="Bounded sessions retained">
          {!history || Object.keys(history).length === 0 ? (
            <EmptyState message="No checkpoint history available (full training runs are offline)." />
          ) : (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Best stage accuracy</span>
                <span className="font-medium text-[var(--text-primary)]">{fmtPct(history.stage_accuracy)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Infiltration accuracy</span>
                <span className="font-medium text-[var(--text-primary)]">{fmtPct(history.infiltration_accuracy)}</span>
              </div>
              {history.checkpoint && (
                <div className="flex justify-between">
                  <span className="text-[var(--text-secondary)]">Checkpoint</span>
                  <span className="font-medium text-[var(--text-primary)]">{history.checkpoint}</span>
                </div>
              )}
            </div>
          )}
        </Panel>

        {/* Recent comparisons */}
        <div className="space-y-3">
          {comparisons.length === 0 && !error && <EmptyState message="Run a baseline or ablation to see comparisons." />}
          {comparisons.map((c, idx) => (
            <Panel key={c.id || idx} title={`${c.run_type} comparison`} subtitle={c.created_at ? format(new Date(c.created_at), 'MMM d, yyyy h:mm a') : undefined}>
              {c.error ? (
                <div className="text-sm text-[var(--accent-red)]">{c.error}</div>
              ) : (
                <div className="space-y-1.5 text-sm">
                  {(c.baselines || []).map((b) => (
                    <div key={b.label} className="flex items-center justify-between">
                      <span className="text-[var(--text-secondary)] capitalize">{b.label}</span>
                      <span className="font-medium text-[var(--text-primary)]">
                        {fmtPct(b.accuracy)}{b.samples != null ? ` (${b.samples} samples)` : ''}
                      </span>
                    </div>
                  ))}
                  {c.world_model && (
                    <div className="flex items-center justify-between font-semibold border-t border-[var(--border-primary)] pt-1.5">
                      <span className="capitalize text-[var(--text-secondary)]">{c.world_model.label}</span>
                      <span className="text-[var(--accent-purple)]">{fmtPct(c.world_model.accuracy)}</span>
                    </div>
                  )}
                  {c.systems && c.systems.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-[var(--border-primary)] space-y-1">
                      <div className="text-xs text-[var(--text-secondary)]">Ablation systems</div>
                      {c.systems.map((s) => (
                        <div key={s.system} className="flex items-center justify-between">
                          <span className="text-[var(--text-secondary)] capitalize">{s.system}</span>
                          <span className="font-medium text-[var(--text-primary)]">{fmtPct(s.stage_accuracy)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </Panel>
          ))}
        </div>
      </div>

      {/* Evaluations + comparison history */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <Panel title="Forecast Evaluations" subtitle={`${evaluations.length} recorded`}>
          {evaluations.length === 0 ? (
            <EmptyState message="No evaluations recorded yet." />
          ) : (
            <div className="space-y-2">
              {evaluations.map((e) => (
                <div key={e.id} className="rounded-lg border border-[var(--border-primary)] p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[var(--text-primary)]">{e.model_version}</span>
                    <span className="text-xs text-[var(--text-muted)]">{format(new Date(e.created_at), 'MMM d, yyyy h:mm a')}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--text-secondary)]">
                    {typeof e.stage_accuracy === 'number' && <span>stage acc {fmtPct(e.stage_accuracy)}</span>}
                    {typeof e.lead_time?.mean_seconds === 'number' && <span>lead time {Math.round(e.lead_time.mean_seconds)}s</span>}
                    {typeof e.infiltration_accuracy === 'number' && <span>infiltration {fmtPct(e.infiltration_accuracy)}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Comparison History" subtitle={`${comparisons.length} run(s)`}>
          {comparisons.length === 0 ? (
            <EmptyState message="No comparisons run yet." />
          ) : (
            <div className="space-y-2">
              {comparisons.map((c, idx) => (
                <div key={`${c.id}-${idx}`} className="rounded-lg border border-[var(--border-primary)] p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold capitalize text-[var(--text-primary)]">{c.run_type}</span>
                    <span className="text-xs text-[var(--text-muted)]">{c.created_at ? format(new Date(c.created_at), 'MMM d, yyyy h:mm a') : ''}</span>
                  </div>
                  {c.error ? (
                    <div className="mt-1 text-xs text-[var(--accent-red)]">{c.error}</div>
                  ) : (
                    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--text-secondary)]">
                      {(c.baselines || []).map((b) => (
                        <span key={b.label}>{b.label}: <span className="text-[var(--text-primary)] font-medium">{fmtPct(b.accuracy)}</span></span>
                      ))}
                      {c.world_model && (
                        <span>{c.world_model.label}: <span className="text-[var(--accent-purple)] font-medium">{fmtPct(c.world_model.accuracy)}</span></span>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
