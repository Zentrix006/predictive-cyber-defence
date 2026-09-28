"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, Brain, CheckCircle2, ChevronRight, Database, GitBranch,
  Layers3, RefreshCw, ScanLine, ShieldCheck, Sparkles, Timer,
} from 'lucide-react';
import api from '@/lib/api';
import { cn } from '@/utils/classnames';

type Metric = number | null | undefined;

interface Observability {
  generated_at?: string;
  model: Record<string, any>;
  quality: Record<string, any>;
  training: { history?: Record<string, any>[]; candidate?: Record<string, any>; [key: string]: any };
  datasets: { name: string; available: boolean; files: number; bytes: number; updated_at?: string | null }[];
  knowledge_flow: { nodes: { id: string; label: string; detail: string }[]; disclosure: string };
}

const percent = (value: Metric) => typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : '—';
const number = (value: Metric, digits = 3) => typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : '—';
const bytes = (value: number) => {
  if (!value) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
};

function MetricCard({ icon, label, value, detail, tone = 'blue' }: {
  icon: React.ReactNode; label: string; value: string; detail: string; tone?: 'blue' | 'green' | 'purple' | 'amber';
}) {
  const tones = {
    blue: 'border-[var(--accent-blue)]/25 bg-[var(--accent-blue)]/8 text-[var(--accent-blue)]',
    green: 'border-[var(--accent-green)]/25 bg-[var(--accent-green)]/8 text-[var(--accent-green)]',
    purple: 'border-[var(--accent-purple)]/25 bg-[var(--accent-purple)]/8 text-[var(--accent-purple)]',
    amber: 'border-[var(--accent-yellow)]/25 bg-[var(--accent-yellow)]/8 text-[var(--accent-yellow)]',
  };
  return (
    <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-4 panel-surface metric-card min-w-0">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">{label}</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight text-[var(--text-primary)] truncate">{value}</p>
        </div>
        <span className={cn('grid h-9 w-9 shrink-0 place-items-center rounded-lg border', tones[tone])}>{icon}</span>
      </div>
      <p className="mt-2 text-xs leading-relaxed text-[var(--text-secondary)]">{detail}</p>
    </section>
  );
}

function SectionTitle({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle: string }) {
  return (
    <div className="flex items-start gap-3">
      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--accent-blue)]/12 text-[var(--accent-blue)]">{icon}</span>
      <div>
        <h3 className="font-semibold text-[var(--text-primary)]">{title}</h3>
        <p className="mt-0.5 text-xs text-[var(--text-secondary)]">{subtitle}</p>
      </div>
    </div>
  );
}

export function AIIntelligenceView() {
  const [data, setData] = useState<Observability | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const requestId = useRef(0);

  const load = useCallback(async () => {
    const id = ++requestId.current;
    setLoading(true);
    try {
      const response = await api.get<Observability>('/model-lab/observability');
      if (id !== requestId.current) return;
      setData(response);
      setError(null);
    } catch (err: any) {
      if (id !== requestId.current) return;
      const restricted = err?.status === 401 || err?.status === 403;
      if (restricted) setData(null);
      setError(restricted
        ? 'Sign in as an administrator to view AI observability. Guest access is view-only for the operations console.'
        : err?.message || 'Unable to load AI observability.');
    } finally {
      if (id === requestId.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = window.setInterval(load, 15000);
    const sessionChanged = () => { setData(null); load(); };
    window.addEventListener('pcd:session-changed', sessionChanged);
    return () => { requestId.current++; window.clearInterval(interval); window.removeEventListener('pcd:session-changed', sessionChanged); };
  }, [load]);

  const history = data?.training.history || [];
  const recentHistory = history.slice(-8);
  const maxLoss = useMemo(() => Math.max(...recentHistory.map((item) => Number(item.val_loss) || 0), 0.001), [recentHistory]);
  const candidate = data?.training.candidate || {};
  const model = data?.model || {};
  const quality = data?.quality || {};

  return (
    <div className="h-full overflow-auto px-4 py-5 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6 pb-8">
        <header className="rounded-2xl border border-[var(--accent-blue)]/25 bg-gradient-to-br from-[var(--accent-blue)]/14 via-[var(--bg-secondary)] to-[var(--accent-purple)]/10 p-5 sm:p-6 panel-surface">
          <div className="flex flex-col justify-between gap-5 md:flex-row md:items-start">
            <div className="flex min-w-0 gap-4">
              <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border border-[var(--accent-blue)]/30 bg-[var(--accent-blue)]/15 text-[var(--accent-blue)]">
                <Brain className="h-6 w-6" />
              </span>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-xl font-semibold tracking-tight text-[var(--text-primary)]">AI Intelligence</h2>
                  <span className={cn('inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium', model.ready ? 'border-[var(--accent-green)]/35 bg-[var(--accent-green)]/10 text-[var(--accent-green)]' : 'border-[var(--accent-yellow)]/35 bg-[var(--accent-yellow)]/10 text-[var(--accent-yellow)]')}>
                    {model.ready ? <CheckCircle2 className="h-3 w-3" /> : <Activity className="h-3 w-3" />}
                    {error ? 'Status unavailable' : !data ? 'Checking model…' : model.ready ? 'Serving checkpoint ready' : 'Model unavailable'}
                  </span>
                </div>
                <p className="mt-1.5 max-w-2xl text-sm leading-6 text-[var(--text-secondary)]">
                  Operational view of the temporal cyber world model: training provenance, validation evidence,
                  model behaviour and the telemetry-to-response knowledge path.
                </p>
              </div>
            </div>
            <button onClick={load} disabled={loading} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-tertiary)] disabled:opacity-60">
              <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} /> Refresh
            </button>
          </div>
          <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 border-t border-[var(--border-primary)]/80 pt-4 text-xs text-[var(--text-secondary)]">
            <span><span className="text-[var(--text-muted)]">Model</span> <b className="ml-1 font-medium text-[var(--text-primary)]">{model.version || '—'}</b></span>
            <span><span className="text-[var(--text-muted)]">Forecast</span> <b className="ml-1 font-medium text-[var(--text-primary)]">{model.context_window || '—'} observed → {model.horizon || '—'} future steps</b></span>
            <span><span className="text-[var(--text-muted)]">Last update</span> <b className="ml-1 font-medium text-[var(--text-primary)]">{data?.generated_at ? new Date(data.generated_at).toLocaleTimeString() : '—'}</b></span>
          </div>
        </header>

        {error && <div role="alert" className="rounded-xl border border-[var(--accent-yellow)]/35 bg-[var(--accent-yellow)]/10 px-4 py-3 text-sm text-[var(--accent-yellow)]">{error}{data && ' Displaying the last successful snapshot; values may be out of date.'}</div>}
        {loading && !data && !error && <p role="status" className="text-sm text-[var(--text-secondary)]">Loading checkpoint, training history and dataset inventory…</p>}

        {data && <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard icon={<ScanLine className="h-4 w-4" />} label="Stage accuracy" value={percent(quality.stage_accuracy)} detail="Checkpoint-reported held-out stage accuracy." tone="green" />
            <MetricCard icon={<ShieldCheck className="h-4 w-4" />} label="Infiltration accuracy" value={percent(quality.infiltration_accuracy)} detail="Future infiltration classification accuracy." tone="blue" />
            <MetricCard icon={<GitBranch className="h-4 w-4" />} label="Belief futures" value={`${model.branches ?? '—'} branches`} detail="Plausible futures compared before response ranking." tone="purple" />
            <MetricCard icon={<Layers3 className="h-4 w-4" />} label="Input representation" value={`${model.feature_dim || '—'} features`} detail={`${bytes(model.checkpoint_bytes || 0)} serving checkpoint.`} tone="amber" />
          </div>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-5">
            <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-5 panel-surface xl:col-span-3">
              <SectionTitle icon={<Activity className="h-4 w-4" />} title="Training & validation" subtitle="Metrics reported by the serving checkpoint; performance depends on the evaluation dataset and split." />
              <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="rounded-lg bg-[var(--bg-tertiary)]/55 p-3"><p className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Selection metric</p><p className="mt-1 text-sm font-medium text-[var(--text-primary)]">{quality.selection_metric || '—'}</p></div>
                <div className="rounded-lg bg-[var(--bg-tertiary)]/55 p-3"><p className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Validation loss</p><p className="mt-1 text-sm font-medium text-[var(--text-primary)]">{number(quality.validation_loss, 4)}</p></div>
                <div className="rounded-lg bg-[var(--bg-tertiary)]/55 p-3"><p className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Attack macro-F1</p><p className="mt-1 text-sm font-medium text-[var(--text-primary)]">{percent(quality.attack_macro_f1 ?? quality.macro_f1)}</p></div>
              </div>
              <p className="mt-4 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/35 px-3 py-2 text-xs leading-5 text-[var(--text-secondary)]">
                <b className="font-medium text-[var(--text-primary)]">Evaluation protocol:</b> {quality.validation_split || 'Not recorded'}
              </p>
              <p className="mt-2 text-xs leading-5 text-[var(--text-secondary)]"><b className="font-medium text-[var(--text-primary)]">Training source mode:</b> {data.training.synthetic_mode || 'Not recorded'}. Checkpoint metrics do not establish accuracy on your current live network.</p>
              <div className="mt-5 space-y-2.5">
                {recentHistory.length === 0 ? <p className="text-sm text-[var(--text-secondary)]">No per-epoch history is available for the serving checkpoint.</p> : recentHistory.map((epoch) => (
                  <div key={epoch.epoch} className="grid grid-cols-[44px_1fr_auto] items-center gap-3 text-xs">
                    <span className="font-medium text-[var(--text-secondary)]">E{epoch.epoch}</span>
                    <div className="h-2 overflow-hidden rounded-full bg-[var(--bg-tertiary)]"><div className="h-full rounded-full bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-purple)]" style={{ width: `${Math.min(100, Math.max(4, (Number(epoch.val_loss) / maxLoss) * 100))}%` }} /></div>
                    <span className="w-28 text-right text-[var(--text-secondary)]">loss {number(epoch.val_loss, 3)} · F1 {percent(epoch.attack_stage_macro?.f1 ?? epoch.stage_macro?.f1)}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-5 panel-surface xl:col-span-2">
              <SectionTitle icon={<Timer className="h-4 w-4" />} title="Candidate promotion gate" subtitle="Candidate weights remain isolated until evaluation passes." />
              <div className="mt-5 rounded-xl border border-[var(--accent-purple)]/25 bg-[var(--accent-purple)]/8 p-4">
                <div className="flex items-center justify-between gap-3"><span className="text-sm font-medium text-[var(--text-primary)]">{candidate.status?.replaceAll('_', ' ') || 'No candidate run'}</span><Sparkles className="h-4 w-4 text-[var(--accent-purple)]" /></div>
                <p className="mt-2 text-xs leading-5 text-[var(--text-secondary)]">{candidate.message || 'No training candidate is currently recorded.'}</p>
                <dl className="mt-4 space-y-2 border-t border-[var(--accent-purple)]/20 pt-3 text-xs">
                  <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Checkpoint</dt><dd className="font-medium text-[var(--text-primary)]">{candidate.checkpoint_available ? 'available' : 'not written'}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Recorded epochs</dt><dd className="font-medium text-[var(--text-primary)]">{candidate.epochs_recorded ?? 0}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Written</dt><dd className="font-medium text-[var(--text-primary)]">{candidate.checkpoint_written_at ? new Date(candidate.checkpoint_written_at).toLocaleString() : '—'}</dd></div>
                </dl>
              </div>
              <p className="mt-4 text-xs leading-5 text-[var(--text-muted)]">The active endpoint continues serving the validated checkpoint until candidate comparison and an explicit promotion decision.</p>
            </section>
          </div>

          <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-5 panel-surface">
              <SectionTitle icon={<Database className="h-4 w-4" />} title="Dataset inventory" subtitle="Available local files. Availability alone does not confirm that a dataset was used to train the serving checkpoint." />
            <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
              {data.datasets.map((dataset) => <div key={dataset.name} className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-primary)]/25 p-3">
                <div className="flex items-center justify-between gap-2"><span className="font-medium text-sm text-[var(--text-primary)]">{dataset.name}</span><span className={cn('h-2 w-2 rounded-full', dataset.available ? 'bg-[var(--accent-green)]' : 'bg-[var(--text-muted)]')} /></div>
                <p className="mt-3 text-lg font-semibold text-[var(--text-primary)]">{bytes(dataset.bytes)}</p>
                <p className="mt-1 text-xs text-[var(--text-secondary)]">{dataset.available ? 'Available locally' : 'Unavailable'} · {dataset.files} source file{dataset.files === 1 ? '' : 's'}</p>
              </div>)}
              {data.datasets.length === 0 && <p className="text-sm text-[var(--text-secondary)]">No dataset inventory has been reported.</p>}
            </div>
          </section>

          <section className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-5 panel-surface">
            <SectionTitle icon={<Brain className="h-4 w-4" />} title="Knowledge flow" subtitle="How telemetry is converted into a bounded forecast and recommended defence." />
            <div className="mt-6 grid grid-cols-1 items-stretch gap-2 md:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr_auto_1fr]">
              {data.knowledge_flow.nodes.map((node, index) => <div key={node.id} className="contents">
                <div className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-primary)]/30 p-3 text-center"><p className="text-sm font-medium text-[var(--text-primary)]">{node.label}</p><p className="mt-1 text-xs leading-5 text-[var(--text-secondary)]">{node.detail}</p></div>
                {index < data.knowledge_flow.nodes.length - 1 && <ChevronRight className="mx-auto hidden h-5 w-5 self-center text-[var(--accent-blue)] md:block" />}
              </div>)}
            </div>
            <p className="mt-5 rounded-lg border border-[var(--accent-blue)]/20 bg-[var(--accent-blue)]/7 px-3 py-2 text-xs leading-5 text-[var(--text-secondary)]">{data.knowledge_flow.disclosure}</p>
          </section>
        </>}
      </div>
    </div>
  );
}
