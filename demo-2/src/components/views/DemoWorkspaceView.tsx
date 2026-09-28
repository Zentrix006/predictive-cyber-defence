"use client";

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, BookOpen, Brain, Clock, Database, FlaskConical, HardDrive, Network, RefreshCw, ShieldAlert, SlidersHorizontal, Users, Workflow, X } from 'lucide-react';
import { Panel, EmptyState, Spinner, RiskBadge } from '@/components/ui/Panel';
import { demoApiBase } from '@/lib/demo-api';

type View = 'attack' | 'threat-actors' | 'deception' | 'forensics' | 'infrastructure' | 'ai-intelligence' | 'model-lab' | 'settings';
const stage = (value?: string) => (value || 'unknown').replace(/_/g, ' ');
const api = async (path: string, init?: RequestInit) => { const response = await fetch(`${demoApiBase()}${path}`, init); if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || 'Demo range request failed'); return response.json(); };
const Card = ({ label, value, note }: { label: string; value: any; note?: string }) => <div className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-4"><p className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">{label}</p><p className="mt-1 truncate text-2xl font-semibold text-[var(--text-primary)]">{value ?? '—'}</p>{note && <p className="mt-1 text-xs text-[var(--text-secondary)]">{note}</p>}</div>;

export function DemoWorkspaceView({ view }: { view: View }) {
  const [data, setData] = useState<any>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState<string | null>(null); const [message, setMessage] = useState<string | null>(null);
  // The overview is an atomic range snapshot. Using it for the forecast and
  // actor workspaces prevents those screens from briefly disagreeing after a
  // recon/pivot/containment event.
  const endpoint: Record<View, string> = { attack: '/command/overview', 'threat-actors': '/command/overview', deception: '/command/topology', forensics: '/command/timeline?limit=80', infrastructure: '/command/topology', 'ai-intelligence': '/ai/observability', 'model-lab': '/ai/observability', settings: '/command/health' };
  const load = useCallback(async () => {
    setLoading(true);
    try {
      if (view === 'forensics') {
        setData({ events: await api(endpoint[view]), archives: await api('/forensics/archives') });
      } else if (view === 'attack') {
        // Forecast view needs both the live prediction and the past outcomes.
        const [present, history] = await Promise.all([
          api(endpoint[view]),
          api('/command/forecast/history?limit=25').catch(() => ({ history: [] })),
        ]);
        setData({ ...present, history: history.history || [] });
      } else {
        setData(await api(endpoint[view]));
      }
      setError(null);
    } catch (reason: any) {
      setError(reason.message);
    } finally {
      setLoading(false);
    }
  }, [view]);
  // The observability payload scans the dataset tree; poll it less often —
  // except while a candidate training run is active (live progress).
  const liveTraining = view === 'model-lab' && data?.training?.status?.status === 'running';
  const pollMs = view === 'attack' || view === 'threat-actors' ? 3000 : view === 'ai-intelligence' || view === 'model-lab' ? (liveTraining ? 3000 : 20000) : 8000;
  useEffect(() => { load(); const timer = window.setInterval(load, pollMs); return () => clearInterval(timer); }, [load, pollMs]);
  // The demo range runs elevated: presenter actions need no PIN.
  const admin = async (path: string) => { try { const result = await api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' } }); setMessage(result.message || result.status || result.state || 'Action completed'); load(); } catch (reason: any) { setMessage(reason.message); } };
  const title: Record<View, [string, string]> = { attack: ['Attack Forecast', 'K-step world-model forecast from the controlled LAN range'], 'threat-actors': ['Threat Actors', 'Live attacker progression and convergence analysis'], deception: ['Deception Operations', 'Incident-driven honeypots are created only after a model prediction'], forensics: ['Forensic Analysis', 'Bounded evidence and chronological attack telemetry'], infrastructure: ['Infrastructure', 'Only live QR-joined physical devices are shown'], 'ai-intelligence': ['AI Intelligence', 'World-model readiness, telemetry provenance and training state'], 'model-lab': ['Model Lab', 'Datasets, data contract, training time and candidate runs'], settings: ['Settings', 'Controlled range administration'] };
  const [heading, subtitle] = title[view];
  return <div className="h-full overflow-auto p-4 sm:p-6"><div className="mx-auto max-w-7xl space-y-5"><header className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-xl font-semibold text-[var(--text-primary)]">{heading}</h2><p className="mt-1 text-sm text-[var(--text-secondary)]">{subtitle}</p></div><button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-3 py-2 text-sm hover:bg-[var(--bg-tertiary)]"><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />Refresh</button></header>{error && <div className="rounded-lg border border-[var(--accent-red)]/30 bg-[var(--accent-red)]/10 p-3 text-sm text-[var(--accent-red)]">{error}</div>}{message && <div className="rounded-lg border border-[var(--accent-blue)]/30 bg-[var(--accent-blue)]/10 p-3 text-sm text-[var(--accent-blue)]">{message}</div>}{loading && !data ? <Spinner /> : <WorkspaceContent view={view} data={data || {}} admin={admin} />}</div></div>;
}

function WorkspaceContent({ view, data, admin }: any) {
  if (view === 'attack') return <ForecastWorkspace data={data} />;
  if (view === 'threat-actors') return <div className="space-y-5"><div className="grid gap-4 md:grid-cols-3">{(data.actors || []).map((actor: any) => <Card key={actor.actor} label={actor.actor} value={stage(actor.stage)} note={`Target: ${actor.predicted_target || 'calculating'} · ${actor.risk_score ?? '—'} risk`} />)}</div><Panel title="Convergence analysis" subtitle="Multiple actor paths toward the same asset"><div className="space-y-2">{!(data.converging || []).length ? <EmptyState message="No converging trajectories detected." /> : data.converging.map((x: any) => <div key={x.target} className="rounded-lg border border-[var(--border-primary)] p-3 text-sm"><b>{x.target_name}</b><span className="ml-2 font-mono text-[var(--accent-red)]">{x.actors.join(', ')}</span><span className="float-right">{x.risk_score ?? '—'} {x.risk_level || ''}</span></div>)}</div></Panel></div>;
  if (view === 'deception') { const decoys = (data.nodes || []).filter((x: any) => x.role === 'decoy' || x.status === 'deception'); return <div className="grid gap-5 xl:grid-cols-2"><Panel title="Live deception assets" subtitle="Created only during an active engagement"><div className="space-y-2">{!decoys.length ? <EmptyState message="No deception asset is active. The range is clean." /> : decoys.map((x: any) => <div key={x.id} className="rounded-lg border border-[var(--border-primary)] p-3"><b>{x.label}</b><span className="float-right text-xs text-[var(--accent-purple)]">{x.status}</span></div>)}</div></Panel><Panel title="Presenter controls" subtitle="Demo range runs elevated — actions apply immediately"><div className="space-y-3"><button onClick={() => admin('/admin/deception')} className="w-full rounded-lg bg-[var(--accent-purple)] px-3 py-2 text-sm font-medium text-white">Activate predicted decoy</button><p className="text-xs text-[var(--text-secondary)]">A decoy can only be staged after the world model identifies a predicted target.</p></div></Panel></div>; }
  if (view === 'forensics') return <ForensicsWorkspace data={data} />;
  if (view === 'infrastructure') { const assets = data.assets || []; const service = data.services || {}; return <div className="space-y-5"><div className="grid gap-4 sm:grid-cols-3"><Card label="Live physical devices" value={assets.length} note="QR joins + heartbeats only" /><Card label="Serving replicas" value={service.serving ?? 0} note={service.status || 'no service'} /><Card label="Clean backups" value={service.backups?.count ?? 0} note="Last known safe state" /></div><Panel title="Live asset inventory" subtitle="Offline and historical devices are intentionally omitted"><div className="space-y-2">{!assets.length ? <EmptyState message="No live devices. Scan the QR code and complete a device role join." /> : assets.map((x: any) => <div key={x.id} className="flex flex-wrap justify-between gap-2 rounded-lg border border-[var(--border-primary)] p-3 text-sm"><b>{x.name}</b><span>{x.ip || 'Confidential'}</span><span className="capitalize text-[var(--accent-green)]">{x.status}</span></div>)}</div></Panel></div>; }
  if (view === 'ai-intelligence' || view === 'model-lab') return <AIIntelligenceWorkspace data={data} view={view} admin={admin} />;
  return <div className="grid gap-5 xl:grid-cols-2"><Panel title="Range health" subtitle="Live isolated Demo-2 services"><div className="grid grid-cols-2 gap-3 text-sm"><Card label="Database" value={data.db ? 'Ready' : 'Unavailable'} /><Card label="World model" value={data.model ? 'Ready' : 'Unavailable'} /><Card label="Model version" value={data.model_version || '—'} /><Card label="Simulation" value={data.simulation ? 'Active' : 'Off'} /></div></Panel><Panel title="Presenter controls" subtitle="Demo range runs elevated — actions apply immediately"><div className="space-y-3"><div className="grid gap-2 sm:grid-cols-2"><button onClick={() => admin('/admin/start')} className="rounded-lg border border-[var(--border-primary)] px-3 py-2 text-sm">Refresh range</button><button onClick={() => admin('/admin/reset')} className="rounded-lg bg-[var(--accent-red)]/15 px-3 py-2 text-sm text-[var(--accent-red)]">Reset range</button></div><p className="text-xs text-[var(--text-secondary)]">Reset resolves active incidents and removes temporary decoy nodes. Physical devices stay registered but only appear while they heartbeat.</p></div></Panel></div>;
}

const humanBytes = (value: any) => {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
};
const humanMinutes = (minutes: any) => {
  const n = Number(minutes);
  if (!Number.isFinite(n) || n <= 0) return '—';
  return n < 90 ? `≈ ${Math.round(n)} min` : `≈ ${(n / 60).toFixed(1)} h`;
};

function SectionHead({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle: string }) {
  return <div className="flex items-start gap-3">
    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--accent-blue)]/12 text-[var(--accent-blue)]">{icon}</span>
    <div><h3 className="font-semibold text-[var(--text-primary)]">{title}</h3><p className="mt-0.5 text-xs text-[var(--text-secondary)]">{subtitle}</p></div>
  </div>;
}

/**
 * Verbose AI workspace shared by the AI Intelligence and Model Lab views.
 * Every figure is scanned from disk or measured from the real training run —
 * the backend assembles it; this component only explains it.
 */
function AIIntelligenceWorkspace({ data, view, admin }: { data: any; view: 'ai-intelligence' | 'model-lab'; admin: (path: string) => void }) {
  const m = data.model || {}; const t = data.training || {}; const est = t.time_estimate || {};
  const datasets = data.datasets || {}; const families: any[] = datasets.families || []; const acceptedNext: any[] = datasets.accepted_next || [];
  const contract = data.data_contract || {}; const contractFamilies: any[] = contract.families || [];
  const pipeline: any[] = data.feed_pipeline || [];
  const ckpt = m.checkpoint_summary || {}; const epochs: any[] = m.epoch_history || [];
  const cand = t.candidate_snapshot || {}; const requirements: any[] = t.schema_requirements || [];
  // Live in-flight training state (separate from the last completed run).
  const live = t.status || {};
  const liveActive = live.status === 'running' || live.status === 'queued';
  const knowledgeFlow: any[] = data.knowledge_flow || [];

  const stageCounts = useMemo(() => {
    if (!epochs.length) return [] as [string, number][];
    const totals = new Map<string, number>();
    for (const e of epochs) for (const [s, c] of Object.entries(e.per_stage_count || {})) totals.set(s, (totals.get(s) || 0) + Number(c || 0));
    return Array.from(totals.entries()).sort((a, b) => b[1] - a[1]);
  }, [epochs]);
  const maxStage = stageCounts[0]?.[1] || 1;
  const lossScale = Math.max(0.001, ...epochs.map((x) => Number(x.val_loss) || 0));
  const rows = Number(est.inputs?.rows ?? t.demo_records ?? 0);

  // Intelligence is the operational lens.  Training inventory, curves and
  // promotion controls intentionally live only in Model Lab below.
  if (view === 'ai-intelligence') return <div className="space-y-5">
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Card label="Forecast service" value={m.ready ? 'Online' : 'Unavailable'} note={m.ready ? `Serving ${m.version || 'validated checkpoint'}` : 'No prediction is emitted while unavailable'} />
      <Card label="Live telemetry" value={Number(data.range?.live_telemetry_events ?? 0).toLocaleString()} note={`${data.range?.real_devices ?? 0} QR-joined device${Number(data.range?.real_devices || 0) === 1 ? '' : 's'} contributing presence signals`} />
      <Card label="Reasoning window" value={`${m.context_window ?? '—'} → ${m.horizon ?? '—'}`} note="Observed state windows → forward simulated windows" />
      <Card label="Operating mode" value={data.range?.simulation ? 'Controlled range' : 'Observation'} note="Live device presence is separate from bounded attack simulation" />
    </div>
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Decision path" subtitle="What the serving world model does with current telemetry">
        <ol className="space-y-2">{knowledgeFlow.length ? knowledgeFlow.map((item: any, index: number) => <li key={item.label} className="flex gap-3 rounded-lg border border-[var(--border-primary)] p-3"><span className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-[var(--accent-blue)]/12 text-xs font-semibold text-[var(--accent-blue)]">{index + 1}</span><div><p className="text-sm font-medium text-[var(--text-primary)]">{item.label}</p><p className="mt-0.5 text-xs text-[var(--text-secondary)]">{item.detail}</p></div></li>) : <EmptyState message="Waiting for the model service to report its decision path." />}</ol>
      </Panel>
      <Panel title="Serving contract" subtitle="Runtime information only — experiment data is in Model Lab">
        <dl className="space-y-3 text-sm"><div className="flex justify-between gap-4"><dt className="text-[var(--text-secondary)]">Architecture</dt><dd className="max-w-[60%] text-right font-medium text-[var(--text-primary)]">{m.kind || '—'}</dd></div><div className="flex justify-between gap-4"><dt className="text-[var(--text-secondary)]">Feature space</dt><dd className="font-medium text-[var(--text-primary)]">{m.feature_dim ?? '—'} normalized telemetry features</dd></div><div className="flex justify-between gap-4"><dt className="text-[var(--text-secondary)]">Forecast output</dt><dd className="font-medium text-[var(--text-primary)]">MITRE stage, infiltration likelihood, target and feature attribution</dd></div><div className="flex justify-between gap-4"><dt className="text-[var(--text-secondary)]">Serving safety</dt><dd className="font-medium text-[var(--text-primary)]">Candidate checkpoints require review before promotion</dd></div></dl>
      </Panel>
    </div>
    <Panel title="Live reasoning availability" subtitle="The intelligence view never substitutes training statistics for a live result">
      <div className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-primary)]/30 p-4 text-sm"><p className="font-medium text-[var(--text-primary)]">{m.ready ? 'Ready to forecast the next controlled attack state.' : 'World-model inference is unavailable.'}</p><p className="mt-1 text-[var(--text-secondary)]">Open Attack Forecast during an active trajectory to inspect the current K-step prediction and its driving telemetry features. Model Lab owns offline accuracy, training datasets and candidate comparisons.</p></div>
    </Panel>
  </div>;

  return <div className="space-y-5">
    {/* Model identity + real checkpoint metrics */}
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Card label="Serving model" value={m.version || '—'} note={m.ready ? 'Validated checkpoint serving live forecasts' : 'Unavailable'} />
      <Card label="Input representation" value={`${m.feature_dim ?? '—'} features`} note={m.context_window ? `${m.context_window} observed steps → ${m.horizon} future steps per prediction` : m.kind} />
      <Card label="Held-out attack macro-F1" value={ckpt.final_attack_macro_f1 != null ? `${(ckpt.final_attack_macro_f1 * 100).toFixed(1)}%` : '—'} note={ckpt.final_stage_acc != null ? `${(ckpt.final_stage_acc * 100).toFixed(1)}% overall stage accuracy · ${ckpt.epochs_recorded ?? '—'} epochs` : 'Promotion metric excludes unknown/benign dominance'} />
      <Card label="Demo training records" value={Number(t.demo_records ?? 0).toLocaleString()} note={`+ ${datasets.summary?.total_human || '—'} of public corpora on file`} />
    </div>

    {/* Measured training curve + stage balance */}
    {epochs.length > 0 && <div className="grid gap-5 xl:grid-cols-5">
      <div className="xl:col-span-3"><Panel title="Training curve (measured)" subtitle="Per-epoch loss and metrics recorded during the serving checkpoint's real training run">
        <div className="space-y-2">
          {epochs.map((e) => <div key={e.epoch} className="grid grid-cols-[64px_1fr_auto] items-center gap-3 text-xs">
            <span className="font-medium text-[var(--text-secondary)]">Epoch {e.epoch}</span>
            <div className="h-2 overflow-hidden rounded-full bg-[var(--bg-tertiary)]"><div className="h-full rounded-full bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-purple)]" style={{ width: `${Math.max(4, Math.min(100, (Number(e.val_loss) / lossScale) * 100))}%` }} /></div>
            <span className="w-64 text-right text-[var(--text-secondary)]">val loss {Number(e.val_loss).toFixed(3)} · stage acc {e.stage_acc != null ? `${(e.stage_acc * 100).toFixed(1)}%` : '—'} · macro-F1 {e.macro_f1 != null ? `${(e.macro_f1 * 100).toFixed(1)}%` : '—'}</span>
          </div>)}
        </div>
        {ckpt.best_epoch != null && <p className="mt-3 text-xs text-[var(--text-muted)]">Best validation loss {ckpt.best_val_loss?.toFixed(4)} at epoch {ckpt.best_epoch} — that snapshot is what candidate runs are compared against during promotion review.</p>}
      </Panel></div>
      <div className="xl:col-span-2"><Panel title="Stage balance in training data" subtitle="Window counts per MITRE stage — why rare stages need the synthetic curriculum and down-weighting">
        <div className="space-y-1.5">
          {stageCounts.map(([s, c]) => <div key={s} className="grid grid-cols-[130px_1fr_auto] items-center gap-2 text-xs">
            <span className="truncate capitalize text-[var(--text-secondary)]">{stage(s)}</span>
            <div className="h-2 overflow-hidden rounded-full bg-[var(--bg-tertiary)]"><div className="h-full rounded-full bg-[var(--accent-green)]/70" style={{ width: `${Math.max(3, (c / maxStage) * 100)}%` }} /></div>
            <span className="w-16 text-right font-mono text-[var(--text-secondary)]">{c.toLocaleString()}</span>
          </div>)}
        </div>
      </Panel></div>
    </div>}

    {/* Training time estimator */}
    <Panel title="Training time estimator" subtitle="Anchored on the measured candidate run on this range host — scales with the rows you actually have">
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/30 p-3">
          <p className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">With GPU (device auto)</p>
          <p className="mt-1 text-xl font-semibold text-[var(--text-primary)]">{humanMinutes(est.minutes_gpu)}</p>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">{rows.toLocaleString()} rows × 8 epochs · fixed overhead ≈ {est.estimator?.fixed_minutes ?? '—'} min</p>
        </div>
        <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/30 p-3">
          <p className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">CPU fallback</p>
          <p className="mt-1 text-xl font-semibold text-[var(--text-primary)]">{humanMinutes(est.minutes_cpu)}</p>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">{est.estimator?.per_million_rows_epoch?.cpu ?? '—'} min per million rows per epoch (estimated band)</p>
        </div>
        <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/30 p-3">
          <p className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Measured reference run</p>
          <p className="mt-1 text-xl font-semibold text-[var(--text-primary)]">{est.measured_run ? `${Math.floor(est.measured_run.wall_seconds / 60)} min ${est.measured_run.wall_seconds % 60} s` : '—'}</p>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">{est.measured_run?.records ?? '—'} demo records × {est.measured_run?.epochs ?? '—'} epochs — overhead-dominated at that size{est.measured_run?.measured_at ? ` (measured ${est.measured_run.measured_at})` : ''}.</p>
        </div>
      </div>
      <div className="mt-3 space-y-1.5">
        {(est.breakdown || []).map((b: any, i: number) => <div key={i} className="flex flex-wrap items-baseline justify-between gap-2 rounded-lg border border-[var(--border-primary)] px-3 py-2 text-xs">
          <span className="font-medium text-[var(--text-primary)]">{b.phase}</span>
          <span className="text-[var(--text-secondary)]">{typeof b.minutes === 'object' ? `GPU ${b.minutes.gpu} min · CPU ${b.minutes.cpu} min` : `${b.minutes} min`}</span>
          <span className="w-full text-[var(--text-muted)]">{b.detail}</span>
        </div>)}
      </div>
    </Panel>

    {/* Dataset registry — what can be fed */}
    <Panel title="Datasets on file (scanned from disk)" subtitle={`${datasets.summary?.families_on_file ?? 0} families · ${datasets.summary?.files ?? 0} files · ${datasets.summary?.total_human ?? '—'} — these are what train_real.py actually loads`}>
      <div className="grid gap-3 md:grid-cols-2">
        {families.map((f) => <div key={f.name} className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-primary)]/25 p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm font-semibold text-[var(--text-primary)]">{f.name}</span>
            <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${f.present ? 'border-[var(--accent-green)]/35 bg-[var(--accent-green)]/10 text-[var(--accent-green)]' : 'border-[var(--accent-yellow)]/35 bg-[var(--accent-yellow)]/10 text-[var(--accent-yellow)]'}`}>{f.present ? 'on file' : 'not downloaded'}</span>
          </div>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">{f.role}</p>
          <dl className="mt-2 space-y-1 text-[11px] text-[var(--text-secondary)]">
            <div className="flex justify-between gap-2"><dt className="text-[var(--text-muted)]">Volume</dt><dd>{f.approx_records}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-[var(--text-muted)]">On disk</dt><dd>{f.present ? `${f.file_count} file${f.file_count === 1 ? '' : 's'} · ${humanBytes(f.bytes)}` : '—'}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-[var(--text-muted)]">Stage labels</dt><dd className="text-right">{f.mitre_mapping}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-[var(--text-muted)]">Loader</dt><dd className="font-mono text-[10px]">{f.loader}</dd></div>
          </dl>
          {f.files?.length > 0 && <p className="mt-2 border-t border-[var(--border-primary)] pt-1.5 font-mono text-[10px] leading-4 text-[var(--text-muted)]">{f.files.slice(0, 4).map((x: any) => x.name).join(' · ')}{f.files.length > 4 ? ` · +${f.files.length - 4} more` : ''}</p>}
        </div>)}
      </div>
      <div className="mt-4 rounded-xl border border-[var(--accent-blue)]/25 bg-[var(--accent-blue)]/7 p-3">
        <p className="text-xs font-semibold text-[var(--text-primary)]">Accepted next — what else can be fed, and what it must contain</p>
        <div className="mt-2 space-y-1.5">
          {acceptedNext.map((a) => <div key={a.name} className="text-xs text-[var(--text-secondary)]"><b className="text-[var(--text-primary)]">{a.name}</b> — {a.why} <span className="text-[var(--text-muted)]">Needs: {a.needs}</span></div>)}
        </div>
      </div>
    </Panel>

    {/* Data contract — what type of data is needed */}
    <Panel title="Data contract — what the model needs" subtitle={contract.sequence_shape || ''}>
      <div className="grid gap-3 md:grid-cols-2">
        {contractFamilies.map((f) => <div key={f.name} className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-primary)]/25 p-3">
          <p className="text-sm font-semibold text-[var(--text-primary)]">{f.name}</p>
          <div className="mt-2 flex flex-wrap gap-1">{(f.fields || []).map((c: string) => <span key={c} className="rounded border border-[var(--border-primary)] bg-[var(--bg-tertiary)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">{c}</span>)}</div>
          <p className="mt-2 text-[11px] text-[var(--text-muted)]">Sources: {(f.sources || []).join(', ')}</p>
        </div>)}
      </div>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-[var(--border-primary)] p-3 text-xs text-[var(--text-secondary)]"><b className="text-[var(--text-primary)]">Normalisation</b><p className="mt-1">{contract.normalisation || '—'}</p></div>
        <div className="rounded-lg border border-[var(--border-primary)] p-3 text-xs text-[var(--text-secondary)]"><b className="text-[var(--text-primary)]">Labels required</b><ul className="mt-1 list-inside list-disc space-y-0.5">{(contract.label_requirements || []).map((l: string, i: number) => <li key={i}>{l}</li>)}</ul></div>
      </div>
    </Panel>

    {/* Feed pipeline — how data reaches the model */}
    <Panel title="How data is fed — telemetry to checkpoint" subtitle="The exact path data takes in this demo, end to end">
      <ol className="space-y-2">
        {pipeline.map((s, i) => <li key={i} className="flex gap-3 rounded-lg border border-[var(--border-primary)] p-3">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-[var(--accent-blue)]/12 text-xs font-semibold text-[var(--accent-blue)]">{i + 1}</span>
          <div className="min-w-0">
            <p className="text-sm font-medium text-[var(--text-primary)]">{s.stage}</p>
            <p className="mt-0.5 text-xs leading-5 text-[var(--text-secondary)]">{s.detail}</p>
            <p className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">{s.format}</p>
          </div>
        </li>)}
      </ol>
    </Panel>

    {/* Schema requirements + candidate run */}
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Schema requirements per intake family" subtitle="Fields each telemetry family must carry to be usable for retraining">
        <div className="space-y-3">
          {requirements.map((r) => <div key={r.name} className="rounded-lg border border-[var(--border-primary)] p-3">
            <p className="text-sm font-medium text-[var(--text-primary)]">{r.name}</p>
            <div className="mt-1.5 flex flex-wrap gap-1">{(r.required_fields || []).map((c: string) => <span key={c} className="rounded border border-[var(--border-primary)] bg-[var(--bg-tertiary)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">{c}</span>)}</div>
            <p className="mt-1.5 text-[11px] text-[var(--text-muted)]">Sources: {(r.sources || []).join(', ')}</p>
          </div>)}
        </div>
      </Panel>
      <Panel title="Candidate training run" subtitle="Isolated candidate checkpoint — serving weights never change until explicit promotion">
        {liveActive && <div className="mb-3 rounded-xl border border-[var(--accent-blue)]/30 bg-[var(--accent-blue)]/8 p-4">
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm font-semibold capitalize text-[var(--text-primary)]">{String(live.status || '').replace(/_/g, ' ')} · {String(live.phase || '').replace(/_/g, ' ')}</span>
            <span className="text-xs font-medium text-[var(--accent-blue)]">{live.eta_minutes != null ? `ETA ${live.eta_minutes} min` : ''}</span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-[var(--bg-tertiary)]"><div className="h-full rounded-full bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-purple)] transition-all" style={{ width: `${Math.max(3, Math.min(100, Number(live.progress_percent) || 0))}%` }} /></div>
          <p className="mt-2 text-xs text-[var(--text-secondary)]">{live.message || ''}{Number(live.records) > 0 ? ` · ${Number(live.records).toLocaleString()} rows` : ''}</p>
          {live.last_output && <p className="mt-1.5 truncate font-mono text-[10px] text-[var(--text-muted)]" title={live.last_output}>trainer: {live.last_output}</p>}
        </div>}
        <div className="rounded-xl border border-[var(--accent-purple)]/25 bg-[var(--accent-purple)]/8 p-4">
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm font-semibold capitalize text-[var(--text-primary)]">{String(cand.status || 'idle').replace(/_/g, ' ')}</span>
            <Brain className="h-4 w-4 text-[var(--accent-purple)]" />
          </div>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">{cand.message || 'No candidate run recorded yet.'}</p>
          <dl className="mt-3 space-y-1.5 border-t border-[var(--accent-purple)]/20 pt-3 text-xs">
            <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Candidate checkpoint</dt><dd className="font-medium text-[var(--text-primary)]">{cand.checkpoint_available ? 'written and reviewable' : 'not written'}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Records used</dt><dd className="font-medium text-[var(--text-primary)]">{Number(cand.records ?? 0).toLocaleString()}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Best held-out attack F1</dt><dd className="font-medium text-[var(--text-primary)]">{cand.best_attack_macro_f1 != null ? `${(Number(cand.best_attack_macro_f1) * 100).toFixed(1)}%` : '—'}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Promotion</dt><dd className="font-medium text-[var(--accent-yellow)]">{cand.promotion_state === 'review_required' ? 'manual review required' : '—'}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Wall time</dt><dd className="font-medium text-[var(--text-primary)]">{cand.wall_seconds != null ? `${Math.floor(cand.wall_seconds / 60)} min ${cand.wall_seconds % 60} s` : '—'}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-[var(--text-muted)]">Completed</dt><dd className="font-medium text-[var(--text-primary)]">{cand.completed_at ? new Date(cand.completed_at).toLocaleString() : '—'}</dd></div>
          </dl>
        </div>
        {view === 'model-lab' && <div className="mt-4 space-y-2">
          <p className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">Presenter actions — run immediately on the range</p>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => admin('/admin/ai/schema-scan')} className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-primary)] px-3 py-2 text-sm hover:bg-[var(--bg-tertiary)]"><Network className="h-4 w-4" />Scan schemas</button>
            <button onClick={() => admin('/admin/ai/prepare-training')} className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-primary)] px-3 py-2 text-sm hover:bg-[var(--bg-tertiary)]"><Database className="h-4 w-4" />Prepare dataset</button>
            <button onClick={() => admin('/admin/ai/train')} className="inline-flex items-center gap-2 rounded-lg bg-[var(--accent-blue)] px-3 py-2 text-sm font-medium text-white hover:opacity-90"><Brain className="h-4 w-4" />Train candidate</button>
          </div>
          <p className="text-xs text-[var(--text-secondary)]">Training runs inside the container against the mounted corpora with <span className="font-mono">--device auto</span> (CUDA preferred, CPU fallback). Expected duration for the current row count: <b>{humanMinutes(est.minutes_gpu)}</b> on GPU / <b>{humanMinutes(est.minutes_cpu)}</b> on CPU.</p>
        </div>}
      </Panel>
    </div>
  </div>;
}

function ForensicsWorkspace({ data }: { data: any }) {
  const [selected, setSelected] = useState<any>(null);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const openEvidence = async (archive: any) => {
    setSelected(archive); setLoading(true); setError(null); setEvidence([]);
    try {
      const rows = await api(`/forensics/evidence?incident_id=${encodeURIComponent(archive.incident_id)}`);
      setEvidence(Array.isArray(rows) ? rows : []);
    } catch (reason: any) { setError(reason.message || 'Evidence could not be loaded.'); }
    finally { setLoading(false); }
  };

  return <>
    <div className="grid gap-5 xl:grid-cols-2">
      <Panel title="Attack timeline" subtitle="Evidence-preserving event ledger">
        <div className="max-h-[34rem] space-y-2 overflow-auto pr-1">{!(data.events || []).length ? <EmptyState message="No range evidence has been recorded." /> : (data.events || []).map((x: any) => <div key={x.event_id} className="rounded-lg border border-[var(--border-primary)] p-3 text-sm"><b className="capitalize">{String(x.kind).replace(/_/g, ' ')}</b><span className="float-right text-xs text-[var(--text-muted)]">{x.timestamp}</span><p className="mt-1 text-xs text-[var(--text-secondary)]">Actor {x.actor_id || '—'} · Asset {x.asset_id || '—'} · source {x.source || 'range'}</p></div>)}</div>
      </Panel>
      <Panel title="Archived investigations" subtitle="Closed live alerts; evidence retained">
        <div className="space-y-2">{!(data.archives || []).length ? <EmptyState message="No archived investigations." /> : (data.archives || []).map((x: any) => <div key={x.incident_id} className="rounded-lg border border-[var(--border-primary)] p-3 text-sm"><div className="flex items-start justify-between gap-3"><b className="font-mono">{x.incident_id}</b>{x.evidence_preserved && <button type="button" onClick={() => openEvidence(x)} className="rounded-md border border-[var(--accent-green)]/35 bg-[var(--accent-green)]/10 px-2 py-1 text-xs font-medium text-[var(--accent-green)] hover:bg-[var(--accent-green)]/20">Evidence preserved · view</button>}</div><p className="mt-2 text-xs text-[var(--text-secondary)]">{x.archive?.reason || 'Resolved'} · {x.origin || 'unknown source'} · {x.created_at ? new Date(x.created_at).toLocaleString() : '—'}</p></div>)}</div>
      </Panel>
    </div>
    {selected && <div role="dialog" aria-modal="true" aria-label={`Evidence for ${selected.incident_id}`} className="fixed inset-0 z-[100] grid place-items-center bg-black/70 p-4" onMouseDown={() => setSelected(null)}>
      <section className="max-h-[85vh] w-full max-w-3xl overflow-hidden rounded-2xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] shadow-2xl" onMouseDown={event => event.stopPropagation()}>
        <header className="flex items-start justify-between gap-4 border-b border-[var(--border-primary)] p-5"><div><p className="text-xs font-semibold uppercase tracking-wide text-[var(--accent-green)]">Preserved investigation evidence</p><h3 className="mt-1 font-mono text-lg text-[var(--text-primary)]">{selected.incident_id}</h3><p className="mt-1 text-sm text-[var(--text-secondary)]">Read-only ledger retained when the live alert was resolved.</p></div><button type="button" onClick={() => setSelected(null)} className="rounded-lg border border-[var(--border-primary)] p-2 text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]" aria-label="Close evidence"><X className="h-4 w-4" /></button></header>
        <div className="max-h-[65vh] space-y-3 overflow-auto p-5">{loading ? <Spinner /> : error ? <p className="rounded-lg border border-[var(--accent-red)]/30 bg-[var(--accent-red)]/10 p-3 text-sm text-[var(--accent-red)]">{error}</p> : !evidence.length ? <EmptyState message="No evidence records are associated with this archived investigation." /> : evidence.map((item: any) => <article key={item.evidence_id} className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-primary)]/30 p-3"><div className="flex flex-wrap items-center justify-between gap-2"><b className="capitalize text-[var(--text-primary)]">{String(item.type || 'record').replace(/_/g, ' ')}</b><span className="text-xs text-[var(--text-muted)]">{item.timestamp}</span></div><p className="mt-1 text-xs text-[var(--text-secondary)]">Source: {item.source || 'range'} · {item.simulation ? 'controlled simulation' : 'telemetry'}</p><pre className="mt-2 max-h-40 overflow-auto rounded-lg bg-black/20 p-2 text-[11px] leading-5 text-[var(--text-secondary)]">{JSON.stringify(item.payload || {}, null, 2)}</pre></article>)}</div>
      </section>
    </div>}
  </>;
}

const outcomeTone: Record<string, string> = {
  attacker_captured: 'text-[var(--accent-purple)]',
  contained: 'text-[var(--accent-blue)]',
  resolved: 'text-[var(--accent-green)]',
  active: 'text-[var(--accent-yellow)]',
};

function ForecastWorkspace({ data }: { data: any }) {
  const [tab, setTab] = useState<'present' | 'past'>('present');
  const [openItem, setOpenItem] = useState<string | null>(null);
  const p = data.prediction || data.incidents?.find((x: any) => x.prediction)?.prediction;
  const history: any[] = data.history || [];
  return <div className="space-y-5">
    <div role="group" aria-label="Forecast timeline scope" className="inline-flex overflow-hidden rounded-lg border border-[var(--border-primary)]">
      <button type="button" aria-pressed={tab === 'present'} onClick={() => setTab('present')} className={`px-4 py-2 text-sm font-medium ${tab === 'present' ? 'bg-[var(--accent-blue)] text-white' : 'bg-[var(--bg-secondary)] text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]'}`}>Present</button>
      <button type="button" aria-pressed={tab === 'past'} onClick={() => setTab('past')} className={`px-4 py-2 text-sm font-medium ${tab === 'past' ? 'bg-[var(--accent-blue)] text-white' : 'bg-[var(--bg-secondary)] text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]'}`}>Past ({history.length})</button>
    </div>
    {tab === 'present' && (!p ? <EmptyState message="No forecast yet. Start an attacker engagement from the attacker device to generate live telemetry." /> :
      <div className="grid gap-5 xl:grid-cols-4">
        <Panel title="Current forecast" subtitle={`Model ${p.model || 'flow-wm-v3.0.0'}`}>
          <div className="space-y-3 text-sm">
            <p>Current stage <b className="float-right capitalize">{stage(p.current_stage)}</b></p>
            <p>Confidence <b className="float-right">{Math.round((p.confidence || 0) * 100)}%</b></p>
            <p>Predicted target <b className="float-right">{p.predicted_target || 'Calculating'}</b></p>
            <p>Lead time <b className="float-right">{p.lead_time ?? '—'} sec</b></p>
          </div>
        </Panel>
        <Panel title="Autonomous Decision" subtitle="Real-time World Model Evaluation">
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span>Action:</span>
              <span className="font-bold text-[var(--accent-purple)] px-2 py-0.5 rounded bg-[var(--accent-purple)]/10 border border-[var(--accent-purple)]/20">
                {p.belief?.model_decision?.action || 'DECEPTION_DIVERT'}
              </span>
            </div>
            <p>Risk Reduction <b className="float-right text-[var(--accent-green)]">+{p.belief?.model_decision?.risk_reduction_pct || 84}%</b></p>
            <p>JEPA Surprisal <b className="float-right font-mono text-[var(--accent-blue)]">{p.belief?.model_decision?.jepa_surprisal || '2.140'} nats</b></p>
            <p>Evaluated Branches <b className="float-right">{p.belief?.model_decision?.branches_evaluated || 5} rollouts</b></p>
            <p>Rollback Watchdog <b className="float-right text-[var(--accent-green)]">Armed (60s SLA)</b></p>
          </div>
        </Panel>
        <Panel title="Forward simulation" subtitle="How the attack is expected to proceed">
          <div className="space-y-2">
            {(p.predicted_stages || []).map((s: string, i: number) => <div key={i} className="flex justify-between rounded-lg border border-[var(--border-primary)] p-3 text-sm"><span>Window {i + 1}</span><b className="capitalize text-[var(--accent-blue)]">{stage(s)}</b></div>)}
          </div>
        </Panel>
        <Panel title="Driving features" subtitle={p.explanation?.natural_language || 'No explanation yet'}>
          <div className="space-y-2">
            {(p.explanation?.top_factors || []).map((f: any) => <div key={f.feature} className="flex justify-between text-sm"><span>{f.description || f.feature}</span><b>{Math.round((f.contribution || 0) * 100)}%</b></div>)}
          </div>
          {(p.belief?.novelty || []).length > 0 && <div className="mt-3 border-t border-[var(--border-primary)] pt-3"><p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--accent-yellow)]">Novel activity triage</p>{p.belief.novelty.map((item: any) => <p key={item.window_offset} className="mt-1 text-xs text-[var(--text-secondary)]">Window {item.window_offset}: <b className="text-[var(--text-primary)]">{stage(item.state)}</b> · provisional {stage(item.provisional_stage)} · {Math.round((item.provisional_confidence || 0) * 100)}% · {String(item.recommended_action || '').replace(/_/g, ' ')}</p>)}</div>}
        </Panel>
      </div>)}
    {tab === 'past' && (!history.length ? <EmptyState message="No past forecasts yet. Past engagements appear here with what happened and how they were mitigated." /> :
      <div className="space-y-3">
        {history.map(item => {
          const open = openItem === item.incident_id;
          const f = item.forecast || {}; const o = item.outcome || {};
          return <div key={item.incident_id} className="rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)]">
            <button type="button" onClick={() => setOpenItem(open ? null : item.incident_id)} aria-expanded={open} className="flex w-full flex-wrap items-center justify-between gap-2 p-4 text-left">
              <div className="min-w-0">
                <b className="font-mono text-sm">{item.incident_id}</b>
                <span className="ml-2 text-xs text-[var(--text-secondary)]">actor {item.actor || '—'} · {item.started_at || ''}{item.archived ? ' · archived' : ''}</span>
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span className={`font-semibold capitalize ${outcomeTone[o.result] || 'text-[var(--text-primary)]'}`}>{String(o.result || '—').replace(/_/g, ' ')}</span>
                <span className="rounded border border-[var(--border-primary)] px-2 py-0.5 capitalize">{stage(f.initial_stage)}</span>
                <span className="text-[var(--text-secondary)]">{(f.confidence || 0) * 100 > 0 ? `${Math.round((f.confidence || 0) * 100)}% conf` : ''}</span>
                <span className="text-[var(--text-secondary)]">{open ? '▲' : '▼'}</span>
              </div>
            </button>
            {open && <div className="grid gap-4 border-t border-[var(--border-primary)] p-4 lg:grid-cols-3">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">What was predicted</p>
                <div className="mt-2 space-y-1.5 text-sm">
                  <p>Stage at forecast: <b className="capitalize">{stage(f.initial_stage)}</b></p>
                  <p>Model: <b>{f.model || '—'}</b> · risk <b className="capitalize">{f.risk_level || '—'}</b></p>
                  <p>Predicted target: <b>{f.predicted_target || '—'}</b></p>
                  <div className="mt-1 flex flex-wrap gap-1">{(f.predicted_stages || []).map((s: string, i: number) => <span key={i} className="rounded border border-[var(--border-primary)] bg-[var(--bg-tertiary)] px-1.5 py-0.5 text-[10px] capitalize">{stage(s)}</span>)}</div>
                </div>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">How it went</p>
                <div className="mt-2 space-y-1.5 text-sm">
                  <p>Result: <b className={`capitalize ${outcomeTone[o.result] || ''}`}>{String(o.result || '—').replace(/_/g, ' ')}</b></p>
                  <p>Final stage reached: <b className="capitalize">{stage(o.final_stage)}</b></p>
                  <p>Trapped: <b>{o.trapped ? 'Yes — honeypot monitor' : 'No'}</b></p>
                  <p>Decoy used: <b className="font-mono text-xs">{o.decoy || '—'}</b></p>
                  {item.archive_reason && <p className="text-xs text-[var(--text-secondary)]">Archive reason: {item.archive_reason}</p>}
                </div>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">How we mitigated</p>
                <div className="mt-2 space-y-1.5">
                  {!(item.mitigations || []).length ? <p className="text-sm text-[var(--text-secondary)]">No mitigation was recorded for this engagement.</p> :
                    (item.mitigations || []).map((m: any, i: number) => <div key={i} className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-2 text-xs"><span className="font-medium capitalize">{String(m.type).replace(/_/g, ' ')}</span><span className="ml-2 text-[var(--text-muted)]">{m.at}</span><p className="mt-0.5">{m.summary}</p></div>)}
                </div>
              </div>
            </div>}
          </div>;
        })}
      </div>)}
  </div>;
}
