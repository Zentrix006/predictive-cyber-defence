"use client";

import { useEffect, useState } from 'react';
import { ShieldAlert, RotateCcw, CheckCircle2, Circle } from 'lucide-react';
import { demoApiBase } from '@/lib/demo-api';

/**
 * Presenter narrative rail — mirrors the guided attacker flow
 * (recon → foothold → model forecast → decoy → lateral movement →
 * honeynet capture → containment → maintenance/restore).
 */
const STAGES: { id: string; label: string; explain: string }[] = [
  { id: 'recon', label: 'Recon', explain: 'Attacker joins and selects a live physical target.' },
  { id: 'foothold', label: 'Foothold', explain: 'Challenge handshake confirms the intrusion on the origin device.' },
  { id: 'forecast', label: 'Model forecast', explain: 'World model predicts the next ATT&CK stage and target host.' },
  { id: 'decoy', label: 'Decoy staged', explain: 'A decoy twin of the predicted target is minted into the honeynet.' },
  { id: 'lateral', label: 'Lateral movement', explain: 'Attacker pivots; reachable hosts collapse to the decoy farm.' },
  { id: 'honeynet', label: 'Honeynet capture', explain: 'Every pivot inside the honeynet is recorded as attribution evidence.' },
  { id: 'containment', label: 'Containment', explain: 'Origin is isolated; production traffic fails over to replicas.' },
  { id: 'maintenance', label: 'Restore', explain: 'Clean-backup diagnostics and restore run in the maintenance zone.' },
];

/** Map a live incident to which narrative stages have been reached. */
function stageProgress(inc: any): Record<string, boolean> {
  const level = Number(inc?.level || 0);
  const stage = String(inc?.stage || '');
  const trapped = Boolean(inc?.trapped);
  const monitoring = Boolean(inc?.monitoring);
  return {
    recon: Boolean(inc),
    foothold: level >= 1,
    forecast: Boolean(inc?.predicted_target),
    decoy: Boolean(inc?.decoy) || Boolean(inc?.deception_active),
    lateral: level >= 5 || Number(inc?.pivot_count || 0) > 0,
    honeynet: trapped || monitoring,
    containment: ['contained', 'resolved'].includes(String(inc?.status)) || trapped,
    maintenance: stage === 'maintenance' || ['restored', 'resolved'].includes(String(inc?.status)),
  };
}

export function ActorIntelPanel() {
  const [actors, setActors] = useState<any[]>([]);
  const [actor, setActor] = useState('');
  const [intel, setIntel] = useState<any>(null);
  const [dossier, setDossier] = useState<any>(null);
  const [overview, setOverview] = useState<any>(null);
  const [message, setMessage] = useState('Demo range runs elevated — actor intelligence is unlocked.');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetch(`${demoApiBase()}/command/overview`).then(r => r.json());
        const next = data.actors || [];
        setActors(next);
        setOverview(data);
        setActor((current: string) => {
          if (current) return current;
          if (next[0]?.actor) void reveal(next[0].actor);
          return next[0]?.actor || '';
        });
      } catch {
        setMessage('Attacker telemetry is unavailable.');
      }
    };
    load();
    const id = window.setInterval(load, 5000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const reveal = async (who?: string) => {
    const target = who || actor;
    if (!target) return;
    try {
      const [intelRes, dossierRes] = await Promise.all([
        fetch(`${demoApiBase()}/admin/attacker-intelligence/${encodeURIComponent(target)}`),
        fetch(`${demoApiBase()}/admin/attacker-dossier/${encodeURIComponent(target)}`)
          .catch(() => null),
      ]);
      const data = await intelRes.json();
      if (!intelRes.ok) throw new Error(data.detail || 'Unable to unlock intelligence.');
      setIntel(data);
      if (dossierRes && dossierRes.ok) {
        setDossier(await dossierRes.json());
      } else {
        setDossier(null);
      }
      setMessage('Crucial evidence dossier and live action trace.');
    } catch (error: any) {
      setIntel(null);
      setDossier(null);
      setMessage(error?.message || 'Unable to unlock intelligence.');
    }
  };

  const resetRange = async () => {
    setBusy(true);
    try {
      const response = await fetch(`${demoApiBase()}/admin/reset`, { method: 'POST' });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || 'Reset was rejected.');
      setMessage('Range reset — devices stay registered, temporary deception assets removed.');
      setIntel(null);
    } catch (error: any) {
      setMessage(error?.message || 'Reset failed.');
    } finally {
      setBusy(false);
    }
  };

  const entries = intel ? (Object.entries(intel.identity || {}) as [string, any][]) : [];
  const readiness = overview?.readiness || null;
  const readinessOk = Boolean(readiness?.ready);
  const incidents: any[] = overview?.incidents || [];
  const activeIncident = incidents[0] || null;
  const progress = stageProgress(activeIncident);
  const currentIdx = (() => {
    for (let i = STAGES.length - 1; i >= 0; i -= 1) {
      if (progress[STAGES[i].id]) return i;
    }
    return -1;
  })();

  // Why a stage cannot start yet — surfaced instead of a silently empty screen.
  const blockedReason = (() => {
    if (!readiness) return 'Waiting for the demo range…';
    const devices = Number(readiness.physical_devices || 0);
    const servers = Number(readiness.servers || 0);
    const attackers = Number(readiness.attackers || 0);
    if (devices < 2) return 'Waiting for devices: at least two physical devices must be QR-joined and heartbeating.';
    if (servers < 1) return 'No server on the range yet — one joined device must use the server role.';
    if (!attackers && !activeIncident) return 'No attacker joined yet — open /attacker from the join page to begin recon.';
    return null;
  })();

  return (
    <section className="h-full overflow-auto bg-[var(--bg-secondary)] p-4">
      <div className="flex items-start gap-2">
        <span className="mt-0.5 rounded-lg bg-[var(--accent-red)]/10 p-2 text-[var(--accent-red)]">
          <ShieldAlert className="h-4 w-4" />
        </span>
        <div className="min-w-0">
          <h3 className="font-bold text-xs uppercase tracking-wider text-[var(--text-primary)]">Demo Stage — Engagement Control</h3>
          <p className="text-[11px] text-[var(--text-secondary)]">{message}</p>
        </div>
      </div>

      {/* Readiness gate with explicit, per-requirement explanations */}
      <div className={`mt-2.5 rounded-lg border p-2.5 text-xs ${readinessOk ? 'border-[var(--accent-green)]/40 bg-[var(--accent-green)]/10 text-emerald-700 dark:text-[var(--accent-green)]' : 'border-[var(--accent-yellow)]/40 bg-[var(--accent-yellow)]/10 text-amber-700 dark:text-[var(--accent-yellow)]'}`}>
        <p className="font-bold text-[var(--text-primary)]">{readinessOk ? 'Lateral-movement range ready' : 'Range readiness required'}</p>
        <p className="mt-0.5 text-[11px] text-[var(--text-secondary)]">
          {readiness?.physical_devices || 0} physical devices · {readiness?.servers || 0} server · {readiness?.attackers || 0} attacker
        </p>
        <p className="mt-0.5 text-[11px] text-[var(--text-secondary)]">
          {readinessOk
            ? 'Open /attacker to begin the guided scenario.'
            : blockedReason || readiness?.requirement || 'Waiting for live roles.'}
        </p>
      </div>

      {/* Stage narrative rail: done → green, current → amber, future → muted */}
      <ol className="mt-2.5 grid grid-cols-2 gap-1.5 text-[11px] sm:grid-cols-4">
        {STAGES.map((stage, index) => {
          const done = progress[stage.id];
          const isCurrent = index === currentIdx && !progress[STAGES[Math.min(index + 1, STAGES.length - 1)].id];
          return (
            <li
              key={stage.id}
              title={stage.explain}
              className={`rounded-lg border px-2 py-1.5 transition-colors ${
                done
                  ? 'border-[var(--accent-green)]/40 bg-[var(--accent-green)]/10 text-emerald-700 dark:text-[var(--accent-green)]'
                  : isCurrent || (index === currentIdx + 1 && currentIdx < STAGES.length - 1)
                    ? 'border-[var(--accent-yellow)]/50 bg-[var(--accent-yellow)]/15 text-amber-700 dark:text-[var(--accent-yellow)]'
                    : 'border-[var(--border-primary)] bg-[var(--bg-tertiary)] text-[var(--text-secondary)]'
              }`}
            >
              <span className="flex items-center gap-1 font-semibold text-xs text-[var(--text-primary)]">
                {done ? <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-600 dark:text-emerald-400" /> : <Circle className="h-3 w-3 shrink-0 text-slate-400" />}
                {stage.label}
              </span>
              <span className="mt-0.5 block text-[10px] leading-snug text-[var(--text-muted)]">{stage.explain}</span>
            </li>
          );
        })}
      </ol>

      {/* Actor intelligence — elevated demo: no PIN gate */}
      <div className="mt-2.5 flex gap-2">
        <select
          value={actor}
          onChange={event => { setActor(event.target.value); setIntel(null); }}
          className="min-w-0 flex-1 rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] text-[var(--text-primary)] px-2 py-1.5 text-xs focus:outline-none focus:border-[var(--accent-blue)]"
        >
          <option value="">Select actor</option>
          {actors.map(item => (
            <option key={item.actor} value={item.actor}>{item.actor} · {item.stage || 'recon'}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => reveal()}
          className="inline-flex items-center gap-1 rounded-md bg-[var(--accent-blue)] px-3 text-xs font-semibold text-white shadow-sm hover:opacity-90"
        >
          View
        </button>
      </div>
      {intel && (
        <>
          <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
            {entries.map(([key, value]) => (
              <div key={key} className="rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-2">
                <dt className="uppercase tracking-wide text-[10px] text-[var(--text-secondary)]">{key.replace(/_/g, ' ')}</dt>
                <dd className="mt-1 break-all font-mono text-[var(--text-primary)]">{value?.value || 'Confidential'}</dd>
              </div>
            ))}
          </dl>
          {/* Crucial evidence counts across this actor's engagements */}
          {dossier?.totals && (
            <div className="mt-3 grid grid-cols-4 gap-1.5 text-center text-[10px]">
              <div className="rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-1.5"><b className="block text-sm">{dossier.totals.crucial_evidence}</b>evidence</div>
              <div className="rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-1.5"><b className="block text-sm">{dossier.totals.handshakes}</b>handshakes</div>
              <div className="rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] p-1.5"><b className="block text-sm">{dossier.totals.honeypot_touches}</b>honeypot</div>
              <div className="rounded-md border border-[var(--accent-purple)]/40 bg-[var(--accent-purple)]/10 p-1.5 text-[var(--accent-purple)]"><b className="block text-sm">{dossier.totals.captured}</b>captured</div>
            </div>
          )}
          {/* Latest engagement's crucial evidence trail (kept after archive) */}
          {dossier?.engagements?.[0] && (
            <div className="mt-3">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-[var(--text-secondary)]">
                Crucial evidence · {dossier.engagements[0].incident_id}{dossier.engagements[0].archived ? ' (archived)' : ''}
              </p>
              <div className="mt-1.5 max-h-40 space-y-1 overflow-auto text-xs">
                {(dossier.engagements[0].timeline || []).slice().reverse().map((item: any) => (
                  <div key={item.evidence_id} className="rounded bg-[var(--bg-tertiary)] px-2 py-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium capitalize">{String(item.type).replace(/_/g, ' ')}</span>
                      <span className="shrink-0 text-[var(--text-secondary)]">{new Date(item.at).toLocaleTimeString()}</span>
                    </div>
                    {item.payload?.provided_answer && <p className="text-[var(--text-secondary)]">answer: {String(item.payload.provided_answer).slice(0, 40)}</p>}
                    {item.payload?.decoy_name && <p className="text-[var(--text-secondary)]">decoy: {item.payload.decoy_name}</p>}
                    {item.type === 'prediction' && item.payload?.predicted_target && <p className="text-[var(--text-secondary)]">predicted: {item.payload.predicted_target}</p>}
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="mt-3 max-h-24 space-y-1 overflow-auto text-xs">
            {(intel.activity || []).slice(-6).reverse().map((event: any, index: number) => (
              <div key={`${event.at}-${index}`} className="flex gap-2 rounded bg-[var(--bg-tertiary)] px-2 py-1">
                <span className="shrink-0 text-[var(--text-secondary)]">{new Date(event.at).toLocaleTimeString()}</span>
                <span>{event.kind.replace(/_/g, ' ')}</span>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Presenter controls — elevated demo, applies immediately */}
      <div className="mt-3 flex items-center gap-2">
        <button
          type="button"
          onClick={resetRange}
          disabled={busy}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] px-2 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] disabled:opacity-50"
        >
          <RotateCcw className="h-3.5 w-3.5" />Reset range
        </button>
        <span className="text-[10px] text-[var(--text-secondary)]">
          Devices stay registered; decoys, baits and active incidents are removed.
        </span>
      </div>
    </section>
  );
}
