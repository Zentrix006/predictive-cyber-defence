"use client";

import { useEffect, useState } from 'react';
import api, { ThreatActor, toArray } from '@/lib/api';
import { useIncidentStore } from '@/store/incidentStore';
import { Panel, Spinner, EmptyState, RiskBadge } from '@/components/ui/Panel';
import { cn } from '@/utils/classnames';

const STAGE_LABELS: Record<string, string> = {
  reconnaissance: 'Reconnaissance',
  initial_access: 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  privilege_escalation: 'Privilege Escalation',
  defense_evasion: 'Defense Evasion',
  credential_access: 'Credential Access',
  discovery: 'Discovery',
  lateral_movement: 'Lateral Movement',
  collection: 'Collection',
  command_and_control: 'Command & Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
  unknown: 'Unknown',
};

export function ThreatActorsView() {
  const { activeIncident } = useIncidentStore();
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [convergence, setConvergence] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!activeIncident?.id) return;
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [actorData, convData] = await Promise.all([
          api.get<ThreatActor[]>(`/threats?incident_id=${activeIncident.id}`),
          api.get<any>(`/threats/convergence/report?incident_id=${activeIncident.id}`),
        ]);
        if (cancelled) return;
        setActors(toArray<ThreatActor>(actorData));
        setConvergence(convData);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load threat actors');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [activeIncident?.id]);

  if (!activeIncident) {
    return (
      <div className="p-6 h-full overflow-auto">
        <EmptyState message="Select an incident to view tracked threat actors." />
      </div>
    );
  }

  return (
    <div className="p-6 h-full overflow-auto space-y-5">
      <div>
        <h2 className="text-xl font-semibold text-[var(--text-primary)]">Threat Actors</h2>
        <p className="text-sm text-[var(--text-secondary)]">
          Multi-threat-actor tracking for <span className="font-medium">{activeIncident.title}</span>
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-[var(--accent-red)]/10 border border-[var(--accent-red)] text-sm text-[var(--accent-red)]">
          {error}
        </div>
      )}
      {loading && !actors.length && <Spinner />}

      {convergence && (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-[var(--accent-blue)]">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg>
            </span>
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">Convergence Analysis</h3>
          </div>
          {convergence.message && (
            <p className="text-sm text-[var(--text-secondary)] mb-3">{convergence.message}</p>
          )}
          {convergence.converging_paths?.length === 0 && (
            <EmptyState message="No converging threat trajectories detected." />
          )}
          <div className="space-y-2">
            {convergence.converging_paths?.map((p: any) => (
              <div key={p.asset_id} className="rounded-lg border border-[var(--border-primary)] p-3 flex items-center justify-between flex-wrap gap-2">
                <div className="min-w-0">
                  <span className="font-semibold text-[var(--text-primary)]">{p.asset_name}</span>
                  <span className="ml-2 text-xs px-2 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)]">{p.asset_type}</span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {p.actors?.map((a: string) => (
                      <span key={a} className="text-[11px] px-1.5 py-0.5 rounded bg-[var(--accent-red)]/10 text-[var(--accent-red)] font-mono">{a}</span>
                    ))}
                    {(p.stages || []).map((s: string, i: number) => (
                      <span key={i} className="text-[11px] px-1.5 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)]">{s}</span>
                    ))}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-lg font-bold text-[var(--accent-red)]">{p.combined_risk}</div>
                  <RiskBadge risk={p.risk_level} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {actors.map((actor) => (
          <Panel
            key={actor.id}
            title={`Actor ${actor.display_id}`}
            subtitle={`First seen ${new Date(actor.first_seen).toLocaleString()}`}
          >
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Current location</span>
                <span className="font-medium text-[var(--text-primary)]">{actor.current_asset_name || 'unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Current stage</span>
                <span className="font-medium capitalize text-[var(--text-primary)]">
                  {STAGE_LABELS[actor.current_stage || 'unknown'] || actor.current_stage}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Predicted next</span>
                <span className="font-medium capitalize text-[var(--accent-blue)]">
                  {STAGE_LABELS[actor.predicted_stage || ''] || actor.predicted_stage}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Predicted target</span>
                <span className="font-medium text-[var(--text-primary)]">{actor.predicted_target_name || 'unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Confidence</span>
                <span className="font-medium text-[var(--text-primary)]">{(actor.confidence * 100).toFixed(0)}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-secondary)]">Risk score</span>
                <span className="font-medium text-[var(--accent-yellow)]">{actor.risk_score?.toFixed?.(1) ?? actor.risk_score}</span>
              </div>
            </div>

            {actor.correlated_sources?.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[var(--border-primary)]">
                <div className="text-xs text-[var(--text-secondary)] mb-1.5">Correlated evidence sources</div>
                <div className="flex flex-wrap gap-1.5">
                  {actor.correlated_sources.map((src, i) => (
                    <span key={i} className="px-2 py-0.5 rounded text-[11px] bg-[var(--bg-tertiary)] border border-[var(--border-primary)] text-[var(--text-secondary)]">
                      {src}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-3">
              <RiskBadge risk={(actor.risk_score ?? 0) > 70 ? 'critical' : (actor.risk_score ?? 0) > 40 ? 'high' : (actor.risk_score ?? 0) > 20 ? 'medium' : 'low'} />
            </div>
          </Panel>
        ))}
      </div>

      {!loading && actors.length === 0 && <EmptyState message="No threat actors matched this incident yet." />}
    </div>
  );
}