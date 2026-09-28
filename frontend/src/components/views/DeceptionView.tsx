"use client";

import { useEffect, useState } from 'react';
import api, { toArray } from '@/lib/api';
import { useIncidentStore } from '@/store/incidentStore';
import { Panel, Spinner, EmptyState } from '@/components/ui/Panel';
import { cn } from '@/utils/classnames';

interface HoneypotInstance {
  id: string;
  name: string;
  honeypot_type: string;
  os: string | null;
  version: string | null;
  status: string;
  ip_address: string | null;
  location: string;
  ports: number[];
  services: string[];
  deployment_id: string | null;
  interactions_count: number;
  detection_count: number;
  risk_profile?: Record<string, any>;
}

interface SelectorResult {
  stage: string;
  incident_id: string | null;
  recommendations: { id: string; name: string; honeypot_type: string; score: number; available: boolean; rationale: string }[];
}

const STAGES = ['reconnaissance', 'initial_access', 'execution', 'privilege_escalation', 'credential_access', 'lateral_movement', 'exfiltration', 'impact'];

export function DeceptionView() {
  const { activeIncident } = useIncidentStore();
  const [instances, setInstances] = useState<HoneypotInstance[]>([]);
  const [stage, setStage] = useState('credential_access');
  const [selector, setSelector] = useState<SelectorResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [activating, setActivating] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.get<HoneypotInstance[]>('/deception/instances')
      .then((data) => { if (!cancelled) setInstances(toArray<HoneypotInstance>(data)); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const qs = activeIncident?.id ? `?incident_id=${activeIncident.id}&stage=${stage}` : `?stage=${stage}`;
    api.get<SelectorResult>(`/deception/selector${qs}`)
      .then((data) => { if (!cancelled) setSelector(data); })
      .catch((e: any) => { if (!cancelled) setError(e?.message || 'Failed to load selector'); });
    return () => { cancelled = true; };
  }, [activeIncident?.id, stage]);

  const activate = async (id: string) => {
    setActivating(id);
    setError(null);
    try {
      const updated = await api.post<HoneypotInstance>(`/deception/instances/${id}/activate`);
      setInstances((prev) => prev.map((i) => (i.id === updated.id ? updated : i)));
    } catch (e: any) {
      setError(e?.message || 'Failed to activate honeypot');
    } finally {
      setActivating(null);
    }
  };

  return (
    <div className="p-6 h-full overflow-auto space-y-5">
      <div>
        <h2 className="text-xl font-semibold text-[var(--text-primary)]">Deception Operations</h2>
        <p className="text-sm text-[var(--text-secondary)]">Honeypot inventory, adaptive selector and network deployment</p>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-[var(--accent-red)]/10 border border-[var(--accent-red)] text-sm text-[var(--accent-red)]">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        {/* Selector */}
        <Panel title="Honeypot Selector" subtitle="Defence-plan integration for a predicted stage">
          <div className="flex flex-wrap gap-2 mb-4">
            {STAGES.map((s) => (
              <button
                key={s}
                onClick={() => setStage(s)}
                className={cn(
                  'px-2.5 py-1 rounded text-xs border transition-colors',
                  stage === s
                    ? 'bg-[var(--accent-blue)]/15 border-[var(--accent-blue)] text-[var(--accent-blue)]'
                    : 'border-[var(--border-primary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                )}
              >
                {s.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
          {!selector ? (
            <Spinner />
          ) : (
            <div className="space-y-2">
              {toArray<SelectorResult['recommendations'][number]>(selector.recommendations).map((r) => (
                <div key={r.id} className="rounded-lg border border-[var(--border-primary)] p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-[var(--text-primary)]">{r.name}</span>
                      <span className="ml-2 text-xs px-2 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)]">{r.honeypot_type}</span>
                    </div>
                    <span className="text-sm font-bold text-[var(--accent-purple)]">{(r.score * 100).toFixed(0)}%</span>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] mt-1">{r.rationale}</p>
                  {r.available && (
                    <button
                      onClick={() => activate(r.id)}
                      disabled={activating === r.id}
                      className="mt-2 px-2.5 py-1 rounded text-xs bg-[var(--accent-blue)] text-white hover:opacity-90 disabled:opacity-60"
                    >
                      {activating === r.id ? 'Activating…' : 'Activate'}
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Inventory */}
        <Panel title="Honeypot Inventory" subtitle={`${instances.length} instance(s)`}>
          {instances.length === 0 ? (
            <EmptyState message="No honeypot instances deployed yet." />
          ) : (
            <div className="space-y-2">
              {instances.map((hp) => (
                <div key={hp.id} className="rounded-lg border border-[var(--border-primary)] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <span className="font-semibold text-[var(--text-primary)]">{hp.name}</span>
                      <span className="ml-2 text-xs px-2 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)]">{hp.honeypot_type}</span>
                    </div>
                    <span className={cn(
                      'text-xs px-2 py-0.5 rounded capitalize',
                      hp.status === 'active' ? 'bg-[var(--accent-green)]/15 text-[var(--accent-green)]' :
                      hp.status === 'dormant' ? 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]' :
                      'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]'
                    )}>
                      {hp.status}
                    </span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--text-secondary)]">
                    {hp.os && <span>{hp.os}{hp.version ? ` ${hp.version}` : ''}</span>}
                    {hp.ip_address && <span>{hp.ip_address}</span>}
                    {hp.ports.length > 0 && <span>ports: {hp.ports.join(', ')}</span>}
                    <span className="text-[var(--text-muted)]">{hp.interactions_count} interactions</span>
                    <span className="text-[var(--accent-yellow)]">{hp.detection_count} detections</span>
                  </div>
                  {hp.status === 'dormant' && (
                    <button
                      onClick={() => activate(hp.id)}
                      disabled={activating === hp.id}
                      className="mt-2 px-2.5 py-1 rounded text-xs bg-[var(--accent-blue)] text-white hover:opacity-90 disabled:opacity-60"
                    >
                      {activating === hp.id ? 'Activating…' : 'Activate'}
                    </button>
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