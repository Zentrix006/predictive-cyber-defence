"use client";

import { useCallback, useEffect, useState } from 'react';
import api, { ForecastDetail } from '@/lib/api';
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

function stepColor(prob: number, i: number, total: number) {
  if (i === 0) return 'bg-[var(--accent-red)]';
  return `bg-[var(--accent-blue)]`;
}

function formatWorstCase(worstCase: NonNullable<ForecastDetail['belief']>['worst_case']) {
  if (!worstCase) return null;
  if (typeof worstCase === 'string') return worstCase;

  const stage = worstCase.terminal_stage
    ? STAGE_LABELS[worstCase.terminal_stage] || worstCase.terminal_stage.replace(/_/g, ' ')
    : 'unknown terminal stage';
  const risk = typeof worstCase.peak_infil_risk === 'number'
    ? ` · peak risk ${worstCase.peak_infil_risk.toFixed(0)}`
    : '';
  const branch = typeof worstCase.branch === 'number' ? `Branch ${worstCase.branch}: ` : '';
  return `${branch}${stage}${risk}`;
}

export function AttackForecastView() {
  const { activeIncident } = useIncidentStore();
  const [forecast, setForecast] = useState<ForecastDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (fresh = false) => {
    if (!activeIncident?.id) {
      setForecast(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<ForecastDetail>(
        `/forecast/${activeIncident.id}${fresh ? '?fresh=true' : ''}`
      );
      setForecast(data);
    } catch (e: any) {
      setError(e?.message || 'Failed to load forecast');
    } finally {
      setLoading(false);
    }
  }, [activeIncident?.id]);

  useEffect(() => {
    setForecast(null);
    load();
  }, [load, activeIncident?.id]);

  if (!activeIncident) {
    return (
      <div className="p-6 h-full overflow-auto">
        <EmptyState message="Select an incident to view the attack forecast." />
      </div>
    );
  }

  return (
    <div className="p-6 h-full overflow-auto space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="text-xl font-semibold text-[var(--text-primary)]">Attack Forecast</h2>
          <p className="text-sm text-[var(--text-secondary)]">
            K-step prediction for <span className="font-medium">{activeIncident.title}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => load(false)}
            className="px-3 py-1.5 rounded-md text-sm bg-[var(--bg-tertiary)] border border-[var(--border-primary)] hover:bg-[var(--bg-secondary)] transition-colors"
          >
            Refresh
          </button>
          <button
            onClick={() => load(true)}
            disabled={loading}
            className={cn(
              'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
              'bg-[var(--accent-blue)] text-white hover:opacity-90',
              loading && 'opacity-60 cursor-wait'
            )}
          >
            {loading ? 'Running world model…' : 'Run fresh forecast'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-[var(--accent-red)]/10 border border-[var(--accent-red)] text-sm text-[var(--accent-red)]">
          {error}
        </div>
      )}
      {loading && !forecast && <Spinner />}

      {forecast && (
        <>
          {/* Summary strip */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg px-4 py-3">
              <div className="text-xs text-[var(--text-secondary)]">Current Stage</div>
              <div className="text-lg font-bold capitalize text-[var(--text-primary)]">
                {(STAGE_LABELS[forecast.current_stage] || forecast.current_stage).toLowerCase()}
              </div>
            </div>
            <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg px-4 py-3">
              <div className="text-xs text-[var(--text-secondary)]">Confidence</div>
              <div className="text-lg font-bold text-[var(--text-primary)]">
                {(forecast.current_confidence * 100).toFixed(1)}%
              </div>
            </div>
            <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg px-4 py-3">
              <div className="text-xs text-[var(--text-secondary)]">Risk Level</div>
              <div className="mt-1"><RiskBadge risk={forecast.risk_level} /></div>
            </div>
            <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg px-4 py-3">
              <div className="text-xs text-[var(--text-secondary)]">Recommendation</div>
              <div className="text-lg font-bold capitalize text-[var(--accent-purple)]">
                {forecast.recommended_action?.replace(/_/g, ' ')}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            {/* Forecast timeline */}
            <Panel title="Predicted Attack Path" subtitle={`Model ${forecast.model_version} • horizon ${forecast.forecast_horizon}`}>
              <div className="space-y-3">
                {forecast.steps.map((step, i) => {
                  const max = Math.max(...forecast.steps.map((s) => s.probability), 1);
                  return (
                    <div key={i} className={cn('rounded-lg border p-3', i === 0 ? 'border-[var(--accent-red)] bg-[var(--accent-red)]/5' : 'border-[var(--border-primary)]')}>
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className={cn('w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold text-white', stepColor(step.probability, i, forecast.steps.length))}>
                            {step.offset}
                          </span>
                          <span className="font-semibold text-[var(--text-primary)] capitalize">
                            {STAGE_LABELS[step.stage] || step.stage}
                          </span>
                        </div>
                        <div className="text-right text-xs text-[var(--text-secondary)]">
                          <div className="font-bold text-[var(--text-primary)]">{(step.probability * 100).toFixed(1)}%</div>
                          <div>ETA {Math.round(step.eta_seconds)}s</div>
                        </div>
                      </div>
                      <div className="h-1.5 bg-[var(--bg-tertiary)] rounded-full overflow-hidden">
                        <div
                          className={cn('h-full rounded-full', i === 0 ? 'bg-[var(--accent-red)]' : 'bg-[var(--accent-blue)]')}
                          style={{ width: `${(step.probability / max) * 100}%` }}
                        />
                      </div>
                      <div className="mt-1 text-xs text-[var(--text-emphasis,var(--text-secondary))]">
                        Target: <span className="font-medium text-[var(--text-primary)]">{step.target_asset_name || 'unknown'}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Panel>

            {/* Belief state + risk */}
            <div className="space-y-5">
              <Panel title="Belief-State Reasoning" subtitle="Multi-branch consensus from the world model">
                {forecast.belief ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="text-sm">
                        <span className="text-[var(--text-secondary)]">Consensus: </span>
                        <span className="font-semibold capitalize text-[var(--text-primary)]">
                          {STAGE_LABELS[forecast.belief.consensus_stage || ''] || forecast.belief.consensus_stage}
                        </span>
                        <span className="text-[var(--text-secondary)]"> on </span>
                        <span className="font-semibold text-[var(--text-primary)]">{forecast.belief.consensus_target || 'unknown'}</span>
                      </div>
                      <span className="text-xs text-[var(--text-secondary)]">
                        agreement {((forecast.belief.consensus_agreement || 0) * 100).toFixed(0)}%
                      </span>
                    </div>
                    {forecast.belief.branches.map((branch) => (
                      <div key={branch.branch} className="border border-[var(--border-primary)] rounded-lg p-3">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-[var(--text-secondary)]">Branch {branch.branch}</span>
                          <span className="text-[var(--text-primary)] font-medium">
                            {(branch.confidence * 100).toFixed(0)}% • risk {branch.risk.toFixed(0)}
                          </span>
                        </div>
                        <div className="mt-1 text-sm capitalize text-[var(--text-primary)]">
                          → {branch.target_name || 'unknown'} <span className="text-[var(--text-secondary)]">({STAGE_LABELS[branch.stage || ''] || branch.stage})</span>
                        </div>
                      </div>
                    ))}
                    {forecast.belief.worst_case && (
                      <div className="text-xs text-[var(--accent-red)]">
                        Worst case: {formatWorstCase(forecast.belief.worst_case)}
                      </div>
                    )}
                  </div>
                ) : (
                  <EmptyState message="No belief branches available for the stored forecast. Run a fresh forecast." />
                )}
              </Panel>

              <Panel title="Per-Step Risk" subtitle={`Aggregate level: ${forecast.risk_level}`}>
                <div className="space-y-2">
                  {forecast.steps.map((step, i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <span className="capitalize text-[var(--text-primary)]">
                        T+{step.offset} · {STAGE_LABELS[step.stage] || step.stage}
                      </span>
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-1.5 bg-[var(--bg-tertiary)] rounded-full overflow-hidden">
                          <div
                            className="h-full bg-[var(--accent-purple)]"
                            style={{ width: `${(forecast.risk[i] / 100) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs text-[var(--text-secondary)] w-8 text-right">{forecast.risk[i].toFixed(0)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>
          </div>

          {/* Recommendation & explanation */}
          <Panel title="Recommended Response">
            <div className="flex items-start gap-3">
              <div className="text-2xl text-[var(--accent-purple)]">◆</div>
              <div className="flex-1">
                <div className="font-semibold capitalize text-[var(--text-primary)]">
                  {forecast.recommended_action?.replace(/_/g, ' ')}
                </div>
                {forecast.explanation?.natural_language && (
                  <p className="text-sm text-[var(--text-secondary)] mt-1">{forecast.explanation.natural_language}</p>
                )}
                {Array.isArray(forecast.recommended_actions) && forecast.recommended_actions.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {forecast.recommended_actions.map((a: any, i: number) => (
                      <span key={i} className="px-2 py-1 rounded text-xs bg-[var(--bg-tertiary)] border border-[var(--border-primary)] text-[var(--text-secondary)]">
                        {a.action || a}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}