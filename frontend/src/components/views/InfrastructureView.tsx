"use client";

import { useEffect, useState } from 'react';
import api, { toArray } from '@/lib/api';
import { Panel, Spinner, EmptyState, StatCard } from '@/components/ui/Panel';
import { Server, Boxes, Users, Shield, Network as NetworkIcon, AlertTriangle } from 'lucide-react';
import { cn } from '@/utils/classnames';
import { SyntaxTemplatePanel } from '@/components/infrastructure/SyntaxTemplatePanel';

interface Metrics {
  assets: number;
  services: number;
  users: number;
  auth_events: number;
  vulnerabilities: number;
  critical_vulnerabilities: number;
  suspicious_assets: number;
  compromised_assets: number;
}

interface NetworkState {
  asset_count: number;
  services: any[];
  users: any[];
  auth_events: any[];
  vulnerabilities: any[];
  suspicious_assets: any[];
  compromised_assets: any[];
  timestamp: string;
}

export function InfrastructureView() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [state, setState] = useState<NetworkState | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [m, s] = await Promise.all([
          api.get<Metrics>('/network/metrics'),
          api.get<NetworkState>('/network/state?limit=80'),
        ]);
        if (cancelled) return;
        setMetrics(m);
        setState(s);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load network state');
      }
    };
    load();
    const id = setInterval(load, 10000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const vulnerabilities = toArray<any>(state?.vulnerabilities);
  const services = toArray<any>(state?.services);
  const authEvents = toArray<any>(state?.auth_events);
  const suspiciousAssets = toArray<any>(state?.suspicious_assets);

  return (
    <div className="p-6 h-full overflow-auto space-y-5">
      <div>
        <h2 className="text-xl font-semibold text-[var(--text-primary)]">Infrastructure & Network State</h2>
        <p className="text-sm text-[var(--text-secondary)]">Live aggregate view of monitored assets, services and risk posture</p>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-[var(--accent-red)]/10 border border-[var(--accent-red)] text-sm text-[var(--accent-red)]">{error}</div>
      )}
      {!metrics && !error && <Spinner />}

      {metrics && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="Assets" value={metrics.assets} icon={<Server className="w-5 h-5" />} />
            <StatCard label="Services" value={metrics.services} icon={<NetworkIcon className="w-5 h-5" />} />
            <StatCard label="Users" value={metrics.users} icon={<Users className="w-5 h-5" />} />
            <StatCard label="Auth Events" value={metrics.auth_events} icon={<Shield className="w-5 h-5" />} />
            <StatCard
              label="Vulnerabilities"
              value={metrics.vulnerabilities}
              hint={`${metrics.critical_vulnerabilities} critical`}
              tone={metrics.critical_vulnerabilities > 0 ? 'red' : 'green'}
              icon={<AlertTriangle className="w-5 h-5" />}
            />
            <StatCard
              label="Suspicious Assets"
              value={metrics.suspicious_assets}
              tone={metrics.suspicious_assets > 0 ? 'yellow' : 'blue'}
              icon={<Boxes className="w-5 h-5" />}
            />
            <StatCard
              label="Compromised"
              value={metrics.compromised_assets}
              tone={metrics.compromised_assets > 0 ? 'red' : 'green'}
              icon={<Server className="w-5 h-5" />}
            />
          </div>

          {suspiciousAssets.length > 0 && (
            <Panel title="Suspicious / Compromised Assets" subtitle="Alert list">
              <div className="space-y-2">
                {suspiciousAssets.map((a: any) => (
                  <div key={a.id} className="flex items-center justify-between rounded-lg border border-[var(--border-primary)] p-3">
                    <div>
                      <span className="font-semibold text-[var(--text-primary)]">{a.hostname}</span>
                      <span className={cn(
                        'ml-2 text-xs px-2 py-0.5 rounded capitalize',
                        a.status === 'compromised' ? 'bg-[var(--accent-red)]/15 text-[var(--accent-red)]' : 'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]'
                      )}>{a.status}</span>
                    </div>
                    <span className="text-sm font-bold text-[var(--accent-purple)]">
                      {(a.threat_score * 100).toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
            <Panel title="Vulnerabilities" subtitle={`${vulnerabilities.length} recent`}>
              {vulnerabilities.length === 0 ? (
                <EmptyState message="No vulnerabilities recorded." />
              ) : (
                <div className="space-y-2">
                  {vulnerabilities.map((v: any, i: number) => (
                    <div key={v.id || i} className="rounded-lg border border-[var(--border-primary)] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-[var(--text-primary)] truncate">{v.name || v.cve_id || 'vuln'}</span>
                        <span className={cn(
                          'shrink-0 text-[11px] px-2 py-0.5 rounded uppercase',
                          v.severity === 'critical' ? 'bg-[var(--accent-red)]/15 text-[var(--accent-red)]'
                          : v.severity === 'high' ? 'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]'
                          : 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]'
                        )}>{v.severity}</span>
                      </div>
                      <div className="mt-1 text-xs text-[var(--text-muted)]">
                        {v.cvss_score ? `CVSS ${v.cvss_score} • ` : ''}{v.asset_name || v.service_name || v.hostname || ''}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            <Panel title="Active Services" subtitle={`${services.length} recent`}>
              {services.length === 0 ? (
                <EmptyState message="No services monitored." />
              ) : (
                <div className="space-y-2">
                  {services.map((s: any, i: number) => (
                    <div key={s.id || i} className="flex items-center justify-between rounded-lg border border-[var(--border-primary)] p-2.5 text-sm">
                      <span className="font-medium text-[var(--text-primary)]">{s.service_name}</span>
                      <span className="text-xs text-[var(--text-muted)]">
                        {s.hostname || s.asset_name || ''}{s.port ? `:${s.port}` : ''}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </div>

          <SyntaxTemplatePanel />

          <Panel title="Recent Authentication Events" subtitle={`${authEvents.length} recent`}>
            {authEvents.length === 0 ? (
              <EmptyState message="No authentication events." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-[var(--text-secondary)] border-b border-[var(--border-primary)]">
                      <th className="py-2 pr-3">User</th>
                      <th className="py-2 pr-3">Source</th>
                      <th className="py-2 pr-3">Status</th>
                      <th className="py-2">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {authEvents.slice(0, 25).map((e: any, i: number) => (
                      <tr key={e.id || i} className="border-b border-[var(--border-primary)]/50">
                        <td className="py-1.5 pr-3 text-[var(--text-primary)]">{e.username}</td>
                        <td className="py-1.5 pr-3 text-[var(--text-muted)]">{e.source_ip}</td>
                        <td className="py-1.5 pr-3">
                          <span className={cn(
                            'text-[11px] px-1.5 py-0.5 rounded capitalize',
                            e.success ? 'bg-[var(--accent-green)]/15 text-[var(--accent-green)]' : 'bg-[var(--accent-red)]/15 text-[var(--accent-red)]'
                          )}>{e.success ? 'success' : 'failed'}</span>
                        </td>
                        <td className="py-1.5 text-xs text-[var(--text-muted)]">{e.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
