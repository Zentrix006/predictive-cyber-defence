"use client";

import { useEffect, useState } from 'react';
import api, { SimulationStatus } from '@/lib/api';
import { useUIStore } from '@/store/uiStore';
import { Panel, Spinner } from '@/components/ui/Panel';
import { Play, Square, Activity, Sun, Moon, Radio } from 'lucide-react';
import { cn } from '@/utils/classnames';

import { NetworkSettingsPanel } from "./NetworkSettingsPanel";

export function SettingsView() {
  const { theme, setTheme } = useUIStore();
  const [status, setStatus] = useState<SimulationStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [apiOk, setApiOk] = useState<boolean | null>(null);

  const refresh = async () => {
    try {
      const s = await api.get<SimulationStatus>('/simulation/status');
      setStatus(s);
      setApiOk(true);
    } catch {
      setApiOk(false);
      setStatus(null);
    }
  };

  useEffect(() => {
    refresh();
    window.addEventListener('pcd:session-changed', refresh);
    const id = setInterval(refresh, 15000);
    return () => { clearInterval(id); window.removeEventListener('pcd:session-changed', refresh); };
  }, []);

  const start = async () => {
    setLoading(true);
    setMessage(null);
    try {
      const s = await api.post<SimulationStatus>('/simulation/start');
      setStatus(s);
      setMessage('Simulation started.');
    } catch (e: any) {
      setMessage(`Error: ${e?.message || 'failed to start'}`);
    } finally {
      setLoading(false);
    }
  };

  const stop = async () => {
    setLoading(true);
    setMessage(null);
    try {
      await api.post('/simulation/stop');
      await refresh();
      setMessage('Simulation stopped and cleaned up.');
    } catch (e: any) {
      setMessage(`Error: ${e?.message || 'failed to stop'}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="console-shell-chrome p-4 sm:p-6 h-full overflow-auto space-y-5">
      <div>
        <h2 className="text-xl font-semibold text-[var(--text-primary)]">Settings</h2>
        <p className="text-sm text-[var(--text-secondary)]">Platform configuration, simulation sandbox and API health</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Simulation */}
        <Panel title="Simulation Sandbox" subtitle="Controlled multi-actor intrusion exercise">
          {apiOk === false ? (
            <div role="status" className="p-4 text-sm text-[var(--text-secondary)]">Simulation status is unavailable. Check your session and API connection, then use Refresh in API Health.</div>
          ) : !status && !message ? (
            <Spinner />
          ) : (
            <div className="p-4 space-y-4">
              <div className="p-3 rounded-lg border border-[var(--border-primary)] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {status?.active ? (
                    <Activity className="w-4 h-4 text-[var(--accent-green)] animate-pulse" />
                  ) : (
                    <Radio className="w-4 h-4 text-[var(--text-muted)]" />
                  )}
                  <span className="font-semibold text-[var(--text-primary)]">
                    {status?.active ? 'Simulation running' : 'Simulation idle'}
                  </span>
                </div>
                {status?.active && (
                  <span className="text-xs text-[var(--text-secondary)]">scenario: {status.scenario}</span>
                )}
              </div>

              {status?.active && status.incident_id && (
                <div className="text-xs text-[var(--text-secondary)]">
                  Incident <span className="font-mono text-[var(--text-primary)]">{status.incident_id}</span>
                  {status.started_at && <> • started {new Date(status.started_at).toLocaleString()}</>}
                </div>
              )}

              <div className="flex gap-2">
                <button
                  onClick={start}
                  disabled={loading || status?.active}
                  className={cn(
                    'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                    'bg-[var(--accent-green)] text-white hover:opacity-90',
                    (loading || status?.active) && 'opacity-60 cursor-not-allowed'
                  )}
                >
                  <Play className="w-4 h-4" /> Start simulation
                </button>
                <button
                  onClick={stop}
                  disabled={loading || !status?.active}
                  className={cn(
                    'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                    'bg-[var(--accent-red)] text-white hover:opacity-90',
                    (loading || !status?.active) && 'opacity-60 cursor-not-allowed'
                  )}
                >
                  <Square className="w-4 h-4" /> Stop & clean up
                </button>
              </div>
              {loading && <div className="text-xs text-[var(--text-secondary)]">Working…</div>}
              {message && (
                <div className={cn(
                  'text-xs px-3 py-2 rounded',
                  message.startsWith('Error') ? 'text-[var(--accent-red)] bg-[var(--accent-red)]/10' : 'text-[var(--accent-green)] bg-[var(--accent-green)]/10'
                )}>{message}</div>
              )}
            </div>
          )}
        </Panel>

        <div className="space-y-5">
          {/* Appearance */}
          <Panel title="Appearance">
            <div className="p-4 flex items-center justify-between">
              <div>
                <div className="font-semibold text-[var(--text-primary)]">Theme</div>
                <div className="text-xs text-[var(--text-secondary)]">Currently {theme} mode</div>
              </div>
              <button
                onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                className="flex items-center gap-2 px-3 py-2 rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] text-sm hover:bg-[var(--bg-secondary)] transition-colors"
              >
                {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                Switch to {theme === 'dark' ? 'light' : 'dark'}
              </button>
            </div>
          </Panel>

          {/* API health */}
          <Panel title="API Health">
            <div className="p-4 flex items-center justify-between">
              <div>
                <div className="font-semibold text-[var(--text-primary)]">Backend status</div>
                <div className="text-xs text-[var(--text-secondary)]">Base URL: {process.env.NEXT_PUBLIC_API_URL || '/api/v1 (same origin)'}</div>
              </div>
              {apiOk === null ? (
                <Spinner />
              ) : (
                <span className={cn(
                  'flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded',
                  apiOk ? 'text-[var(--accent-green)] bg-[var(--accent-green)]/10' : 'text-[var(--accent-red)] bg-[var(--accent-red)]/10'
                )}>
                  <span className={cn('w-2 h-2 rounded-full', apiOk ? 'bg-[var(--accent-green)]' : 'bg-[var(--accent-red)]')} />
                  {apiOk ? 'Online' : 'Offline'}
                </span>
              )}
              <button
                onClick={refresh}
                className="px-3 py-1.5 rounded-md text-xs border border-[var(--border-primary)] bg-[var(--bg-tertiary)] hover:bg-[var(--bg-secondary)] transition-colors"
              >
                Refresh
              </button>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
