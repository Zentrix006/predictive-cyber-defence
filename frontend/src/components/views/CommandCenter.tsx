"use client";

import { useEffect, useState } from 'react';
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { NavBar } from '@/components/nav/NavBar';
import { TopologyCanvas } from '@/components/topology/TopologyCanvas';
import { PredictionPanel } from '@/components/prediction/PredictionPanel';
import { IncidentList } from '@/components/incidents/IncidentList';
import { Timeline } from '@/components/timeline/Timeline';
import { EvidenceTabs } from '@/components/forensics/EvidenceTabs';
import { WorldModelPanel } from '@/components/worldmodel/WorldModelPanel';
import { ModelDecisionHUD } from '@/components/worldmodel/ModelDecisionHUD';
import { AttackForecastView } from '@/components/views/AttackForecastView';
import { ThreatActorsView } from '@/components/views/ThreatActorsView';
import { DeceptionView } from '@/components/views/DeceptionView';
import { ForensicsView } from '@/components/views/ForensicsView';
import { InfrastructureView } from '@/components/views/InfrastructureView';
import { ModelLabView } from '@/components/views/ModelLabView';
import { AIIntelligenceView } from '@/components/views/AIIntelligenceView';
import { SettingsView } from '@/components/views/SettingsView';
import { GraphAnalysisView } from '@/components/views/GraphAnalysisView';
import { PassiveAnalysisView } from '@/components/views/PassiveAnalysisView';
import { LiveTelemetryView } from '@/components/views/LiveTelemetryView';
import { MitigationCacheView } from "./MitigationCacheView";
import { PresentationModeView } from '@/components/views/PresentationModeView';
import { TimelineScrubber } from '@/components/timeline/TimelineScrubber';
import { PacketInspector } from '@/components/forensics/PacketInspector';
import { CommandPalette } from '@/components/ui/CommandPalette';
import { useIncidentStore } from '@/store/incidentStore';
import { useTopologyStore } from '@/store/topologyStore';
import { usePredictionStore } from '@/store/predictionStore';
import { useUIStore } from '@/store/uiStore';
import { cn } from '@/utils/classnames';
import { TopologyNode } from '@/types';
import { Activity, Brain, Clock3, FileSearch, Radio } from 'lucide-react';
import api, { authHeaders } from '@/lib/api';

const API = process.env.NEXT_PUBLIC_API_URL || '/api/v1';

function mapBackendNode(raw: any): TopologyNode {
  return {
    id: raw.id,
    label: raw.label,
    asset_id: raw.asset_id,
    asset_type: raw.asset_type,
    zone: raw.zone,
    status: raw.status,
    threatScore: raw.threat_score ?? raw.threatScore ?? 0,
    criticality: raw.criticality,
    position: raw.position || undefined,
    metadata: raw.metadata || {},
  };
}

function SimulationBanner() {
  const [active, setActive] = useState(false);
  const [scenario, setScenario] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const s = await api.get<any>('/simulation/status');
        if (cancelled) return;
        setActive(Boolean(s.active));
        setScenario(s.scenario);
      } catch { /* offline */ }
    };
    poll();
    const id = setInterval(poll, 15000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  if (!active) return null;
  return (
    <div className="flex items-center gap-2 px-4 py-1.5 text-xs bg-[var(--accent-green)]/10 border-b border-[var(--accent-green)]/40 text-[var(--accent-green)]">
      <Activity className="w-3.5 h-3.5 animate-pulse" />
      <span className="font-medium">SIMULATION ACTIVE</span>
      {scenario && <span className="text-[var(--text-secondary)]">— scenario {scenario}</span>}
    </div>
  );
}

function KpiRow({ incidentsAvailable }: { incidentsAvailable: boolean }) {
  const { incidents } = useIncidentStore();
  const [metrics, setMetrics] = useState<any>(null);
  const [metricsAvailable, setMetricsAvailable] = useState(false);
  const open = incidents.filter((i: any) => i.status !== 'closed').length;
  const critical = incidents.filter((i: any) => i.severity === 'critical' && i.status !== 'closed').length;

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const m = await api.get<any>('/network/metrics');
        if (!cancelled) { setMetrics(m); setMetricsAvailable(true); }
      } catch { if (!cancelled) setMetricsAvailable(false); }
    };
    const sessionChanged = () => { setMetrics(null); setMetricsAvailable(false); poll(); };
    poll();
    window.addEventListener('pcd:session-changed', sessionChanged);
    const id = setInterval(poll, 10000);
    return () => { cancelled = true; clearInterval(id); window.removeEventListener('pcd:session-changed', sessionChanged); };
  }, []);

  const kpi = [
    { label: 'Incidents', value: incidentsAvailable ? open : '—', detail: `${incidentsAvailable ? critical : '—'} critical · open` },
    { label: 'Asset risk', value: metricsAvailable ? metrics?.suspicious_assets ?? '—' : '—', detail: `${metricsAvailable ? metrics?.compromised_assets ?? '—' : '—'} compromised assets` },
    { label: 'Monitored assets', value: metricsAvailable ? metrics?.assets ?? '—' : '—', detail: 'Current inventory' },
    { label: 'Vulnerabilities', value: metricsAvailable ? metrics?.vulnerabilities ?? '—' : '—', detail: 'Recorded findings' },
  ];

  return (
    <div aria-label="Operations summary" className="console-shell-chrome grid grid-cols-2 xl:grid-cols-4 gap-2 px-3 py-2.5 sm:px-4 border-b border-[var(--border-primary)]">
      {kpi.map((k) => (
        <div key={k.label} className="console-metric min-w-0 bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-xl px-3 py-2.5 sm:px-4">
          <div className="flex items-center justify-between gap-2">
            <div className="text-xs font-medium text-[var(--text-secondary)]">{k.label}</div>
            <div className="text-xl font-semibold tabular-nums leading-none text-[var(--text-primary)]">{k.value}</div>
          </div>
          <div className="mt-1.5 truncate text-[10px] text-[var(--text-secondary)]">{k.value === '—' ? 'Data unavailable' : k.detail}</div>
        </div>
      ))}
    </div>
  );
}

export function CommandCenter() {
  const { activeIncident, incidents } = useIncidentStore();
  const { nodes, edges, predictionEdges, setNodes } = useTopologyStore();
  const { currentForecast } = usePredictionStore();
  const { sidebarOpen, activeView, theme, setSidebarOpen } = useUIStore();
  const [incidentDetail, setIncidentDetail] = useState(false);
  const [authRequired, setAuthRequired] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'unavailable' | 'unauthorized'>('connecting');
  const [incidentsAvailable, setIncidentsAvailable] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [packetInspectorOpen, setPacketInspectorOpen] = useState(false);
  const [contextPanel, setContextPanel] = useState<'timeline' | 'evidence' | 'model'>('evidence');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (window.matchMedia("(max-width: 1023px)").matches) setSidebarOpen(false);
  }, [setSidebarOpen]);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetch(`${API}/topology`, { headers: authHeaders() });
        if (cancelled) return;
        if (!res.ok) {
          setAuthRequired(res.status === 401 || res.status === 403);
          setConnectionStatus(res.status === 401 || res.status === 403 ? 'unauthorized' : 'unavailable');
          return;
        }
        const data = await res.json();
        if (cancelled) return;
        if (!Array.isArray(data.nodes)) { setConnectionStatus('unavailable'); return; }
        setNodes(data.nodes.map(mapBackendNode));
        useTopologyStore.getState().setEdges(Array.isArray(data.edges) ? data.edges : []);
        useTopologyStore.getState().setPredictionEdges(Array.isArray(data.prediction_edges) ? data.prediction_edges : []);
        setAuthRequired(false);
        setConnectionStatus('connected');
      } catch {
        if (!cancelled) setConnectionStatus('unavailable');
        // Network / backend unavailable; keep existing nodes.
      }
    };
    const sessionChanged = () => { setConnectionStatus('connecting'); poll(); };
    poll();
    window.addEventListener('pcd:session-changed', sessionChanged);
    const id = setInterval(poll, 4000);
    return () => {
      cancelled = true;
      clearInterval(id);
      window.removeEventListener('pcd:session-changed', sessionChanged);
    };
  }, [setNodes]);

  // Populate the incident list and auto-select the first open incident so
  // forecast / threat-actor / forensics views have an active incident context.
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const data = await api.get<any>('/incidents?page_size=50');
        if (cancelled) return;
        if (!Array.isArray(data.items)) { setIncidentsAvailable(false); return; }
        const { setIncidents, activeIncident } = useIncidentStore.getState();
        setIncidents(data.items);
        setIncidentsAvailable(true);
        if (!activeIncident) {
          const firstOpen = data.items.find((i: any) => i.status !== 'closed') || data.items[0];
          if (firstOpen) useIncidentStore.getState().setActiveIncident(firstOpen);
        } else {
          const stillExists = data.items.some((i: any) => i.id === activeIncident.id);
          if (!stillExists) useIncidentStore.getState().setActiveIncident(null);
        }
      } catch (error: any) {
        if (cancelled) return;
        setIncidentsAvailable(false);
        if (error?.status === 401) setAuthRequired(true);
        // backend unavailable
      }
    };
    const sessionChanged = () => { setIncidentsAvailable(false); poll(); };
    poll();
    window.addEventListener('pcd:session-changed', sessionChanged);
    const id = setInterval(poll, 10000);
    return () => { cancelled = true; clearInterval(id); window.removeEventListener('pcd:session-changed', sessionChanged); };
  }, []);

  return (
    <div className={cn(theme === 'light' && 'light', 'h-[100dvh] w-full flex flex-col bg-[var(--bg-primary)] text-[var(--text-primary)]')}>
      <Header
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => useUIStore.getState().toggleSidebar()}
        theme={theme}
        onToggleTheme={() => useUIStore.getState().toggleTheme()}
        activeIncident={activeIncident}
        connectionStatus={connectionStatus}
      />

      <NavBar />

      <div className="flex-1 min-h-0 flex overflow-hidden">
        <Sidebar
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
          incidents={incidents}
          activeIncident={activeIncident}
          onSelectIncident={() => { setIncidentDetail(true); useUIStore.getState().setActiveView('command-center'); }}
          dataAvailable={incidentsAvailable}
        />

        <div className={cn('min-w-0 flex-1 flex flex-col overflow-hidden', 'transition-all duration-300')}>
          <SimulationBanner />
          {authRequired && (
            <div role="alert" className="console-shell-chrome flex items-center gap-2 border-b border-[var(--accent-yellow)]/40 bg-[var(--accent-yellow)]/10 px-4 py-2 text-sm text-[var(--accent-yellow)]">
              Sign in from the header as an administrator for console controls, or continue as a view-only guest to inspect incidents, topology and telemetry.
            </div>
          )}

          {activeView === 'command-center' && (
            <div className="flex-1 min-h-0 flex flex-col overflow-y-auto">
              <KpiRow incidentsAvailable={incidentsAvailable} />
              <div className="flex-none xl:flex-1 min-h-[30rem] flex flex-col xl:flex-row">
                <div className="w-full min-h-[30rem] xl:min-h-0 xl:w-3/5 xl:h-full border-b xl:border-b-0 xl:border-r border-[var(--border-primary)] flex flex-col">
                  <div className="p-3 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] flex items-center justify-between">
                    <div>
                      <h2 className="text-lg font-semibold text-[var(--text-primary)]">Network Topology & Blast Radius</h2>
                      <p className="text-xs text-[var(--text-secondary)]">
                        {nodes.size} assets • {edges.size} connections • {predictionEdges.size} predictions
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setPacketInspectorOpen((prev) => !prev)}
                        className={cn(
                          "px-2.5 py-1 text-xs font-mono font-semibold rounded border transition-colors",
                          packetInspectorOpen
                            ? "bg-cyan-950 text-cyan-300 border-cyan-500/50 shadow-[0_0_8px_rgba(6,182,212,0.3)]"
                            : "bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700"
                        )}
                      >
                        {packetInspectorOpen ? "Close DPI" : "DPI Packet Inspector"}
                      </button>
                      <button
                        onClick={() => setCommandPaletteOpen(true)}
                        className="px-2.5 py-1 text-xs font-mono font-semibold rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors flex items-center gap-1"
                      >
                        <span className="text-cyan-400">⌘K</span> Quick Actions
                      </button>
                    </div>
                  </div>
                  <div className="flex-1 min-h-[24rem] relative flex flex-col">
                    <div className="flex-1 relative min-h-[18rem]">
                      <TopologyCanvas />
                      <ModelDecisionHUD />
                    </div>
                    <TimelineScrubber className="m-2" />
                    {packetInspectorOpen && (
                      <PacketInspector className="m-2 max-h-80" onClose={() => setPacketInspectorOpen(false)} />
                    )}
                  </div>
                </div>

                <div className="w-full min-h-[28rem] xl:min-h-0 xl:w-2/5 xl:h-full flex flex-col overflow-hidden">
                  <div className="h-1/2 border-b border-[var(--border-primary)]">
                    <PredictionPanel forecast={currentForecast} />
                  </div>
                  <div className="h-1/2 overflow-hidden">
                    {incidentDetail && activeIncident ? (
                      <IncidentDetail incident={activeIncident} onClose={() => setIncidentDetail(false)} />
                    ) : (
                      <IncidentList
                        incidents={incidents}
                        onSelect={(inc) => { useIncidentStore.getState().setActiveIncident(inc); setIncidentDetail(true); }}
                      />
                    )}
                  </div>
                </div>
              </div>

              <section aria-label="Incident context" className="flex-none min-h-64 xl:h-64 border-t border-[var(--border-primary)] flex flex-col overflow-hidden">
                <div className="console-shell-chrome flex shrink-0 items-center gap-1 overflow-x-auto border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] px-3 py-1.5" role="tablist" aria-label="Incident context panels">
                  {([
                    ['evidence', 'Evidence & assets', FileSearch],
                    ['timeline', 'Timeline', Clock3],
                    ['model', 'Model snapshot', Brain],
                  ] as const).map(([key, label, Icon]) => (
                    <button
                      key={key}
                      id={`context-tab-${key}`}
                      type="button"
                      role="tab"
                      aria-selected={contextPanel === key}
                      aria-controls="incident-context-panel"
                      onClick={() => setContextPanel(key)}
                      className={cn(
                        'inline-flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-colors',
                        contextPanel === key ? 'bg-[var(--accent-blue)]/12 text-[var(--accent-blue)]' : 'text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)] hover:text-[var(--text-primary)]'
                      )}
                    >
                      <Icon className="h-3.5 w-3.5" />{label}
                    </button>
                  ))}
                  <span className="ml-auto hidden pr-1 text-[10px] text-[var(--text-muted)] sm:block">Select a panel to view its details</span>
                </div>
                <div id="incident-context-panel" role="tabpanel" aria-labelledby={`context-tab-${contextPanel}`} className="min-h-0 flex-1 overflow-hidden">
                  {contextPanel === 'timeline' && <Timeline className="h-full min-h-0" />}
                  {contextPanel === 'evidence' && <EvidenceTabs className="h-full min-h-0" incidentId={activeIncident?.id} />}
                  {contextPanel === 'model' && <WorldModelPanel showPcapAnalysis={false} />}
                </div>
              </section>
            </div>
          )}

          {activeView === 'threat-actors' && <ThreatActorsView />}
          {activeView === 'attack' && <AttackForecastView />}
          {activeView === 'deception' && <DeceptionView />}
          {activeView === 'forensics' && <ForensicsView />}
          {activeView === 'infrastructure' && <InfrastructureView />}
          {activeView === 'model-lab' && <ModelLabView />}
          {activeView === 'ai-intelligence' && <AIIntelligenceView />}
          {activeView === 'settings' && <SettingsView />}
          {activeView === 'graph-analysis' && <GraphAnalysisView />}
          {activeView === 'passive-analysis' && <PassiveAnalysisView />}
          {activeView === 'live-telemetry' && <LiveTelemetryView />}
          {activeView === 'presentation' && <PresentationModeView />}
          {activeView === 'mitigation-cache' && <MitigationCacheView />}
          {(activeView === 'network' || activeView === 'world-model') && (
            <div className="p-6 h-full overflow-auto">
              <div className="flex items-center gap-2 text-[var(--text-secondary)]">
                <Radio className="w-4 h-4" />
                This view has been consolidated into the eight-platform views. Use Command Center for topology, or Infrastructure for network state.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Global Command Palette (Cmd+K) */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        onNavigateView={(v) => useUIStore.getState().setActiveView(v as any)}
      />
    </div>
  );
}

// Simple Incident Detail Component
function IncidentDetail({ incident, onClose }: { incident: any; onClose: () => void }) {
  return (
    <div className="console-shell-chrome h-full flex flex-col bg-[var(--bg-secondary)] p-4 overflow-auto">
      <div className="flex items-center justify-between mb-4">
        <h2 className="min-w-0 break-words text-lg font-semibold">{incident.title}</h2>
        <button onClick={onClose} aria-label="Close incident details" className="shrink-0 p-2 hover:bg-[var(--bg-tertiary)] rounded">
          ✕
        </button>
      </div>
      <div className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-[var(--text-secondary)]">Status:</span>
          <span className="font-medium capitalize">{incident.status}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[var(--text-secondary)]">Severity:</span>
          <span className="font-medium capitalize">{incident.severity}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[var(--text-secondary)]">Stage:</span>
          <span className="font-medium">{incident.current_stage || 'Unknown'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[var(--text-secondary)]">Threat Score:</span>
          <span className="font-medium">{typeof incident.threat_score === 'number' && Number.isFinite(incident.threat_score) ? `${(incident.threat_score * 100).toFixed(0)}%` : 'Unavailable'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[var(--text-secondary)]">Detected:</span>
          <span className="font-medium">{new Date(incident.detected_at).toLocaleString()}</span>
        </div>
      </div>
    </div>
  );
}
