"use client";

import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { NavBar } from '@/components/nav/NavBar';
import { TopologyCanvas } from '@/components/topology/TopologyCanvas';
import { DemoTopology } from '@/components/topology/DemoTopology';
import { ActorIntelPanel } from '@/components/topology/ActorIntelPanel';
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
import { DemoWorkspaceView } from '@/components/views/DemoWorkspaceView';
import { MitigationCacheView } from "./MitigationCacheView";
import { PresentationModeView } from '@/components/views/PresentationModeView';
import { GraphAnalysisView } from '@/components/views/GraphAnalysisView';
import { PassiveAnalysisView } from '@/components/views/PassiveAnalysisView';
import { DemoNodePanel } from '@/components/topology/DemoNodePanel';
import { useIncidentStore } from '@/store/incidentStore';
import { useTopologyStore } from '@/store/topologyStore';
import { usePredictionStore } from '@/store/predictionStore';
import { useUIStore } from '@/store/uiStore';
import { cn } from '@/utils/classnames';
import { TopologyNode } from '@/types';
import { Activity, Radio, Copy, QrCode } from 'lucide-react';
import api, { authHeaders } from '@/lib/api';
import { demoApiBase } from '@/lib/demo-api';

const API = process.env.NEXT_PUBLIC_API_URL || '/api/v1';

interface CommandCenterProps {
  mode?: 'main' | 'lan-demo';
}

function mapBackendNode(raw: any): TopologyNode {
  return {
    id: raw.id,
    label: raw.label || raw.name || raw.id,
    asset_id: raw.asset_id,
    asset_type: raw.asset_type,
    zone: raw.zone || (raw.type === 'infra' ? 'management' : 'user_zone'),
    status: raw.status === 'healthy' || raw.status === 'infra' ? 'normal' : raw.status,
    threatScore: raw.threat_score ?? raw.threatScore ?? 0,
    criticality: raw.criticality,
    position: raw.position || undefined,
    metadata: { ...(raw.metadata || {}), ...raw },
  };
}

function mapDemoEdge(raw: any, index: number) {
  return {
    id: raw.id || `demo-edge-${raw.source}-${raw.target}-${index}`,
    source: raw.source,
    target: raw.target,
    protocol: raw.kind || 'live',
    port: 0,
    bytes_transferred: raw.flow || 0,
    packet_count: raw.flow || 0,
    is_predicted: raw.kind === 'prediction',
    prediction_probability: raw.probability,
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    kind: raw.kind,
    flow: raw.flow,
    confidence: raw.confidence,
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

function DemoSimulationBanner() {
  return <div className="flex items-center gap-2 border-b border-[var(--accent-green)]/40 bg-[var(--accent-green)]/10 px-4 py-1.5 text-xs text-[var(--accent-green)]"><Activity className="h-3.5 w-3.5 animate-pulse" /><span className="font-medium">CONTROLLED LAN SIMULATION ACTIVE</span><span className="text-[var(--text-secondary)]">— telemetry and attacker actions are isolated to Demo‑2</span></div>;
}

function DemoKpiRow() {
  const [overview, setOverview] = useState<any>(null);
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try { const result = await fetch(`${demoApiBase()}/command/overview`); if (!result.ok) throw new Error(); const data = await result.json(); if (!cancelled) setOverview(data); } catch { if (!cancelled) setOverview(null); }
    };
    load(); const interval = window.setInterval(load, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);
  const values = [
    ['Live assets', overview?.online_assets], ['Active threats', overview?.threats], ['Contained', overview?.contained],
    ['Decoys', overview?.decoys], ['Trapped', overview?.trapped], ['Range service', overview?.service?.status?.toUpperCase()],
  ];
  return <div aria-label="Demo range summary" className="console-shell-chrome grid grid-cols-2 gap-2 border-b border-[var(--border-primary)] px-3 py-3 sm:grid-cols-3 lg:grid-cols-6 sm:px-4">{values.map(([label, value]) => <div key={String(label)} className="console-metric min-w-0 rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-3 py-3"><div className="text-[11px] font-medium text-[var(--text-secondary)]">{label}</div><div className="my-1 text-2xl font-semibold leading-snug text-[var(--text-primary)]">{value ?? '—'}</div><div className="text-[10px] text-[var(--text-secondary)]">Live Demo‑2 telemetry</div></div>)}</div>;
}

function LanBridgeBanner() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [joinUrl, setJoinUrl] = useState('');
  const [commandCenterUrl, setCommandCenterUrl] = useState('');
  const [copied, setCopied] = useState(false);
  const [source, setSource] = useState<'config' | 'fallback'>('fallback');

  useEffect(() => {
    let cancelled = false;
    const draw = async () => {
      if (typeof window === 'undefined') return;
      const fallbackBase = process.env.NEXT_PUBLIC_DEMO_PUBLIC_URL || window.location.origin;
      let base = fallbackBase;
      let resolvedSource: 'config' | 'fallback' = 'fallback';

      try {
        const demoApiBase = (process.env.NEXT_PUBLIC_DEMO_API_URL || `http://${window.location.hostname}:8100/api/demo`).replace(/\/$/, '');
        const res = await fetch(`${demoApiBase}/config`);
        if (res.ok) {
          const config = await res.json();
          if (typeof config?.public_base_url === 'string' && config.public_base_url.trim()) {
            base = config.public_base_url.trim();
            resolvedSource = 'config';
          }
        }
      } catch {
        // Keep fallback.
      }

      const cleaned = base.replace(/\/$/, '');
      const nextJoin = `${cleaned}/join`;
      const nextCenter = cleaned;

      if (cancelled) return;
      setJoinUrl(nextJoin);
      setCommandCenterUrl(nextCenter);
      setSource(resolvedSource);

      if (canvasRef.current) {
        await QRCode.toCanvas(canvasRef.current, nextJoin, {
          width: 172,
          margin: 1,
          color: { dark: '#09111f', light: '#dbe7ff' },
        });
      }
    };

    draw().catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  if (!joinUrl) {
    return (
      <div className="border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] px-4 py-3 text-xs text-[var(--text-secondary)]">
        Resolving LAN share address…
      </div>
    );
  }

  return (
    <div className="border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] px-4 py-4">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="min-w-0 space-y-2">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded-full border border-[var(--accent-green)]/30 bg-[var(--accent-green)]/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--accent-green)]">
              <QrCode className="h-3 w-3" />
              LAN demo bridge
            </span>
            <span className="text-[11px] text-[var(--text-secondary)]">
              Source: {source === 'config' ? 'demo config' : 'browser fallback'}
            </span>
          </div>
          <p className="text-sm text-[var(--text-secondary)]">
            Scan the code to open the live demo join page on the host network. The URL is resolved from the LAN base when available, so it avoids hardcoding localhost.
          </p>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="rounded-md border border-[var(--border-primary)] bg-[var(--bg-tertiary)] px-2 py-1 font-mono text-[var(--text-primary)] break-all">
              {joinUrl}
            </span>
            <button
              type="button"
              onClick={async () => {
                await navigator.clipboard.writeText(joinUrl);
                setCopied(true);
                window.setTimeout(() => setCopied(false), 1500);
              }}
              className="inline-flex items-center gap-1 rounded-md border border-[var(--border-primary)] px-2 py-1 text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]"
            >
              <Copy className="h-3.5 w-3.5" />
              {copied ? 'Copied' : 'Copy join URL'}
            </button>
            <a href={joinUrl} target="_blank" rel="noreferrer" className="rounded-md border border-[var(--accent-blue)]/30 bg-[var(--accent-blue)]/10 px-2 py-1 text-[var(--accent-blue)] hover:bg-[var(--accent-blue)]/15">
              Open join page
            </a>
            <a href={commandCenterUrl} target="_blank" rel="noreferrer" className="rounded-md border border-[var(--accent-blue)]/30 bg-[var(--bg-tertiary)] px-2 py-1 text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]">
              Open demo command center
            </a>
          </div>
        </div>
        <div className="flex items-center gap-4 rounded-xl border border-[var(--border-primary)] bg-[var(--bg-primary)] p-3">
          <canvas ref={canvasRef} aria-label="QR code for LAN join" className="rounded-lg bg-[var(--bg-secondary)] p-1" />
          <div className="max-w-xs text-xs text-[var(--text-secondary)]">
            <p className="font-medium text-[var(--text-primary)]">LAN connection flow</p>
            <ul className="mt-1 space-y-1 leading-5">
              <li>1. Use the QR or the join link.</li>
              <li>2. Devices register on the same host network.</li>
              <li>3. The topology and telemetry stay aligned with the live range.</li>
            </ul>
          </div>
        </div>
      </div>
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
    { label: 'Open incidents', value: incidentsAvailable ? open : '—', detail: incidentsAvailable ? 'In loaded incidents' : 'Data unavailable' },
    { label: 'Suspicious assets', value: metricsAvailable ? metrics?.suspicious_assets ?? '—' : '—', detail: 'Inventory snapshot' },
    { label: 'Critical incidents', value: incidentsAvailable ? critical : '—', detail: incidentsAvailable ? 'In loaded incidents' : 'Data unavailable' },
    { label: 'Compromised assets', value: metricsAvailable ? metrics?.compromised_assets ?? '—' : '—', detail: 'Inventory snapshot' },
    { label: 'Vulnerabilities', value: metricsAvailable ? metrics?.vulnerabilities ?? '—' : '—', detail: 'Recorded findings' },
    { label: 'Monitored assets', value: metricsAvailable ? metrics?.assets ?? '—' : '—', detail: 'Inventory snapshot' },
  ];

  return (
    <div aria-label="Operations summary" className="console-shell-chrome grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 px-3 py-3 sm:px-4 border-b border-[var(--border-primary)]">
      {kpi.map((k) => (
        <div key={k.label} className="console-metric min-w-0 bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-xl px-3 py-3">
          <div className="text-[11px] font-medium text-[var(--text-secondary)]">{k.label}</div>
          <div className="my-1 text-2xl font-semibold tabular-nums leading-snug text-[var(--text-primary)]">{k.value}</div>
          <div className="text-[10px] text-[var(--text-secondary)]">{k.value === '—' ? 'Data unavailable' : k.detail}</div>
        </div>
      ))}
    </div>
  );
}

export function CommandCenter({ mode = 'main' }: CommandCenterProps) {
  const { activeIncident, incidents } = useIncidentStore();
  const { nodes, edges, predictionEdges, setNodes } = useTopologyStore();
  const { currentForecast } = usePredictionStore();
  const { sidebarOpen, activeView, theme, setSidebarOpen } = useUIStore();
  const [incidentDetail, setIncidentDetail] = useState(false);
  const [authRequired, setAuthRequired] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'unavailable' | 'unauthorized'>('connecting');
  const [incidentsAvailable, setIncidentsAvailable] = useState(false);
  const [selectedDemoNode, setSelectedDemoNode] = useState<any>(null);
  const [demoCapture, setDemoCapture] = useState<any>(null);
  // Demo topology renderer: guided SVG theatre (honeynet zones narrative) or
  // the main application's Cytoscape canvas with its full controls toolbar.
  const [topoMode, setTopoMode] = useState<'theatre' | 'graph'>('theatre');

  useEffect(() => {
    if (window.matchMedia("(max-width: 1023px)").matches) setSidebarOpen(false);
  }, [setSidebarOpen]);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      if (mode === 'lan-demo' && demoCapture) return;
      try {
        const res = await fetch(mode === 'lan-demo' ? `${demoApiBase()}/command/topology` : `${API}/topology`, { headers: mode === 'lan-demo' ? {} : authHeaders() });
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
        useTopologyStore.getState().setEdges((Array.isArray(data.edges) ? data.edges : []).map(mapDemoEdge));
        const predicted = Array.isArray(data.prediction_edges)
          ? data.prediction_edges
          : (data.predictions || []).flatMap((prediction: any, index: number) =>
              (prediction?.steps || []).map((step: any, stepIndex: number) => ({
                id: `forecast-${index}-${stepIndex}`,
                source: prediction.origin || '',
                target: step.target_asset_id || prediction.predicted_target || '',
                probability: step.probability || prediction.confidence || 0,
                predicted_stage: step.stage || '',
                eta_seconds: step.eta_seconds || 0,
                created_at: new Date().toISOString(),
              })),
            ).filter((edge: any) => edge.source && edge.target);
        useTopologyStore.getState().setPredictionEdges(predicted);
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
  }, [setNodes, mode, demoCapture]);

  // Demo-2 exposes forecasts from its isolated range API rather than relying
  // on the main application's websocket. Prefer the active forecast, then a
  // forecast from any still-active trajectory if a newer recon-only incident
  // has not yet generated one.
  useEffect(() => {
    if (mode !== 'lan-demo') return;
    let cancelled = false;
    const poll = async () => {
      try {
        const response = await fetch(`${demoApiBase()}/command/forecast`);
        if (!response.ok) throw new Error('Demo forecast unavailable');
        const data = await response.json();
        const prediction = data.prediction || data.incidents?.find((item: any) => item.prediction)?.prediction;
        if (!prediction || cancelled) return;
        const stages = Array.isArray(prediction.predicted_stages) ? prediction.predicted_stages : [];
        const probability = Math.max(0, Math.min(1, Number(prediction.confidence) || 0));
        const leadTime = Math.max(0, Number(prediction.lead_time) || 0);
        const target = prediction.predicted_target || data.incident?.predicted_target || 'Protected service';
        usePredictionStore.getState().setForecast({
          incident_id: prediction.incident_id || data.incident?.id || 'demo-range',
          current_stage: prediction.current_stage || data.incident?.stage || 'reconnaissance',
          current_confidence: probability,
          timeline: stages.map((stage: string, index: number) => ({
            window_offset: index + 1,
            stage,
            probability: Math.min(0.99, probability + (index * (1 - probability)) / Math.max(1, stages.length)),
            target_asset_name: target,
            eta_seconds: leadTime ? leadTime * ((index + 1) / Math.max(1, stages.length)) : 0,
            confidence: probability,
          })),
          predicted_targets: [{ asset_id: target, asset_name: target, asset_type: 'range asset', probability, reasoning: prediction.explanation?.top_factors?.map((factor: any) => factor.description || factor.feature) || [] }],
          explanation: prediction.explanation || { feature_importance: {}, top_factors: [], natural_language: 'The controlled range is collecting the next telemetry window.' },
          generated_at: new Date().toISOString(),
          model_version: prediction.model || 'flow-wm-v3.0.0',
        } as any);
      } catch {
        // Preserve the most recent valid forecast during a brief API outage.
      }
    };
    poll();
    const interval = window.setInterval(poll, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [mode]);

  // Populate the incident list and auto-select the first open incident so
  // forecast / threat-actor / forensics views have an active incident context.
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const data = mode === 'lan-demo'
          ? await fetch(`${demoApiBase()}/command/overview`).then(async response => {
              if (!response.ok) throw new Error('Demo range unavailable');
              const overview = await response.json();
              const cur = useIncidentStore.getState().activeIncident;
              return {
                items: (overview.incidents || []).map((incident: any) => ({
                  id: incident.id,
                  title: `Simulated trajectory · ${incident.actor || 'unknown actor'}`,
                  description: `Predicted target: ${incident.predicted_target || 'calculating'}`,
                  severity: incident.prediction?.risk_level === 'critical' ? 'critical' : incident.prediction?.risk_level === 'high' ? 'high' : 'medium',
                  status: incident.trapped || incident.status === 'contained' ? 'contained' : 'open',
                  detected_at: new Date().toISOString(),
                  current_stage: incident.stage,
                  threat_score: (incident.prediction?.risk_score || 0) / 100,
                  attacker: incident.actor,
                  predicted_target: incident.predicted_target,
                  predicted_target_id: incident.predicted_target_id,
                  timeline_events: cur?.id === incident.id ? cur.timeline_events : undefined,
                  evidence: cur?.id === incident.id ? cur.evidence : undefined,
                }))
              };
            })
          : await api.get<any>('/incidents?page_size=50');
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
  }, [mode]);

  return (
    <div className={cn(theme === 'light' && 'light', 'h-[100dvh] w-full flex flex-col bg-[var(--bg-primary)] text-[var(--text-primary)]')}>
      <Header
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => useUIStore.getState().toggleSidebar()}
        theme={theme}
        onToggleTheme={() => useUIStore.getState().toggleTheme()}
        activeIncident={activeIncident}
        connectionStatus={connectionStatus}
        demoMode={mode === 'lan-demo'}
      />

      <NavBar demoMode={mode === 'lan-demo'} />

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
          {mode === 'lan-demo' ? <DemoSimulationBanner /> : <SimulationBanner />}
          {authRequired && (
            <div role="alert" className="console-shell-chrome flex items-center gap-2 border-b border-[var(--accent-yellow)]/40 bg-[var(--accent-yellow)]/10 px-4 py-2 text-sm text-[var(--accent-yellow)]">
              Sign in from the header as an administrator for console controls, or continue as a view-only guest to inspect incidents, topology and telemetry.
            </div>
          )}

          {activeView === 'command-center' && (
            <div className="flex-1 min-h-0 flex flex-col overflow-y-auto">
              {mode === 'lan-demo' ? <DemoKpiRow /> : <KpiRow incidentsAvailable={incidentsAvailable} />}
              <div className="flex-none xl:flex-1 min-h-[30rem] flex flex-col xl:flex-row">
                <div className="w-full min-h-[30rem] xl:min-h-0 xl:w-3/5 xl:h-full border-b xl:border-b-0 xl:border-r border-[var(--border-primary)] flex flex-col">
                  <div className="p-3 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)]">
                    <div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-lg font-semibold text-[var(--text-primary)]">Network Topology</h2><p className="text-xs text-[var(--text-secondary)]">{nodes.size} assets • {edges.size} connections • {predictionEdges.size} predictions</p></div>{mode === 'lan-demo' && <div role="group" aria-label="Topology renderer" className="inline-flex overflow-hidden rounded-lg border border-[var(--border-primary)]"><button type="button" aria-pressed={topoMode === 'theatre'} onClick={() => setTopoMode('theatre')} className={`px-3 py-1.5 text-xs font-medium ${topoMode === 'theatre' ? 'bg-[var(--accent-blue)] text-white' : 'bg-[var(--bg-secondary)] text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]'}`}>Theatre</button><button type="button" aria-pressed={topoMode === 'graph'} onClick={() => setTopoMode('graph')} className={`px-3 py-1.5 text-xs font-medium ${topoMode === 'graph' ? 'bg-[var(--accent-blue)] text-white' : 'bg-[var(--bg-secondary)] text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]'}`}>Graph</button></div>}</div>
                  </div>
                  <div className="flex-1 min-h-[24rem] relative">
                    {mode === 'lan-demo'
                      ? topoMode === 'graph'
                        ? <TopologyCanvas />
                        : <><DemoTopology onSelectNode={setSelectedDemoNode} />{selectedDemoNode && <DemoNodePanel node={selectedDemoNode} onClose={() => setSelectedDemoNode(null)} />}</>
                      : <TopologyCanvas />}
                    <ModelDecisionHUD />
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
                        onSelect={(inc) => {
                          const cur = useIncidentStore.getState().activeIncident;
                          const merged = cur?.id === inc.id
                            ? { ...inc, timeline_events: cur.timeline_events, evidence: cur.evidence }
                            : inc;
                          useIncidentStore.getState().setActiveIncident(merged);
                          setIncidentDetail(true);
                        }}
                      />
                    )}
                  </div>
                </div>
              </div>

              {/* Bottom Operational Drawer: 3 Spacious Columns (Timeline, Forensics, Intelligence) with ZERO Overlap */}
              <div className="flex-none min-h-[20rem] xl:h-[22rem] border-t border-[var(--border-primary)] grid grid-cols-1 xl:grid-cols-3 divide-y xl:divide-y-0 xl:divide-x divide-[var(--border-primary)] bg-[var(--bg-secondary)] overflow-hidden">
                <div className="w-full h-full min-h-[16rem] overflow-hidden">
                  <Timeline className="w-full h-full" />
                </div>
                <div className="w-full h-full min-h-[16rem] overflow-hidden">
                  <EvidenceTabs className="w-full h-full" incidentId={activeIncident?.id} />
                </div>
                <div className="w-full h-full min-h-[16rem] overflow-hidden">
                  {mode === 'lan-demo' ? <ActorIntelPanel /> : <WorldModelPanel />}
                </div>
              </div>
            </div>
          )}

          {activeView === 'threat-actors' && (mode === 'lan-demo' ? <DemoWorkspaceView view="threat-actors" /> : <ThreatActorsView />)}
          {activeView === 'attack' && (mode === 'lan-demo' ? <DemoWorkspaceView view="attack" /> : <AttackForecastView />)}
          {activeView === 'deception' && (mode === 'lan-demo' ? <DemoWorkspaceView view="deception" /> : <DeceptionView />)}
          {activeView === 'forensics' && (mode === 'lan-demo' ? <DemoWorkspaceView view="forensics" /> : <ForensicsView />)}
          {activeView === 'infrastructure' && (mode === 'lan-demo' ? <DemoWorkspaceView view="infrastructure" /> : <InfrastructureView />)}
          {activeView === 'model-lab' && (mode === 'lan-demo' ? <DemoWorkspaceView view="model-lab" /> : <ModelLabView />)}
          {activeView === 'ai-intelligence' && (mode === 'lan-demo' ? <DemoWorkspaceView view="ai-intelligence" /> : <AIIntelligenceView />)}
          {activeView === 'presentation' && <PresentationModeView />}
          {activeView === 'mitigation-cache' && <MitigationCacheView />}
          {activeView === 'graph-analysis' && <GraphAnalysisView />}
          {activeView === 'passive-analysis' && <PassiveAnalysisView />}
          {activeView === 'settings' && (mode === 'lan-demo' ? <DemoWorkspaceView view="settings" /> : <SettingsView />)}
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
