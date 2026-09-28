"use client";

import { useEffect, useLayoutEffect, useRef, useState, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { Capture, PcapReplay } from './PcapReplay';
import { useTopologyStore } from '@/store/topologyStore';
import { usePredictionStore } from '@/store/predictionStore';
import { useUIStore } from '@/store/uiStore';
import { cn } from '@/utils/classnames';
import { TopologyNode } from '@/types';
import { NodePanel } from '../topology/NodePanel';
import { Legend } from '../topology/Legend';
import { MiniMap } from '../topology/MiniMap';
import { Controls } from '../topology/Controls';

// Visual identity per device type: (shape, color, emoji, criticality rank).
const CRITICALITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function criticalityRank(value?: string): number {
  return CRITICALITY_RANK[(value || 'medium').toLowerCase()] ?? 1;
}

function deviceVisual(assetType?: string, os?: string, zone?: string): { shape: string; color: string; icon: string } {
  const t = (assetType || '').toLowerCase();
  const z = (zone || '').toLowerCase();
  const o = (os || '').toLowerCase();

  // Phones / tablets / laptops -> phone-ish.
  if (['android', 'apple_mobile', 'ios'].includes(o) || z === 'user_zone') {
    return { shape: 'round-rectangle', color: '#6366F1', icon: '📱' };
  }
  if (['macos', 'windows', 'linux'].includes(o) || t === 'workstation') {
    return { shape: 'round-rectangle', color: '#0EA5E9', icon: '🖥️' };
  }
  if (['database'].includes(t)) {
    return { shape: 'cylinder', color: '#8B5CF6', icon: '🗄️' };
  }
  if (['domain_controller'].includes(t)) {
    return { shape: 'rectangle', color: '#EC4899', icon: '🛡️' };
  }
  if (['web_server', 'server'].includes(t) || z === 'server_zone') {
    return { shape: 'rectangle', color: '#3B82F6', icon: '🖥️' };
  }
  if (['router', 'switch', 'firewall'].includes(t) || z === 'management') {
    return { shape: 'diamond', color: '#F59E0B', icon: '🌐' };
  }
  if (['honeypot'].includes(t) || z === 'honeynet') {
    return { shape: 'diamond', color: '#F43F5E', icon: '🪤' };
  }
  if (['iot_device'].includes(t) || z === 'iot_zone') {
    return { shape: 'star', color: '#22C55E', icon: '📷' };
  }
  return { shape: 'ellipse', color: '#94A3B8', icon: '❓' };
}

// Node data for each node.
function nodeVisualData(
  nodeId: string,
  label: string,
  assetType?: string,
  os?: string,
  zone?: string,
  criticality?: string,
): { shape: string; color: string; icon: string; critRank: number; displayLabel: string } {
  const v = deviceVisual(assetType, os, zone);
  return {
    shape: v.shape,
    color: v.color,
    icon: v.icon,
    critRank: criticalityRank(criticality),
    displayLabel: label,
  };
}

export function TopologyCanvas() {
  const { 
    nodes, 
    edges, 
    predictionEdges,
    layout,
    setLayout,
  } = useTopologyStore();
  const { theme } = useUIStore();
  const { currentForecast, latestDecision } = usePredictionStore();
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [capture, setCapture] = useState<Capture | null>(null);
  const [frame, setFrame] = useState(0);
  const [maximized, setMaximized] = useState(false);
  const [host, setHost] = useState<HTMLDivElement | null>(null);
  const anchor = useRef<HTMLDivElement>(null);
  const [error, setError] = useState('');
  const currentNodes = useMemo(() => capture ? new Map(capture.nodes.map(n => [n.id, n])) : nodes, [capture, nodes]);
  const nodesRef = useRef(currentNodes);
  nodesRef.current = currentNodes;
  useEffect(() => { setHost(document.createElement('div')); }, []);
  useLayoutEffect(() => {
    if (!host || !anchor.current) return;
    host.style.height = '100%';
    (maximized ? document.body : anchor.current).appendChild(host);
    return () => { host.remove(); };
  }, [host, maximized]);
  useEffect(() => {
    if (!maximized) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = previous; };
  }, [maximized]);
  const [containerRef, setContainerRef] = useState<HTMLDivElement | null>(null);
  const fullscreenRef = useRef<HTMLDivElement | null>(null);
  const [showNodePanel, setShowNodePanel] = useState(false);
  const [cytoscapeInstance, setCytoscapeInstance] = useState<any>(null);
  const [fullscreen, setFullscreen] = useState(false);

  // Convert nodes/edges to Cytoscape format
  const cyNodes = useMemo(() => Array.from(currentNodes.values()).map(node => {
    const v = nodeVisualData(
      node.id,
      node.label,
      node.asset_type,
      node.metadata?.os,
      node.zone,
      node.criticality,
    );
    return {
      data: {
        ...node.metadata,
        id: node.id,
        label: node.label,
        displayLabel: `${v.icon} ${v.displayLabel}`,
        assetId: node.asset_id,
        assetType: node.asset_type,
        zone: node.zone,
        status: node.status,
        threatScore: node.threatScore,
        criticality: node.criticality,
        critRank: criticalityRank(node.criticality),
        shape: v.shape,
        color: v.color,
        original: node,
      },
      position: node.position || { x: 0, y: 0 },
      classes: `status-${node.status} ${node.asset_type} ${node.zone} crit-${(node.criticality || 'medium').toLowerCase()}`,
    };
  }), [currentNodes]);

  const cyEdges = useMemo(() => {
    const baseReal = (capture ? capture.edges : Array.from(edges.values())).map(edge => ({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        protocol: edge.protocol,
        port: edge.port,
        bytes: edge.bytes_transferred,
        packets: edge.packet_count,
        isPredicted: false,
      },
      classes: `real ${edge.protocol?.toLowerCase() || ''}`,
    }));

    const basePredicted = (capture ? [] : Array.from(predictionEdges.values())).map(edge => ({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        probability: edge.probability,
        predictedStage: edge.predicted_stage || 'Attack Path',
        eta: edge.eta_seconds,
        isPredicted: true,
      },
      classes: 'predicted',
    }));

    // Autonomous Model Decision Diversion edge
    const activeDecision = latestDecision || currentForecast?.model_decision;
    const isDivert = activeDecision?.action?.includes('DIVERT') || activeDecision?.action?.includes('DECEPTION');
    const nodesList = Array.from(currentNodes.values());
    const targetAssetId = currentForecast?.predicted_targets?.[0]?.asset_id;
    const victim = nodesList.find(n => ['suspicious', 'under_attack', 'compromised'].includes(n.status)) ||
                   (targetAssetId ? (currentNodes.get(targetAssetId) || nodesList.find(n => n.asset_id === targetAssetId)) : null);
    const honeypot = nodesList.find(n => n.status === 'deception' || n.metadata?.role === 'decoy' || n.zone === 'honeynet');

    const diversionEdges = (isDivert && victim && honeypot && victim.id !== honeypot.id) ? [{
      data: {
        id: 'model-deception-divert-edge',
        source: victim.id,
        target: honeypot.id,
        predictedStage: 'DECEPTION DIVERT (-84%)',
        isPredicted: true,
      },
      classes: 'predicted divert',
    }] : [];

    return [...baseReal, ...basePredicted, ...diversionEdges].filter(
      edge => currentNodes.has(edge.data.source) && currentNodes.has(edge.data.target)
    );
  }, [capture, edges, predictionEdges, currentNodes, currentForecast, latestDecision]);

  // The callback ref arrives after mount. Initialize against that element,
  // and cancel async imports on unmount/StrictMode cleanup.
  useEffect(() => {
    if (!containerRef) return;
    let cancelled = false;
    let cy: any;
    let observer: ResizeObserver | undefined;
    setCytoscapeInstance(null);
    Promise.all([import('cytoscape'), import('cytoscape-cose-bilkent'), import('cytoscape-dagre')])
      .then(([{ default: cytoscape }, { default: cose }, { default: dagre }]) => {
        if (cancelled) return;
        cytoscape.use(cose); cytoscape.use(dagre);
        cy = cytoscape({ container: containerRef, elements: [], layout: { name: 'preset' }, minZoom: 0.05, maxZoom: 4, wheelSensitivity: 0.2 });
        cy.on('tap', 'node', (event: any) => {
          setSelectedNode(nodesRef.current.get(event.target.id()) || null);
          setShowNodePanel(true);
        });
        cy.on('tap', (event: any) => { if (event.target === cy) { setSelectedNode(null); setShowNodePanel(false); } });
        observer = new ResizeObserver(() => {
          if (cy.destroyed()) return;
          cy.resize();
          if (cy.nodes().length && cy.width() > 0 && cy.height() > 0) cy.fit(cy.elements(), 45);
        });
        observer.observe(containerRef);
        setCytoscapeInstance(cy);
      }).catch(() => { if (!cancelled) setError('The topology renderer could not load. Refresh to retry.'); });
    return () => { cancelled = true; observer?.disconnect(); cy?.destroy(); };
  }, [containerRef]);

  useEffect(() => {
    const onChange = () => setFullscreen(document.fullscreenElement === fullscreenRef.current);
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !document.fullscreenElement) { setMaximized(false); setError(''); }
    };
    document.addEventListener('fullscreenchange', onChange);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('fullscreenchange', onChange); document.removeEventListener('keydown', onKey); };
  }, []);

  useEffect(() => {
    if (!cytoscapeInstance) return;
    const cy = cytoscapeInstance;
    const nextIds = cyNodes.map(n => n.data.id).sort().join(',');
    const relayout = cy._prevNodeIds !== nextIds || cy._prevLayout !== layout;
    const desired = [...cyNodes, ...cyEdges];
    const ids = new Set(desired.map(e => e.data.id));
    cy.batch(() => {
      cy.elements().filter((e: any) => !ids.has(e.id())).remove();
      for (const element of desired) {
        const existing = cy.getElementById(element.data.id);
        if (existing.length) { existing.data(element.data); existing.classes(element.classes); }
        else cy.add(element);
      }
    });
    cy._prevNodeIds = nextIds; cy._prevLayout = layout;
    if (relayout) { cy.stop(); cy.layout(buildLayout(layout)).run(); }
  }, [cyNodes, cyEdges, layout, cytoscapeInstance]);

  useEffect(() => { cytoscapeInstance?.style(getStylesheet(theme)); }, [theme, cytoscapeInstance]);
  useEffect(() => {
    if (!cytoscapeInstance || !capture) return;
    const totals = new Map<string, {packets: number; bytes: number}>();
    capture.frames.slice(0, frame + 1).forEach(f => f.edges.forEach(e => {
      const total = totals.get(e.id) || {packets: 0, bytes: 0};
      total.packets += e.packets; total.bytes += e.bytes; totals.set(e.id, total);
    }));
    const active = new Set(capture.frames[frame]?.edges.map(e => e.id));
    cytoscapeInstance.batch(() => cytoscapeInstance.edges().forEach((e: any) => {
      const total = totals.get(e.id());
      e.data({ packets: total?.packets || 0, bytes: total?.bytes || 0 });
      e.toggleClass('replay-pending', !total); e.toggleClass('replay-active', active.has(e.id()));
    }));
  }, [capture, frame, cytoscapeInstance, cyEdges]);

  const fit = () => {
    if (!cytoscapeInstance || cytoscapeInstance.destroyed()) return;
    cytoscapeInstance.stop(); cytoscapeInstance.resize();
    if (cytoscapeInstance.nodes().length) cytoscapeInstance.fit(cytoscapeInstance.elements(), 45);
  };
  useEffect(() => { const id = requestAnimationFrame(fit); return () => cancelAnimationFrame(id); }, [maximized, fullscreen, cytoscapeInstance]);
  const zoom = (factor: number) => {
    const cy = cytoscapeInstance; if (!cy) return;
    cy.zoom({ level: Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor)), renderedPosition: {x: cy.width() / 2, y: cy.height() / 2} });
  };

  // Build cytoscape layout options; 'criticality' arranges nodes into
  // concentric layers from LEAST critical (outer) to MOST critical (inner).
  function buildLayout(name: string): any {
    if (name === 'criticality') {
      return {
        name: 'concentric',
        concentric: (node: any) => criticalityRank(node.data('criticality')) + 1,
        levelWidth: () => 1,
        minNodeSpacing: 40,
        padding: 50,
        animate: false,
        animationDuration: 500,
        fit: true,
        nodeDimensionsIncludeLabels: true,
      } as any;
    }
    return {
      name: name || 'cose-bilkent',
      animate: false,
      animationDuration: 500,
      fit: true,
      padding: 50,
      randomize: false,
      nodeDimensionsIncludeLabels: true,
    } as any;
  }

  // Get Cytoscape stylesheet
  function getStylesheet(currentTheme = theme): any[] {
    const light = currentTheme === 'light';
    return [
      {
        selector: 'node',
        style: {
          'label': 'data(displayLabel)',
          'font-size': '11px',
          'font-weight': '600',
          'color': light ? '#0F172A' : '#E5EDF9',
          'text-outline-width': 2,
          'text-outline-color': light ? '#FFFFFF' : '#05070D',
          'text-valign': 'bottom',
          'text-margin-y': 12,
          'shape': 'data(shape)',
          'width': 'mapData(threatScore, 0, 1, 22, 52)',
          'height': 'mapData(threatScore, 0, 1, 22, 52)',
          'background-color': 'data(color)',
          'border-width': 2,
          'border-color': light ? '#FFFFFF' : '#E2E8F0',
          'overlay-color': '#8C6BFF',
          'overlay-opacity': 0,
          'z-index': 10,
        },
      },
      {
        selector: 'node.status-normal',
        style: { 'border-color': '#28C98B', 'border-width': 2 },
      },
      {
        selector: 'node.status-suspicious',
        style: { 'border-color': '#D3A233', 'border-width': 3 },
      },
      {
        selector: 'node.status-compromised',
        style: { 'border-color': '#FF6A80', 'border-width': 3, 'overlay-color': '#FF6A80', 'overlay-opacity': 0.12 },
      },
      {
        selector: 'node.status-contained',
        style: { 'border-color': '#5F8BFF', 'border-style': 'dashed', 'border-width': 3 },
      },
      {
        selector: 'node.status-deception',
        style: { 'border-color': '#9B7DFF', 'border-style': 'dashed', 'border-width': 3, 'shape': 'diamond' },
      },
      {
        selector: 'node.status-offline',
        style: { 'background-color': '#5F6B82', 'opacity': 0.58 },
      },
      // Criticality layers: from least (low) to most (critical) critical,
      // expressed as a distinct outer glow + ring so the tier is readable.
      {
        selector: 'node.crit-low',
        style: { 'border-color': '#28C98B', 'border-width': 1.5, 'background-blacken': 0 },
      },
      {
        selector: 'node.crit-medium',
        style: { 'border-color': '#D3A233', 'border-width': 2.5 },
      },
      {
        selector: 'node.crit-high',
        style: { 'border-color': '#FF9D4D', 'border-width': 3.5 },
      },
      {
        selector: 'node.crit-critical',
        style: {
          'border-color': '#FF5C7A',
          'border-width': 4.5,
          'overlay-color': '#FF5C7A',
          'overlay-opacity': 0.1,
        },
      },
      {
        selector: 'node:selected',
        style: {
          'border-width': 4,
          'border-color': '#5F8BFF',
          'overlay-color': '#5F8BFF',
          'overlay-opacity': 0.18,
        },
      },
      {
        selector: 'edge',
        style: {
          'width': 2.4,
          'line-color': '#43566F',
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'target-arrow-color': '#43566F',
          'arrow-scale': 0.8,
          'opacity': 0.7,
        },
      },
      {
        selector: 'edge.predicted',
        style: {
          'width': 3.6,
          'line-color': '#F59E0B',
          'line-style': 'dashed',
          'target-arrow-shape': 'triangle',
          'target-arrow-color': '#F59E0B',
          'opacity': 0.9,
          'label': 'data(predictedStage)',
          'font-size': '9px',
          'color': '#FBBF24',
          'text-outline-color': '#05070D',
          'text-outline-width': 2,
        },
      },
      {
        selector: 'edge.divert',
        style: {
          'width': 4.2,
          'line-color': '#C084FC',
          'line-style': 'dashed',
          'target-arrow-shape': 'triangle',
          'target-arrow-color': '#C084FC',
          'opacity': 0.95,
          'label': 'data(predictedStage)',
          'font-size': '9px',
          'color': '#E9D5FF',
          'text-outline-color': '#05070D',
          'text-outline-width': 2,
        },
      },
      {
        selector: 'edge:selected',
        style: {
          'width': 4,
          'line-color': '#5F8BFF',
          'target-arrow-color': '#5F8BFF',
        },
      },
      {
        selector: '.real',
        style: {
          'opacity': 0.76,
        },
      },
      {
        selector: '.predicted',
        style: {
          'opacity': 0.56,
        },
      },
      { selector: 'edge.replay-pending', style: { opacity: 0.08 } },
      { selector: 'edge.replay-active', style: { 'line-color': '#38BDF8', 'target-arrow-color': '#38BDF8', width: 5.2, opacity: 1 } },
    ];
  }

  const view = <section ref={fullscreenRef} aria-label="Network topology workspace" className={cn(
    'topology-workspace flex flex-col overflow-hidden bg-[var(--bg-primary)] text-[var(--text-primary)]',
    theme === 'light' && 'light', maximized ? 'fixed inset-0 z-[100] h-[100dvh] w-screen' : 'relative h-full w-full',
  )}>
    <Controls ready={!!cytoscapeInstance} onZoomIn={() => zoom(1.2)} onZoomOut={() => zoom(1 / 1.2)} onFit={fit}
      maximized={maximized || fullscreen} isFullscreen={fullscreen} currentLayout={layout} onLayoutChange={setLayout}
      onMaximize={async () => {
        if (document.fullscreenElement === fullscreenRef.current) await document.exitFullscreen();
        setError('');
        setMaximized(fullscreen ? false : !maximized);
      }}
      onFullscreen={async () => {
        if (document.fullscreenElement === fullscreenRef.current) { await document.exitFullscreen(); return; }
        try {
          if (!fullscreenRef.current?.requestFullscreen) throw new Error('Fullscreen unavailable');
          await fullscreenRef.current.requestFullscreen(); setError('');
        }
        catch { setMaximized(true); setError('Browser fullscreen is unavailable; topology is maximized. Use Minimize or Escape to restore it.'); }
      }} />
    <PcapReplay capture={capture} onCapture={value => { setCapture(value); setSelectedNode(null); }} frame={frame} onFrame={setFrame} onLive={() => { setCapture(null); setSelectedNode(null); setFrame(0); }} />
    {error && <p role="status" className="shrink-0 px-3 py-1 text-xs text-[var(--text-secondary)]">{error}</p>}
    <div className="relative flex min-h-0 flex-1">
      <div className="relative min-w-0 flex-1">
        <div ref={setContainerRef} data-testid="topology-canvas" className="absolute inset-0" />
        {!currentNodes.size && <p className="pointer-events-none absolute inset-0 flex items-center justify-center p-6 text-center text-sm text-[var(--text-secondary)]">No live assets loaded. Sign in to view live telemetry or upload a PCAP to replay captured connections.</p>}
        <Legend /><MiniMap cy={cytoscapeInstance} />
      </div>
      {showNodePanel && selectedNode && <NodePanel key={selectedNode.id} node={selectedNode} readOnly={!!capture} onClose={() => { setShowNodePanel(false); setSelectedNode(null); }} />}
    </div>
  </section>;
  return <div ref={anchor} className="h-full w-full">{host && createPortal(view, host)}</div>;
}
