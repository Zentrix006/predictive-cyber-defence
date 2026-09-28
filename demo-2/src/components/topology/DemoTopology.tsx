"use client";

import { useMemo } from 'react';
import { useTopologyStore } from '@/store/topologyStore';
import { usePredictionStore } from '@/store/predictionStore';
import { useUIStore } from '@/store/uiStore';
import { cn } from '@/utils/classnames';

type Point = { x: number; y: number };
type VisualNode = any;

const DARK_STATUS_STYLE: Record<string, { color: string; ring: 'none' | 'breathe' | 'alert' | 'contain' | 'repair' | 'decoy'; label: string }> = {
  healthy: { color: '#25d695', ring: 'none', label: 'UP' },
  normal: { color: '#25d695', ring: 'none', label: 'UP' },
  suspicious: { color: '#f5b942', ring: 'breathe', label: 'SUSPICIOUS' },
  under_attack: { color: '#ff6a70', ring: 'alert', label: 'UNDER ATTACK' },
  compromised: { color: '#ff4e66', ring: 'alert', label: 'COMPROMISED' },
  contained: { color: '#649bff', ring: 'contain', label: 'CONTAINED' },
  maintenance: { color: '#e6b84e', ring: 'repair', label: 'MAINTENANCE' },
  deception: { color: '#b482ff', ring: 'decoy', label: 'DECEPTION' },
  trapped: { color: '#ff6e8b', ring: 'alert', label: 'TRAPPED' },
  offline: { color: '#718096', ring: 'none', label: 'OFFLINE' },
  infra: { color: '#4c6286', ring: 'none', label: 'INFRA' },
};

const LIGHT_STATUS_STYLE: Record<string, { color: string; ring: 'none' | 'breathe' | 'alert' | 'contain' | 'repair' | 'decoy'; label: string }> = {
  healthy: { color: '#059669', ring: 'none', label: 'UP' },
  normal: { color: '#059669', ring: 'none', label: 'UP' },
  suspicious: { color: '#d97706', ring: 'breathe', label: 'SUSPICIOUS' },
  under_attack: { color: '#dc2626', ring: 'alert', label: 'UNDER ATTACK' },
  compromised: { color: '#b91c1c', ring: 'alert', label: 'COMPROMISED' },
  contained: { color: '#2563eb', ring: 'contain', label: 'CONTAINED' },
  maintenance: { color: '#d97706', ring: 'repair', label: 'MAINTENANCE' },
  deception: { color: '#7c3aed', ring: 'decoy', label: 'DECEPTION' },
  trapped: { color: '#e11d48', ring: 'alert', label: 'TRAPPED' },
  offline: { color: '#64748b', ring: 'none', label: 'OFFLINE' },
  infra: { color: '#334155', ring: 'none', label: 'INFRA' },
};

const ZONE_DEFS = [
  { id: 'CONTAINED', label: 'CONTAINED', darkColor: '#649bff', lightColor: '#2563eb' },
  { id: 'THREAT-ZONE', label: 'THREAT ZONE', darkColor: '#ff6a70', lightColor: '#dc2626' },
  { id: 'HONEYNET', label: 'HONEYNET', darkColor: '#b482ff', lightColor: '#7c3aed' },
  { id: 'MAINTENANCE', label: 'MAINTENANCE', darkColor: '#e6b84e', lightColor: '#d97706' },
] as const;

const ZONE_CELL_W = 118;
const ZONE_CELL_H = 94;
const ZONE_Y = 320;
const ZONE_H = 230;

function edgeStyle(kind?: string, isLight = false): [string, number] {
  if (isLight) {
    return ({ 
      capture: ['#e11d48', 4], 
      bait: ['#7c3aed', 3.2], 
      deception: ['#7c3aed', 3], 
      foothold: ['#ea580c', 3.2], 
      prediction: ['#d97706', 2.8], 
      traffic: ['#0284c7', 2.5], 
      maintenance: ['#d97706', 2.5] 
    } as Record<string, [string, number]>)[kind || ''] || ['#94a3b8', 1.8];
  }
  return ({ 
    capture: ['#ff6e8b', 4], 
    bait: ['#b482ff', 3.2], 
    deception: ['#b482ff', 3], 
    foothold: ['#ffb15c', 3.2], 
    prediction: ['#ffb15c', 2.8], 
    traffic: ['#4cd7ff', 2.5], 
    maintenance: ['#e6b84e', 2.5] 
  } as Record<string, [string, number]>)[kind || ''] || ['#3d5a7b', 1.8];
}

function pointInGrid(index: number, x: number, y: number, columns: number, dx: number, dy: number): Point {
  return { x: x + (index % columns) * dx, y: y + Math.floor(index / columns) * dy };
}

export function DemoTopology({ onSelectNode }: { onSelectNode?: (node: VisualNode) => void }) {
  const { nodes, edges } = useTopologyStore();
  const { currentForecast, latestDecision } = usePredictionStore();
  const { theme } = useUIStore();
  const isLight = theme === 'light';

  const styleFor = (status?: string) => {
    const styleMap = isLight ? LIGHT_STATUS_STYLE : DARK_STATUS_STYLE;
    return styleMap[status || ''] || { 
      color: isLight ? '#475569' : '#7890ae', 
      ring: 'none' as const, 
      label: String(status || 'LIVE').toUpperCase() 
    };
  };

  const graph = useMemo(() => {
    const all = Array.from(nodes.values()) as VisualNode[];
    const hidden = new Set(['CONTAINED', 'THREAT-ZONE', 'HONEYNET', 'MAINTENANCE']);
    const base = all.filter(node => !hidden.has(node.id) && !['INTERNET', 'FIREWALL', 'CORE-SWITCH'].includes(node.id));

    const maintenance = base.filter(node => node.status === 'maintenance' || node.metadata?.recovering);
    const restAfterMaintenance = base.filter(node => !maintenance.includes(node));
    const contained = restAfterMaintenance.filter(node => ['contained', 'compromised'].includes(node.status));
    const restAfterContained = restAfterMaintenance.filter(node => !contained.includes(node));
    const honeypots = restAfterContained.filter(node =>
      node.metadata?.role === 'decoy' || node.status === 'deception' || node.metadata?.bait);
    const restAfterHoneypots = restAfterContained.filter(node => !honeypots.includes(node));
    const threatened = restAfterHoneypots.filter(node =>
      node.metadata?.type === 'attacker' || ['suspicious', 'under_attack'].includes(node.status));
    const normal = restAfterHoneypots.filter(node => !threatened.includes(node));

    const positions: Record<string, Point> = {
      INTERNET: { x: 90, y: 72 }, FIREWALL: { x: 255, y: 72 }, 'CORE-SWITCH': { x: 430, y: 72 },
    };
    normal.forEach((node, index) => { positions[node.id] = pointInGrid(index, 275, 175, 5, 155, 96); });

    const counts: Record<string, number> = {
      'CONTAINED': contained.length,
      'THREAT-ZONE': threatened.length,
      'HONEYNET': honeypots.length,
      'MAINTENANCE': maintenance.length,
    };
    let cursorX = 28;
    const zones: { id: string; label: string; color: string; x: number; y: number; w: number; h: number }[] = [];
    for (const zone of ZONE_DEFS) {
      const count = counts[zone.id];
      const cols = Math.max(2, Math.min(7, Math.ceil(Math.max(count, 1) / 2)));
      const w = 24 + cols * ZONE_CELL_W;
      const color = isLight ? zone.lightColor : zone.darkColor;
      zones.push({ id: zone.id, label: zone.label, color, x: cursorX, y: ZONE_Y, w, h: ZONE_H });
      cursorX += w + 24;
    }
    const inZone = (list: VisualNode[], zone: typeof zones[number]) =>
      list.forEach((node, index) => {
        const cols = Math.max(2, Math.min(7, Math.ceil(Math.max(list.length, 1) / 2)));
        positions[node.id] = pointInGrid(index, zone.x + 54, ZONE_Y + 82, cols, ZONE_CELL_W, ZONE_CELL_H);
      });
    const zById = Object.fromEntries(zones.map(z => [z.id, z]));
    inZone(contained, zById['CONTAINED']);
    inZone(threatened, zById['THREAT-ZONE']);
    inZone(honeypots, zById['HONEYNET']);
    inZone(maintenance, zById['MAINTENANCE']);

    const svgW = Math.max(1210, cursorX + 8);

    // Identify key nodes for autonomous model decision visuals
    const attacker = all.find(n => n.metadata?.type === 'attacker' || n.role === 'attacker' || n.id.includes('APT') || n.id.includes('BOTNET')) || threatened[0];
    const targetAssetId = currentForecast?.predicted_targets?.[0]?.asset_id;
    const victim = (targetAssetId ? all.find(n => n.id === targetAssetId || n.asset_id === targetAssetId || n.label?.toLowerCase().includes(String(targetAssetId).toLowerCase())) : null) ||
                   all.find(n => n.id === 'DC-PROD' || n.id === 'DNS-DMZ' || n.id === 'WEB-CLUSTER') ||
                   threatened.find(n => n.metadata?.type !== 'attacker' && n.status === 'under_attack') ||
                   normal[0];
    const honeypot = honeypots[0] || all.find(n => n.metadata?.role === 'decoy' || n.role === 'decoy' || n.id.includes('HONEYNET'));
    const foothold = all.find(n => n.id === 'DMZ-PIVOT-01' || (n.status === 'under_attack' && n.id !== victim?.id)) || threatened.find(n => n.id !== attacker?.id && n.id !== victim?.id);

    return { all, positions, zones, svgW, attacker, victim, honeypot, foothold };
  }, [nodes, currentForecast, isLight]);

  const activeDecision = latestDecision || currentForecast?.model_decision;
  const isDivert = activeDecision?.action?.includes('DIVERT') || activeDecision?.action?.includes('DECEPTION') || graph.honeypot;
  const isContain = activeDecision?.action?.includes('CONTAIN') || activeDecision?.action?.includes('ISOLATE');

  const attackerPos = graph.attacker ? graph.positions[graph.attacker.id] : null;
  const footholdPos = graph.foothold ? graph.positions[graph.foothold.id] : null;
  const victimPos = graph.victim ? graph.positions[graph.victim.id] : null;
  const honeypotPos = graph.honeypot ? graph.positions[graph.honeypot.id] : null;

  return (
    <div className={cn(
      "h-full min-h-[24rem] overflow-auto p-2 relative transition-colors duration-200",
      isLight ? "bg-slate-100/90" : "bg-[#050a12]"
    )}>
      <svg 
        viewBox={`0 0 ${graph.svgW} 585`} 
        className={cn("h-full min-h-[24rem] min-w-[800px] w-full rounded-xl border transition-colors", isLight ? "border-slate-300 shadow-sm" : "border-white/5")} 
        role="img" 
        aria-label="Live cyber-range topology with containment, threat, honeynet and maintenance zones"
      >
        <defs>
          <pattern id="demo-grid" width="28" height="28" patternUnits="userSpaceOnUse">
            <path d="M28 0H0V28" fill="none" stroke={isLight ? "#cbd5e1" : "#20334d"} strokeOpacity={isLight ? ".65" : ".55"} />
          </pattern>
          <radialGradient id="demo-glow">
            {isLight ? (
              <>
                <stop stopColor="#ffffff" />
                <stop offset=".6" stopColor="#f8fafc" />
                <stop offset="1" stopColor="#f1f5f9" />
              </>
            ) : (
              <>
                <stop stopColor="#172a47" />
                <stop offset=".62" stopColor="#09111e" />
                <stop offset="1" stopColor="#03070d" />
              </>
            )}
          </radialGradient>
          
          {/* Arrow markers */}
          <marker id="gold-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill={isLight ? "#d97706" : "#f59e0b"} />
          </marker>
          <marker id="purple-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill={isLight ? "#9333ea" : "#c084fc"} />
          </marker>
          <filter id="neon-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation={isLight ? "1.5" : "3"} result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect width={graph.svgW} height="585" rx="12" fill="url(#demo-glow)" />
        <rect width={graph.svgW} height="585" fill="url(#demo-grid)" opacity={isLight ? ".85" : ".5"} />
        <ellipse cx="430" cy="165" rx="345" ry="115" fill={isLight ? "#3b82f6" : "#285588"} opacity={isLight ? ".08" : ".08"} />

        {/* Zones */}
        {graph.zones.map(zone => (
          <g key={zone.id}>
            <rect 
              x={zone.x} 
              y={zone.y} 
              width={zone.w} 
              height={zone.h} 
              rx="17" 
              fill={zone.color} 
              fillOpacity={isLight ? ".06" : ".11"} 
              stroke={zone.color} 
              strokeOpacity={isLight ? ".75" : ".65"} 
              strokeDasharray="7 6" 
              strokeWidth="1.6" 
            />
            <rect 
              x={zone.x + 10} 
              y={zone.y + 10} 
              width={zone.w - 20} 
              height="26" 
              rx="8" 
              fill={zone.color} 
              opacity={isLight ? ".16" : ".12"} 
            />
            <text 
              x={zone.x + 17} 
              y={zone.y + 28} 
              fill={zone.color} 
              fontSize="11" 
              fontWeight="900" 
              letterSpacing="1.5"
            >
              {zone.label}
            </text>
          </g>
        ))}

        {/* Normal Edges */}
        {(Array.from(edges.values()) as any[]).map((edge, index) => {
          const source = graph.positions[edge.source]; 
          const target = graph.positions[edge.target];
          if (!source || !target) return null;
          const [stroke, width] = edgeStyle(edge.kind || edge.protocol, isLight);
          const animated = edge.kind && !['zone', 'membership'].includes(edge.kind);
          return (
            <line 
              key={edge.id || index} 
              x1={source.x} 
              y1={source.y} 
              x2={target.x} 
              y2={target.y} 
              stroke={stroke} 
              strokeOpacity={edge.kind === 'zone' || edge.kind === 'membership' ? (isLight ? .25 : .3) : (isLight ? .9 : 1)} 
              strokeWidth={width} 
              strokeDasharray={animated ? '7 7' : undefined} 
              className={animated ? 'demo-topology-flow' : undefined} 
              style={animated ? { animationDuration: edge.kind === 'capture' ? '.85s' : '1.7s' } : undefined} 
            />
          );
        })}

        {/* Model Vectors: Active Foothold Vector */}
        {attackerPos && footholdPos && attackerPos !== footholdPos && (
          <g>
            <path
              d={`M ${attackerPos.x} ${attackerPos.y} Q ${(attackerPos.x + footholdPos.x) / 2} ${Math.min(attackerPos.y, footholdPos.y) - 25} ${footholdPos.x} ${footholdPos.y}`}
              fill="none"
              stroke={isLight ? "#ea580c" : "#f97316"}
              strokeWidth="2.6"
              strokeDasharray="5 3"
              filter="url(#neon-glow)"
              className="demo-topology-flow"
              style={{ animationDuration: '0.9s' }}
            />
            <rect
              x={(attackerPos.x + footholdPos.x) / 2 - 46}
              y={Math.min(attackerPos.y, footholdPos.y) - 36}
              width="92"
              height="16"
              rx="4"
              fill={isLight ? "#fff7ed" : "#1f1003"}
              stroke={isLight ? "#ea580c" : "#f97316"}
              strokeWidth="1"
              opacity="0.95"
            />
            <text
              x={(attackerPos.x + footholdPos.x) / 2}
              y={Math.min(attackerPos.y, footholdPos.y) - 25}
              textAnchor="middle"
              fill={isLight ? "#c2410c" : "#fed7aa"}
              fontSize="8"
              fontWeight="800"
              letterSpacing="0.6"
            >
              FOOTHOLD PIVOT
            </text>
          </g>
        )}

        {/* Autonomous Model Vectors: Predicted Attack Path */}
        {(footholdPos || attackerPos) && victimPos && (footholdPos || attackerPos) !== victimPos && (
          <g>
            {(() => {
              const startPos = footholdPos || attackerPos!;
              return (
                <>
                  <path
                    d={`M ${startPos.x} ${startPos.y} Q ${(startPos.x + victimPos.x) / 2} ${Math.min(startPos.y, victimPos.y) - 40} ${victimPos.x} ${victimPos.y}`}
                    fill="none"
                    stroke={isLight ? "#d97706" : "#fbbf24"}
                    strokeWidth="3.2"
                    strokeDasharray="6 4"
                    markerEnd="url(#gold-arrow)"
                    filter="url(#neon-glow)"
                    className="demo-topology-flow"
                    style={{ animationDuration: '1.2s' }}
                  />
                  <rect
                    x={(startPos.x + victimPos.x) / 2 - 70}
                    y={Math.min(startPos.y, victimPos.y) - 52}
                    width="140"
                    height="19"
                    rx="4"
                    fill={isLight ? "#fefce8" : "#181303"}
                    stroke={isLight ? "#d97706" : "#fbbf24"}
                    strokeWidth="1.2"
                    opacity="0.95"
                  />
                  <text
                    x={(startPos.x + victimPos.x) / 2}
                    y={Math.min(startPos.y, victimPos.y) - 39}
                    textAnchor="middle"
                    fill={isLight ? "#b45309" : "#fbbf24"}
                    fontSize="8.5"
                    fontWeight="800"
                    letterSpacing="0.8"
                  >
                    PREDICTED ATTACK PATH
                  </text>
                </>
              );
            })()}
          </g>
        )}

        {/* Autonomous Model Vectors: Deception Diversion into Honeynet */}
        {isDivert && (victimPos || footholdPos) && honeypotPos && (
          <g>
            {(() => {
              const originDivert = victimPos || footholdPos!;
              const reduction = activeDecision?.risk_reduction_pct || 84;
              return (
                <>
                  <path
                    d={`M ${originDivert.x} ${originDivert.y} Q ${(originDivert.x + honeypotPos.x) / 2} ${Math.max(originDivert.y, honeypotPos.y) + 42} ${honeypotPos.x} ${honeypotPos.y}`}
                    fill="none"
                    stroke={isLight ? "#9333ea" : "#c084fc"}
                    strokeWidth="3.4"
                    strokeDasharray="8 5"
                    markerEnd="url(#purple-arrow)"
                    filter="url(#neon-glow)"
                    className="demo-topology-flow"
                    style={{ animationDuration: '1.0s' }}
                  />
                  <rect
                    x={(originDivert.x + honeypotPos.x) / 2 - 96}
                    y={Math.max(originDivert.y, honeypotPos.y) + 33}
                    width="192"
                    height="21"
                    rx="5"
                    fill={isLight ? "#faf5ff" : "#1a0a2e"}
                    stroke={isLight ? "#9333ea" : "#c084fc"}
                    strokeWidth="1.3"
                    opacity="0.95"
                  />
                  <text
                    x={(originDivert.x + honeypotPos.x) / 2}
                    y={Math.max(originDivert.y, honeypotPos.y) + 47}
                    textAnchor="middle"
                    fill={isLight ? "#6b21a8" : "#f3e8ff"}
                    fontSize="8.5"
                    fontWeight="800"
                    letterSpacing="0.6"
                  >
                    AI DECEPTION DIVERT (+{reduction}% GAIN)
                  </text>
                </>
              );
            })()}
          </g>
        )}

        {/* Nodes */}
        {graph.all.map((node: VisualNode) => {
          const point = graph.positions[node.id]; 
          if (!point) return null;
          const style = styleFor(node.status);
          const attacker = node.metadata?.type === 'attacker';
          const radius = attacker ? 17 : 14;
          const outerRadius = attacker ? 46 : 39;
          const nodeClass = `demo-node-${style.ring}`;
          const label = String(node.label || node.id);
          const compactLabel = label.length > 18 ? `${label.slice(0, 17)}…` : label;
          const selectable = node.metadata?.type === 'asset';
          const isTargetedVictim = graph.victim && graph.victim.id === node.id && activeDecision;

          return (
            <g 
              key={node.id} 
              transform={`translate(${point.x} ${point.y})`} 
              className={cn(nodeClass, selectable && 'cursor-pointer hover:opacity-90')} 
              onClick={() => selectable && onSelectNode?.(node)} 
              role={selectable ? 'button' : undefined} 
              tabIndex={selectable ? 0 : undefined} 
              onKeyDown={(event) => { 
                if (selectable && (event.key === 'Enter' || event.key === ' ')) { 
                  event.preventDefault(); 
                  onSelectNode?.(node); 
                } 
              }} 
              aria-label={selectable ? `View details for ${label}` : undefined}
            >
              <title>{label} · {style.label}</title>
              {style.ring !== 'none' && (
                <circle 
                  r={outerRadius - 10} 
                  fill="none" 
                  stroke={style.color} 
                  strokeOpacity={isLight ? ".7" : ".6"} 
                  strokeWidth="1.6" 
                  strokeDasharray={style.ring === 'decoy' ? '3 6' : '5 5'} 
                  className="demo-node-ring-inner" 
                />
              )}
              {style.ring !== 'none' && (
                <circle 
                  r={outerRadius} 
                  fill="none" 
                  stroke={style.color} 
                  strokeOpacity={isLight ? ".4" : ".35"} 
                  strokeWidth="1.2" 
                  strokeDasharray={style.ring === 'contain' ? '0' : '5 6'} 
                  className="demo-node-ring-outer" 
                />
              )}
              
              {/* Autonomous Action Badge above targeted node */}
              {isTargetedVictim && (
                <g transform="translate(0, -38)">
                  <rect
                    x="-65"
                    y="-11"
                    width="130"
                    height="20"
                    rx="10"
                    fill={isLight ? "#ffffff" : "#0b1329"}
                    stroke={isDivert ? (isLight ? '#9333ea' : '#a855f7') : isContain ? '#dc2626' : '#0284c7'}
                    strokeWidth="1.5"
                    filter={isLight ? undefined : "url(#neon-glow)"}
                  />
                  <circle cx="-52" cy="-1" r="3.5" fill={isDivert ? (isLight ? '#9333ea' : '#c084fc') : '#0284c7'}>
                    <animate attributeName="opacity" values="1;0.3;1" dur="1s" repeatCount="indefinite" />
                  </circle>
                  <text
                    x="2"
                    y="2"
                    textAnchor="middle"
                    fill={isLight ? "#0f172a" : "#f8fafc"}
                    fontSize="8"
                    fontWeight="800"
                    letterSpacing="0.5"
                  >
                    {activeDecision?.action || 'ACTION ACTIVE'}
                  </text>
                </g>
              )}

              <circle 
                r={radius} 
                fill={isLight ? "#ffffff" : "#091321"} 
                stroke={style.color} 
                strokeWidth={attacker ? 3.2 : 2.4} 
              />
              <circle r={attacker ? 7 : 5} fill={style.color} />
              
              <text 
                y={outerRadius + 16} 
                textAnchor="middle" 
                fill={isLight ? "#0f172a" : "#e7eefb"} 
                fontSize="10" 
                fontWeight="700"
              >
                {compactLabel}
              </text>
              <text 
                y={outerRadius + 30} 
                textAnchor="middle" 
                fill={style.color} 
                fontSize="8.5" 
                fontWeight="800" 
                letterSpacing=".65"
              >
                {style.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
