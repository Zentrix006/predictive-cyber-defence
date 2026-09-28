import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { demoApi, type DemoTimelineItem } from "@/lib/api";
import type { LiveRange } from "@/lib/live";
import { Badge, Panel, Time } from "@/components/ui";

type LivePanelsProps = {
  live: LiveRange;
  scope?: "full" | "evidence";
};

const ACTOR_COLORS = ["#ff5c5c", "#ff9d3b", "#b44cff", "#4cd7ff", "#7dffb0", "#ffdd4d", "#8b9cfc", "#ff2d78"];
const actorColor = (id?: string) => {
  if (!id) return "#5b6681";
  let h = 0;
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return ACTOR_COLORS[h % ACTOR_COLORS.length];
};
const scoreLevelColor = (lvl?: string) =>
  ({ "tier-1": "#ffdd4d", advanced: "#4cd7ff", active: "#16c784", volunteer: "#5b6681" })[lvl || ""] || "#5b6681";
const convColor = (lvl?: string | null) =>
  lvl === "critical" ? "#ff4d6d" : lvl === "high" ? "#ff9d3b" : lvl === "medium" ? "#f0b429" : "#b44cff";
const heatBg = (conf: number) => {
  const t = Math.min(1, conf);
  const r = 20 + t * 215;
  const g = 28 + (1 - t) * 100;
  const b = 34 + (1 - t) * 100;
  return `rgba(${r},${g},${b},0.32)`;
};

const statusColor = (s?: string) =>
  ({
    healthy: "#16c784",
    suspicious: "#f0b429",
    under_attack: "#ff5c5c",
    compromised: "#ff2d55",
    contained: "#4c8dff",
    deception: "#b44cff",
    maintenance: "#f0b429",
    offline: "#5b6681",
    infra: "#2a3550",
    predicted: "#ff9d3b",
    serving: "#16c784",
    recovered: "#16c784",
    down: "#ff5c5c",
    na: "#5b6681",
  } as Record<string, string>)[s || ""] || "#5b6681";

const RAIL_KINDS: Record<string, string> = {
  decoy_interaction: "interact",
  deception_containment: "capture",
  attacker_telemetry: "telemetry",
  attacker_intel: "intel",
  attacker_start: "intel",
  decoy_created: "mint",
  decoy_origin_twin: "mint",
  bait_ring_deployed: "bait",
  server_isolated: "isolate",
  diagnostic_check: "diag",
  maintenance_complete: "diag",
  data_loss_reported: "diag",
  server_restored: "restore",
  service_recovered: "restore",
  traffic_rerouted: "traffic",
  challenge_level: "intel",
  prediction_updated: "model",
};
const RAIL_COLORS: Record<string, string> = {
  interact: "#b44cff",
  capture: "#ff4d6d",
  telemetry: "#2ee6ff",
  intel: "#ff9d3b",
  mint: "#7dffb0",
  bait: "#f0b429",
  diag: "#4c8dff",
  restore: "#16c784",
  traffic: "#4cd7ff",
  model: "#8b9cfc",
  isolate: "#ff4d6d",
};
function RailKind({ kind }: { kind: string }) {
  const g = RAIL_KINDS[kind] || "event";
  const c = RAIL_COLORS[g] || "#5b6681";
  return <span className="rail-kind" style={{ background: c }}>{g}</span>;
}

const eventGlyph = (e: DemoTimelineItem) => {
  if (e.source === "world-model") return "🧠";
  if (e.kind.includes("convergence") || e.kind.includes("consensus")) return "⚠";
  if (e.kind.includes("deception") || e.kind.includes("decoy") || e.kind.includes("bait") || e.kind.includes("honeypot")) return "🟣";
  if (e.kind.includes("contain") || e.kind.includes("traffic") || e.kind.includes("pivot")) return "🔵";
  if (e.kind.includes("service") || e.kind.includes("restore") || e.kind.includes("server") || e.kind.includes("recovered") || e.kind.includes("isolat")) return "🟢";
  if (e.kind.includes("participant") || e.kind.includes("asset_online") || e.kind.includes("device")) return "🖥";
  return "·";
};

function PlaybookTree({ ov }: { ov: NonNullable<LiveRange["ov"]> }) {
  const incs = ov.incidents || [];
  const active = incs.length > 0;
  const risk = ov.prediction?.risk_level || "";
  const escalate = ["high", "critical"].includes(risk);
  const contained = (ov.contained || 0) > 0;
  const decoys = (ov.decoys || 0) > 0;
  const trapped = (ov.trapped || 0) > 0;
  const maint = ov.maintenance || [];

  const t = (label: string, state: "on" | "next" | "off", sub?: string) => (
    <div className={`tree-node ${state}`} key={label}>
      <span className="tree-mark">{state === "on" ? "▶" : state === "next" ? "◔" : "○"}</span>
      <span className="tree-label">{label}{sub && <em> {sub}</em>}</span>
    </div>
  );

  return (
    <div className="tree">
      {t(active ? "Intrusion detected → escalate" : "Range monitoring — watch & listen", active ? "on" : active ? "next" : "off")}
      {active && t(`Risk threshold → ${risk || "…"}`, escalate ? "on" : "off")}
      {escalate && t("CONTAIN & DECEIVE activated", contained ? "on" : "next")}
      {escalate && contained && t(`Isolate origin ${ov.contained} offline → THREAT ZONE`, "on")}
      {escalate && decoys && t("Mint decoy twins + segment bait ring", "on",
        trapped ? ` = ${ov.trapped} attacker${ov.trapped > 1 ? "s" : ""} trapped` : "")}
      {!escalate && active && t("MEDIUM / LOW → isolate & monitor", "off")}
      {maint.length > 0 && maint.map((m) => t(
        `Maintenance ${m.asset}`,
        m.recoverable ? "on" : "next",
        m.recoverable ? "→ restore & re-add ready" : `→ ${(m.checks || []).length}/5 diagnostic checks`,
      ))}
      {maint.some((m) => m.recoverable) && t("Restore from clean snapshot → fresh re-snapshot captured", "next")}
    </div>
  );
}

const MINI_ZONE_BOX = {
  CONTAINED: { x: 22, y: 92, w: 150, h: 96 },
  THREAT_ZONE: { x: 186, y: 92, w: 178, h: 108 },
  HONEYNET: { x: 376, y: 92, w: 186, h: 108 },
  MAINTENANCE: { x: 574, y: 92, w: 134, h: 96 },
} as const;

function ReplayTopologyMap({
  topo,
  events,
  currentEvent,
  actor,
}: {
  topo: LiveRange["topo"];
  events: DemoTimelineItem[];
  currentEvent: DemoTimelineItem | null;
  actor?: string;
}) {
  const nodeIds = useMemo(() => new Set((topo?.nodes || []).map((n) => n.id)), [topo]);
  const incidentIds = useMemo(() => {
    const ids = new Set<string>();
    for (const ev of events) {
      const payload = ev.payload || {};
      const vals = [
        ev.source,
        typeof payload.actor === "string" ? payload.actor : undefined,
        typeof payload.target === "string" ? payload.target : undefined,
        typeof payload.origin === "string" ? payload.origin : undefined,
        typeof payload.asset === "string" ? payload.asset : undefined,
        typeof payload.decoy === "string" ? payload.decoy : undefined,
        typeof payload.from === "string" ? payload.from : undefined,
        typeof payload.to === "string" ? payload.to : undefined,
        typeof payload.node === "string" ? payload.node : undefined,
        typeof payload.asset_id === "string" ? payload.asset_id : undefined,
      ].filter((v): v is string => !!v);
      vals.forEach((v) => { if (nodeIds.has(v)) ids.add(v); });
    }
    if (actor) ids.add(actor);
    if (currentEvent?.source && nodeIds.has(currentEvent.source)) ids.add(currentEvent.source);
    return ids;
  }, [events, nodeIds, actor, currentEvent]);

  const incidentPath = useMemo(() => {
    const ids = new Set<string>();
    events.forEach((ev) => {
      const payload = ev.payload || {};
      const src = ev.source;
      if (nodeIds.has(src)) ids.add(src);
      Object.values(payload).forEach((v) => {
        if (typeof v === "string" && nodeIds.has(v)) ids.add(v);
      });
    });
    return ids;
  }, [events, nodeIds]);

  const layout = useMemo(() => {
    const pos: Record<string, { x: number; y: number }> = {
      INTERNET: { x: 62, y: 34 },
      FIREWALL: { x: 152, y: 34 },
      "CORE-SWITCH": { x: 242, y: 34 },
      CONTAINED: { x: MINI_ZONE_BOX.CONTAINED.x + MINI_ZONE_BOX.CONTAINED.w / 2, y: MINI_ZONE_BOX.CONTAINED.y + 12 },
      "THREAT-ZONE": { x: MINI_ZONE_BOX.THREAT_ZONE.x + MINI_ZONE_BOX.THREAT_ZONE.w / 2, y: MINI_ZONE_BOX.THREAT_ZONE.y + 12 },
      HONEYNET: { x: MINI_ZONE_BOX.HONEYNET.x + MINI_ZONE_BOX.HONEYNET.w / 2, y: MINI_ZONE_BOX.HONEYNET.y + 12 },
      MAINTENANCE: { x: MINI_ZONE_BOX.MAINTENANCE.x + MINI_ZONE_BOX.MAINTENANCE.w / 2, y: MINI_ZONE_BOX.MAINTENANCE.y + 12 },
    };

    const attacks = (topo?.nodes || []).filter((n) => n.type === "attacker");
    const servers = (topo?.nodes || []).filter((n) => n.type === "asset" && n.role === "server" && !incidentPath.has(n.id));
    const clients = (topo?.nodes || []).filter((n) => n.type === "asset" && ["client", "host", "other"].includes(n.role || "") && !incidentPath.has(n.id));
    const threats = (topo?.nodes || []).filter((n) => n.type === "asset" && ["contained", "compromised", "under_attack"].includes(n.status || ""));
    const decoys = (topo?.nodes || []).filter((n) => n.type === "asset" && (n.role === "decoy" || /-DECOY$/i.test(n.id)));
    const maint = (topo?.nodes || []).filter((n) => (topo?.edges || []).some((e) => e.kind === "maintenance" && e.target === n.id));
    const forecasts = (topo?.nodes || []).filter((n) => n.type === "forecast");

    servers.forEach((n, i) => { pos[n.id] = { x: 98 + (i % 4) * 78, y: 162 + Math.floor(i / 4) * 36 }; });
    clients.forEach((n, i) => { pos[n.id] = { x: 298 + (i % 4) * 76, y: 164 + Math.floor(i / 4) * 34 }; });
    threats.forEach((n, i) => { pos[n.id] = { x: MINI_ZONE_BOX.CONTAINED.x + 26 + (i % 2) * 58, y: MINI_ZONE_BOX.CONTAINED.y + 36 + Math.floor(i / 2) * 28 }; });
    attacks.forEach((n, i) => { pos[n.id] = { x: MINI_ZONE_BOX.THREAT_ZONE.x + 36 + (i % 2) * 72, y: MINI_ZONE_BOX.THREAT_ZONE.y + 40 + Math.floor(i / 2) * 34 }; });
    decoys.forEach((n, i) => { pos[n.id] = { x: MINI_ZONE_BOX.HONEYNET.x + 30 + (i % 3) * 48, y: MINI_ZONE_BOX.HONEYNET.y + 40 + Math.floor(i / 3) * 30 }; });
    maint.forEach((n, i) => { pos[n.id] = { x: MINI_ZONE_BOX.MAINTENANCE.x + 28 + (i % 2) * 42, y: MINI_ZONE_BOX.MAINTENANCE.y + 40 + Math.floor(i / 2) * 28 }; });
    forecasts.forEach((n, i) => { pos[n.id] = { x: 252 + i * 18, y: 104 + (i % 2) * 12 }; });
    return pos;
  }, [topo, incidentPath]);

  const viewBox = "0 0 740 214";
  const miniEdges = useMemo(() => {
    if (!topo) return [];
    const seen = new Map<string, typeof topo.edges[number]>();
    for (const e of topo.edges) {
      const key = `${e.source}->${e.target}`;
      if (!seen.has(key) || (e.flow || 0) >= ((seen.get(key)?.flow || 0))) seen.set(key, e);
    }
    return Array.from(seen.values());
  }, [topo]);

  const currentStep = currentEvent ? `${eventGlyph(currentEvent)} ${currentEvent.kind.replace(/_/g, " ")}` : "waiting";

  return (
    <div className="replay-map-wrap">
      <div className="replay-map-head">
        <b>Topology trace</b>
        <span className="mono small muted">{incidentPath.size} node{incidentPath.size === 1 ? "" : "s"} in path</span>
      </div>
      <svg className="replay-map" viewBox={viewBox} role="img" aria-label="Trajectory topology replay">
        <defs>
          <pattern id="replayGrid" width="26" height="26" patternUnits="userSpaceOnUse">
            <path d="M 26 0 L 0 0 0 26" fill="none" stroke="#22324b" strokeOpacity="0.35" strokeWidth="1" />
          </pattern>
          <linearGradient id="replayMaint" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#4a3612" stopOpacity="0.88" />
            <stop offset="100%" stopColor="#130f0a" stopOpacity="0.76" />
          </linearGradient>
          <linearGradient id="replayThreat" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#3a1c25" stopOpacity="0.90" />
            <stop offset="100%" stopColor="#120d17" stopOpacity="0.72" />
          </linearGradient>
          <linearGradient id="replayHoney" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#2d1d4b" stopOpacity="0.90" />
            <stop offset="100%" stopColor="#120c22" stopOpacity="0.72" />
          </linearGradient>
          <linearGradient id="replayContained" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#19396c" stopOpacity="0.88" />
            <stop offset="100%" stopColor="#0d1525" stopOpacity="0.72" />
          </linearGradient>
        </defs>
        <rect x="0" y="0" width="100%" height="100%" rx="12" fill="rgba(8,12,18,0.96)" />
        <rect x="0" y="0" width="100%" height="100%" fill="url(#replayGrid)" opacity="0.22" />
        <g opacity="0.98">
          <rect x={MINI_ZONE_BOX.CONTAINED.x} y={MINI_ZONE_BOX.CONTAINED.y} width={MINI_ZONE_BOX.CONTAINED.w} height={MINI_ZONE_BOX.CONTAINED.h} rx="12" fill="url(#replayContained)" stroke="#4c8dff" strokeOpacity="0.42" strokeDasharray="6 4" />
          <rect x={MINI_ZONE_BOX.THREAT_ZONE.x} y={MINI_ZONE_BOX.THREAT_ZONE.y} width={MINI_ZONE_BOX.THREAT_ZONE.w} height={MINI_ZONE_BOX.THREAT_ZONE.h} rx="12" fill="url(#replayThreat)" stroke="#ff5c5c" strokeOpacity="0.42" strokeDasharray="6 4" />
          <rect x={MINI_ZONE_BOX.HONEYNET.x} y={MINI_ZONE_BOX.HONEYNET.y} width={MINI_ZONE_BOX.HONEYNET.w} height={MINI_ZONE_BOX.HONEYNET.h} rx="12" fill="url(#replayHoney)" stroke="#b44cff" strokeOpacity="0.42" strokeDasharray="6 4" />
          <rect x={MINI_ZONE_BOX.MAINTENANCE.x} y={MINI_ZONE_BOX.MAINTENANCE.y} width={MINI_ZONE_BOX.MAINTENANCE.w} height={MINI_ZONE_BOX.MAINTENANCE.h} rx="12" fill="url(#replayMaint)" stroke="#f0b429" strokeOpacity="0.42" strokeDasharray="6 4" />
          <text x={MINI_ZONE_BOX.CONTAINED.x + 12} y={MINI_ZONE_BOX.CONTAINED.y + 14} fontSize="8.5" fontWeight="800" fill="#93c5fd">CONTAINED</text>
          <text x={MINI_ZONE_BOX.THREAT_ZONE.x + 12} y={MINI_ZONE_BOX.THREAT_ZONE.y + 14} fontSize="8.5" fontWeight="800" fill="#fda4af">THREAT</text>
          <text x={MINI_ZONE_BOX.HONEYNET.x + 12} y={MINI_ZONE_BOX.HONEYNET.y + 14} fontSize="8.5" fontWeight="800" fill="#c4b5fd">HONEYNET</text>
          <text x={MINI_ZONE_BOX.MAINTENANCE.x + 12} y={MINI_ZONE_BOX.MAINTENANCE.y + 14} fontSize="8.5" fontWeight="800" fill="#ffda7a">MAINT</text>
        </g>

        {miniEdges.map((e, i) => {
          const a = layout[e.source];
          const b = layout[e.target];
          if (!a || !b) return null;
          const isPath = incidentPath.has(e.source) || incidentPath.has(e.target);
          const active = currentEvent && (currentEvent.source === e.source || currentEvent.payload?.target === e.target || currentEvent.payload?.origin === e.target);
          const stroke = e.kind === "maintenance" ? "#d3a233" : e.kind === "capture" ? "#ff6a80" : e.kind === "prediction" ? "#8c6bff" : e.kind === "traffic" ? "#47d7ff" : "#42567a";
          const width = active ? 2.8 : isPath ? 2.1 : 1.1;
          const opacity = active ? 1 : isPath ? 0.85 : 0.22;
          return (
            <line
              key={`${e.source}-${e.target}-${i}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={stroke}
              strokeWidth={width}
              strokeOpacity={opacity}
              strokeDasharray={e.kind === "maintenance" ? "5 4" : e.kind === "prediction" ? "3 5" : undefined}
            />
          );
        })}

        {topo?.nodes.map((n) => {
          const p = layout[n.id];
          if (!p) return null;
          const active = incidentIds.has(n.id);
          const path = incidentPath.has(n.id);
          const c = statusColor(n.status);
          const stroke = n.type === "attacker" ? actorColor(n.id) : active ? "#ffda7a" : path ? "#7dd3fc" : "#162235";
          const fill = n.type === "infra" ? "#16253b" : c;
          if (n.type === "infra") {
            return <circle key={n.id} cx={p.x} cy={p.y} r="5.5" fill={fill} stroke={stroke} strokeWidth="1.3" />;
          }
          if (n.type === "attacker") {
            return (
              <g key={n.id}>
                <circle cx={p.x} cy={p.y} r={active ? 13 : 11} fill={fill} stroke={stroke} strokeWidth="2" />
                <text x={p.x} y={p.y + 4} textAnchor="middle" fontSize="9" fontWeight="800" fill={stroke}>⚠</text>
                <text x={p.x} y={p.y + 24} textAnchor="middle" fontSize="8.2" fill={stroke}>{n.label.replace(/^ATK · /, "")}</text>
              </g>
            );
          }
          if (n.type === "forecast") {
            return (
              <g key={n.id}>
                <rect x={p.x - 16} y={p.y - 7} width="32" height="14" rx="5" fill="#171229" stroke="#8c6bff" strokeWidth="1" />
                <text x={p.x} y={p.y + 2.5} textAnchor="middle" fontSize="7.5" fontWeight="800" fill="#8c6bff">PRED</text>
              </g>
            );
          }
          return (
            <g key={n.id}>
              {path && <circle cx={p.x} cy={p.y} r="16" fill="rgba(46,230,255,0.09)" stroke={active ? "#ffda7a" : "#7dd3fc"} strokeWidth="1.4" strokeDasharray="4 4" />}
              <circle cx={p.x} cy={p.y} r={10.5} fill={fill} stroke={stroke} strokeWidth={1.8} />
              <text x={p.x} y={p.y + 22} textAnchor="middle" fontSize="8" fill={active ? "#ffda7a" : path ? "#cfe6ff" : "#8b9bb5"}>
                {n.label}{n.status === "contained" ? " ⛃" : n.status === "deception" ? " ◉" : ""}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="replay-step-strip">
        <span className="mono tiny muted">current</span>
        <b>{currentStep}</b>
      </div>
    </div>
  );
}

function BeliefVsKnows({ ov }: { ov: NonNullable<LiveRange["ov"]> }) {
  const p = ov.prediction;
  const trapped = !!ov.incident?.trapped || (ov.trapped || 0) > 0;
  const believes = p ? [
    { k: "Next target", v: p.predicted_target || "—", cls: "text-warn" },
    { k: "Confidence", v: `${Math.round((p.confidence || 0) * 100)}%` },
    { k: "Risk", v: (p.risk_level || "").toUpperCase(), cls: ["high", "critical"].includes(p.risk_level) ? "text-bad" : p.risk_level === "medium" ? "text-warn" : "text-good" },
    { k: "Stages ahead", v: (p.predicted_stages || []).join(" → ") || "—" },
  ] : [{ k: "Next target", v: "awaiting signal" }];
  const knows = [
    { k: "Live events", v: `${ov.evidence_count || 0}` },
    { k: "Decoys live", v: `${ov.decoys || 0}` },
    { k: "Trajectories", v: `${(ov.incidents || []).length}` },
    { k: "Ground truth", v: trapped ? "ATTACKER CAPTURED" : (!ov.contained ? "no containment yet" : `${ov.contained} origin(s) isolated`), cls: trapped ? "text-bad" : "text-good" },
  ];
  return (
    <div className="bvs">
      <div className="bvs-col">
        <div className="bvs-head"><b>BELIEVES</b><span className="mono small muted">world-model</span></div>
        {believes.map((r) => <div className="row" key={r.k}><span className="grow">{r.k}</span><b className={r.cls || ""}>{r.v}</b></div>)}
      </div>
      <div className="bvs-col">
        <div className="bvs-head"><b>KNOWS</b><span className="mono small muted">observed</span></div>
        {knows.map((r) => <div className="row" key={r.k}><span className="grow">{r.k}</span><b className={r.cls || ""}>{r.v}</b></div>)}
      </div>
    </div>
  );
}

type ReplayState = {
  actor: string;
  idx: number | null;
  playing: boolean;
  events: DemoTimelineItem[];
};

export default function LivePanels({ live, scope = "full" }: LivePanelsProps) {
  const { ov, topo, timeline, board } = live;
  const [tlQuery, setTlQuery] = useState("");
  const [tlKind, setTlKind] = useState("all");
  const [replay, setReplay] = useState<ReplayState>({ actor: "", idx: null, playing: false, events: [] });
  const eventsRef = useRef<DemoTimelineItem[]>([]);
  eventsRef.current = replay.events;

  const actorByInc = useMemo(() => new Map((ov?.incidents || []).map((i) => [i.id, i.actor || ""])), [ov]);
  const boardByPid = useMemo(() => {
    const m = new Map<string, NonNullable<LiveRange["board"]>["participants"][number]>();
    board.participants.forEach((p) => m.set(p.participant_id, p));
    return m;
  }, [board]);
  const pidForEvent = (e: DemoTimelineItem) => {
    if (boardByPid.has(e.source)) return e.source;
    const act = e.payload?.actor;
    return typeof act === "string" && boardByPid.has(act) ? act : undefined;
  };

  const tlKinds = useMemo(() => Array.from(new Set(timeline.map((e) => e.kind))).sort(), [timeline]);
  const filteredTimeline = useMemo(() => {
    const q = tlQuery.trim().toLowerCase();
    return timeline.filter((e) => {
      if (tlKind !== "all" && e.kind !== tlKind) return false;
      if (!q) return true;
      return [e.kind, e.source, JSON.stringify(e.payload)].join(" ").toLowerCase().includes(q);
    });
  }, [timeline, tlQuery, tlKind]);

  const heatTable = useMemo(() => {
    type Row = { target: string; confs: Record<string, { conf: number; risk: number }> };
    const rows = new Map<string, Row>();
    (ov?.incidents || []).forEach((inc) => {
      const target = inc.predicted_target_id || inc.predicted_target || "?";
      const conf = inc.prediction?.confidence || 0;
      const risk = inc.prediction?.risk_score || 0;
      if (!inc.actor) return;
      const row = rows.get(target) || { target, confs: {} };
      row.confs[inc.actor] = { conf, risk };
      rows.set(target, row);
    });
    return Array.from(rows.values());
  }, [ov]);
  const heatActors = useMemo(() => (ov?.actors || []).map((a) => a.actor), [ov]);

  const incByActor = useMemo(() => new Map((ov?.incidents || []).map((i) => [i.actor || "", i])), [ov]);
  const actorEvents = useMemo(() => {
    const inc = replay.actor ? incByActor.get(replay.actor) : undefined;
    return inc ? replay.events.filter((e) => e.incident_id === inc.id) : [];
  }, [replay.events, replay.actor, incByActor]);
  const replayEv = replay.idx !== null && replay.actor ? actorEvents[Math.min(replay.idx, actorEvents.length - 1)] : null;
  const replaySlice = replay.idx !== null ? actorEvents.slice(0, Math.min(actorEvents.length, replay.idx + 1)) : actorEvents;

  const loadReplay = useCallback(async (actorId: string) => {
    const inc = incByActor.get(actorId);
    if (!inc) return;
    try {
      const all = await demoApi.timeline(200);
      setReplay((r) => ({ ...r, events: all.filter((e) => e.incident_id === inc.id) }));
    } catch {
      /* keep */
    }
  }, [incByActor]);

  useEffect(() => {
    if (!replay.playing || replay.idx === null) return;
    const t = setInterval(() => {
      setReplay((r) => {
        if (r.idx === null || r.idx >= (eventsRef.current.length || 1) - 1) {
          return { ...r, playing: false };
        }
        return { ...r, idx: r.idx + 1 };
      });
    }, 1100);
    return () => clearInterval(t);
  }, [replay.playing, replay.idx]);

  return (
    <>
      {scope === "full" && (
        <Panel title="Participant scoreboard · live scoring"
          right={<span className="mono small muted">{board.live} online now · max {board.max_score} pts</span>}>
          <div className="scoreboard">
            {board.participants.map((p) => {
              const dot = p.online ? "#16c784" : p.engaged ? "#f0b429" : p.score >= 45 ? "#4cd7ff" : "#5b6681";
              return (
                <div className={`sb-card ${p.online ? "on" : ""}`} key={p.participant_id}>
                  <div className="sb-head">
                    <span className="dot" style={{ background: dot, flex: "none" }} />
                    <b className="small">{p.participant_id}</b>
                    <span className="mono tiny" style={{ color: "#9fb0d0" }}>{p.role.toUpperCase()}</span>
                    <span className="badge" style={{ background: scoreLevelColor(p.level), color: "#0b0f1a" }}>{p.level}</span>
                  </div>
                  <div className="sb-bar"><i style={{ width: `${Math.max(4, p.score)}%` }} /></div>
                  <div className="sb-meta">
                    <span className="muted tiny">{p.asset_id ? `${p.asset_id} · ${p.asset_status || "—"}` : p.browser ? `${p.browser} · ${p.platform}` : "no asset yet"}</span>
                    <b className="mono">{p.score}</b>
                  </div>
                  <div className="sb-chips">
                    {p.chips.map((c) => <em key={c}>{c}</em>)}
                  </div>
                </div>
              );
            })}
            {!board.participants.length && <p className="muted">No participants yet — they appear the moment someone joins the range (QR / join page).</p>}
          </div>
        </Panel>
      )}

      <div className="stage-row2">
        <Panel title="Live capture evidence rail" right={<span className="mono small muted">{ov?.evidence_count ?? 0} ev</span>}>
          <div className="rail">
            {filteredTimeline.slice().reverse().slice(0, 24).map((e) => (
              <div className="rail-item" key={e.event_id}>
                <RailKind kind={e.kind} />
                <div className="grow">
                  <b className="small">{eventGlyph(e)} {e.kind.replace(/_/g, " ")}</b>
                  <div className="muted tiny">{e.source} · {JSON.stringify(e.payload).slice(0, 96)}</div>
                </div>
                <Time iso={e.timestamp} />
              </div>
            ))}
            {!filteredTimeline.length && <p className="muted">No events yet.</p>}
          </div>
        </Panel>

        <Panel title="Live timeline · filter / search"
          right={<span className="mono small muted">{filteredTimeline.length}/{timeline.length}</span>}>
          <div className="flex mb8" style={{ gap: 8 }}>
            <input className="grow" placeholder="search events…" value={tlQuery} onChange={(ev) => setTlQuery(ev.target.value)} />
            <select value={tlKind} onChange={(ev) => setTlKind(ev.target.value)} style={{ width: "auto" }}>
              <option value="all">all kinds</option>
              {tlKinds.map((k) => <option value={k} key={k}>{k}</option>)}
            </select>
          </div>
          <div className="timeline timeline-scroll">
            {filteredTimeline.slice(-60).reverse().map((e) => {
              const actor = e.incident_id ? actorByInc.get(e.incident_id) : undefined;
              const pid = pidForEvent(e);
              const scorer = pid ? boardByPid.get(pid) : undefined;
              const stage = typeof e.payload?.stage === "string" ? e.payload.stage : undefined;
              const tgt = typeof e.payload?.target === "string" ? e.payload.target : undefined;
              return (
                <div className={`tl-row ${e.source === "system" ? "muted" : ""}`} key={e.event_id}>
                  <span style={{ width: 18 }}>{eventGlyph(e)}</span>
                  {actor && <span className="actor-tag" style={{ background: actorColor(actor), color: "#0b0f1a" }}>{actor}</span>}
                  {scorer && (
                    <span className="score-tag" style={{ background: scoreLevelColor(scorer.level), color: "#0b0f1a" }}
                      title={`${pid} · ${scorer.level} · ${scorer.online ? "online" : scorer.engaged ? "engaged" : "away"}`}>
                      ★ {scorer.score}
                    </span>
                  )}
                  {stage && <span className="stage-tag">{stage.replace(/_/g, " ")}</span>}
                  {tgt && <span className="stage-tag tgt">→ {tgt}</span>}
                  <Time iso={e.timestamp} /> <b>{e.kind.replace(/_/g, " ")}</b>
                  <span className="muted"> · {e.source}</span>
                  {e.payload && Object.keys(e.payload).length > 0 && (
                    <div className="muted small">{JSON.stringify(e.payload).slice(0, 140)}</div>
                  )}
                </div>
              );
            })}
            {timeline.length === 0 && <p className="muted">No events yet.</p>}
          </div>
        </Panel>
      </div>

      <div className="stage-row3">
        <Panel title="Playbook decision tree">
          {ov && <PlaybookTree ov={ov} />}
        </Panel>

        <Panel title="Next-target odds · heat map">
          {heatTable.length ? (
            <table className="heat">
              <thead><tr><th>target</th>{heatActors.map((a) => <th key={a} style={{ color: actorColor(a) }}>{a}</th>)}<th>fused</th></tr></thead>
              <tbody>
                {heatTable.map((row) => (
                  <tr key={row.target}>
                    <td><b className="small">{row.target}</b></td>
                    {heatActors.map((a) => {
                      const c = row.confs[a];
                      return <td key={a} style={{ background: c ? heatBg(c.conf) : "transparent", color: c ? "#fff" : "#5b6681", textAlign: "center" }}>{c ? `${Math.round(c.conf * 100)}%` : "–"}</td>;
                    })}
                    <td style={{ textAlign: "center" }}>
                      {(topo?.convergence || []).find((g) => g.target === row.target && (g.count || 0) >= 2)
                        ? <Badge tone="purple">{Math.round((topo?.convergence || []).find((g) => g.target === row.target)?.aggregate_risk_score || 0)}</Badge>
                        : <span className="muted">–</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="muted">No predictions yet — odds appear once the world model forecasts targets.</p>
          )}
          <p className="muted small mt8">Cell heat = model confidence that {heatActors[0] || "an actor"} moves to that node next. Fused risk = multi-actor convergence (1 − Π(1 − p)) on the same target.</p>
        </Panel>

        <div className="stage-side-col">
          <Panel title="Trajectory replay"
            right={replay.idx !== null && replay.actor ? <button className="tiny" onClick={() => setReplay((r) => ({ ...r, playing: false, idx: null }))}>live</button> : undefined}>
            <div className="flex" style={{ gap: 8 }}>
              <select value={replay.actor} onChange={(ev) => {
                const actor = ev.target.value;
                setReplay({ actor, idx: null, playing: false, events: [] });
                if (actor) loadReplay(actor);
              }} style={{ width: "auto" }}>
                <option value="">choose actor…</option>
                {(ov?.actors || []).map((a) => <option value={a.actor} key={a.actor}>{a.actor}</option>)}
              </select>
              <button className="tiny" disabled={!replay.actor} onClick={() => {
                if (replay.idx === null) {
                  if (!replay.events.length && replay.actor) loadReplay(replay.actor);
                  setReplay((r) => ({ ...r, idx: 0 }));
                } else { setReplay((r) => ({ ...r, playing: false, idx: null })); }
              }}>◀ replay</button>
            </div>
            {replay.actor && (
              <>
                <ReplayTopologyMap topo={topo} events={replaySlice} currentEvent={replayEv} actor={replay.actor} />
                <div className="flex mt8" style={{ gap: 6, alignItems: "center" }}>
                  <button className="tiny" disabled={replay.idx === null} onClick={() => setReplay((r) => ({ ...r, playing: false, idx: 0 }))}>|◀</button>
                  <button className="tiny" disabled={replay.idx === null} onClick={() => setReplay((r) => ({ ...r, playing: false, idx: Math.max(0, (r.idx ?? 0) - 1) }))}>◀</button>
                  <button className="tiny primary" disabled={!actorEvents.length}
                    onClick={() => {
                      if (replay.idx === null) {
                        if (!replay.events.length && replay.actor) loadReplay(replay.actor);
                        setReplay((r) => ({ ...r, idx: 0 }));
                      }
                      setReplay((r) => ({ ...r, playing: !r.playing }));
                    }}>
                    {replay.playing ? "❚❚" : "▶ play"}
                  </button>
                  <button className="tiny" disabled={replay.idx === null} onClick={() => setReplay((r) => ({ ...r, playing: false, idx: Math.min(actorEvents.length - 1, (r.idx ?? 0) + 1) }))}>▶</button>
                  <button className="tiny" disabled={replay.idx === null} onClick={() => setReplay((r) => ({ ...r, playing: false, idx: actorEvents.length - 1 }))}>▶|</button>
                  <span className="muted small">{replay.idx !== null ? `${replay.idx + 1}/${actorEvents.length}` : "LIVE"}</span>
                </div>
                <p className="muted small mt8">Confirmed path: {replay.events.length} recorded event(s) across the whole engagement · stepping the full history (depth 200).</p>
                <input type="range" min={0} max={Math.max(0, actorEvents.length - 1)} value={replay.idx ?? actorEvents.length - 1}
                  onChange={(ev) => setReplay((r) => ({ ...r, playing: false, idx: Number(ev.target.value) }))} className="scrubber" />
                {replayEv ? (
                  <div className="note mt8 replay-snap">
                    <RailKind kind={replayEv.kind} />
                    <b className="small"> {replayEv.kind.replace(/_/g, " ")}</b>
                    <div className="muted tiny">{replayEv.source} · <Time iso={replayEv.timestamp} /></div>
                    <pre className="mono tiny">{JSON.stringify(replayEv.payload, null, 1)}</pre>
                  </div>
                ) : replay.idx !== null ? (
                  <p className="muted small mt8">No events yet.</p>
                ) : null}
                <div className="replay-step-list">
                  {replaySlice.slice(-6).map((e, i) => (
                    <div className={`replay-step ${i === replaySlice.slice(-6).length - 1 ? "active" : ""}`} key={e.event_id}>
                      <span>{eventGlyph(e)}</span>
                      <div className="grow">
                        <b>{e.kind.replace(/_/g, " ")}</b>
                        <div className="muted tiny">{e.source}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
            {!replay.actor && <p className="muted small mt8">Step or play back a chosen attacker's full trajectory — the live feed holds while you inspect, then resumes the moment you do.</p>}
          </Panel>
        </div>
      </div>

      <div className="stage-row3 ov-beta">
        <Panel title="Believes vs knows · model vs ground truth">
          {ov && <BeliefVsKnows ov={ov} />}
        </Panel>
        <Panel title="Convergence analysis">
          {(topo?.convergence || []).filter((g) => (g.count || 0) >= 2).length ? (
            <div className="rows">
              {(topo?.convergence || []).filter((g) => (g.count || 0) >= 2).map((g) => (
                <div className="note" key={g.target} style={{ borderColor: convColor(g.aggregate_risk_level) }}>
                  <b className="text-bad">⚠ CONVERGENCE ×{g.count} · {g.target_name || g.target}</b>
                  <div className="small mt8">
                    {g.actors.map((a) => (
                      <div className="row" key={a.actor}>
                        <span className="grow">{a.actor}</span>
                        <span className="mono tiny" style={{ color: actorColor(a.actor) }}>{a.stage}</span>
                        {a.confidence != null && <span className="mono tiny muted">{Math.round(a.confidence * 100)}%</span>}
                        {a.risk_level && <span className="mono tiny" style={{ color: convColor(a.risk_level) }}>{a.risk_level.slice(0, 3).toUpperCase()}</span>}
                      </div>
                    ))}
                  </div>
                  <div className="row mt8">
                    <span className="grow">Fused risk (1 − Π(1 − p))</span>
                    <Badge tone={["critical", "high"].includes(g.aggregate_risk_level || "") ? "bad" : "purple"}>
                      {g.aggregate_risk_level?.toUpperCase()} · {Math.round(g.aggregate_risk_score || 0)}
                    </Badge>
                  </div>
                  {g.correlation_id && <div className="mono tiny muted mt8">{g.correlation_id}</div>}
                  <p className="muted tiny mt8">Trajectories are tracked separately — convergence aggregates risk, it does not merge actors.</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">No multi-actor convergence yet. When two or more trajectories predict the same target, fusion risk appears here and on the topology.</p>
          )}
        </Panel>
      </div>
    </>
  );
}
