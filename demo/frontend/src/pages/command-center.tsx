import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  demoApi,
  type Overview,
  type Topology,
  type Health,
  type Forecast,
} from "@/lib/api";
import { useLiveRange } from "@/lib/live";
import { Badge, Kpi, Panel, Spinner, StatusDot, useNow } from "@/components/ui";
import LivePanels from "@/components/LivePanels";

type Node = Topology["nodes"][number];
type Edge = Topology["edges"][number];
type Actor = Overview["actors"][number];
type ThreatRow = Actor & {
  lead_time?: number;
  belief?: Forecast["belief"];
  predicted_stages?: string[];
  confidence?: number;
  risk_level?: string;
  risk_score?: number;
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
    held: "#ffdd4d",
    trapped: "#ff4d6d",
    active: "#ff5c5c",
    offline: "#5b6681",
    infra: "#2a3550",
    predicted: "#ff9d3b",
    serving: "#16c784",
    recovered: "#16c784",
    down: "#ff5c5c",
    na: "#5b6681",
  } as Record<string, string>)[s || ""] || "#5b6681";

const ACTOR_COLORS = ["#ff5c5c", "#ff9d3b", "#b44cff", "#4cd7ff", "#7dffb0", "#ffdd4d", "#8b9cfc", "#ff2d78"];

const actorColor = (id?: string) => {
  if (!id) return "#5b6681";
  let h = 0;
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return ACTOR_COLORS[h % ACTOR_COLORS.length];
};

const THREAT = new Set(["compromised", "contained"]);

const KC: [string, string][] = [
  ["recon", "reconnaissance"],
  ["discover", "discovery"],
  ["access", "initial_access"],
  ["execute", "execution"],
  ["move", "lateral_movement"],
  ["collect", "collection"],
];
const kcIndex = (stage?: string) => {
  const i = KC.findIndex(([, v]) => v === stage);
  return i < 0 ? 0 : i;
};

// Fixed theater regions. Zone infra nodes sit as *titles* above each box so
 // they never compete with live assets for space. Live nodes are seeded inside
 // their lane, then a label-bbox collision pass pushes anything that still
 // overlaps.
const ZONE_BOX = {
  CONTAINED: { x: 36, y: 300, w: 168, h: 210 },
  "THREAT-ZONE": { x: 220, y: 300, w: 280, h: 230 },
  HONEYNET: { x: 520, y: 300, w: 320, h: 230 },
  MAINTENANCE: { x: 860, y: 300, w: 190, h: 210 },
} as const;

function layout(nodes: Node[], edges: Edge[]) {
  const pos: Record<string, { x: number; y: number }> = {};
  // Spine
  pos["INTERNET"] = { x: 80, y: 72 };
  pos["FIREWALL"] = { x: 230, y: 72 };
  pos["CORE-SWITCH"] = { x: 390, y: 72 };
  // Zone titles sit on the top edge of each theater box (not the center).
  pos["CONTAINED"] = { x: ZONE_BOX.CONTAINED.x + ZONE_BOX.CONTAINED.w / 2, y: ZONE_BOX.CONTAINED.y + 14 };
  pos["THREAT-ZONE"] = { x: ZONE_BOX["THREAT-ZONE"].x + ZONE_BOX["THREAT-ZONE"].w / 2, y: ZONE_BOX["THREAT-ZONE"].y + 14 };
  pos["HONEYNET"] = { x: ZONE_BOX.HONEYNET.x + ZONE_BOX.HONEYNET.w / 2, y: ZONE_BOX.HONEYNET.y + 14 };
  pos["MAINTENANCE"] = { x: ZONE_BOX.MAINTENANCE.x + ZONE_BOX.MAINTENANCE.w / 2, y: ZONE_BOX.MAINTENANCE.y + 14 };

  const attacks = nodes.filter((n) => n.type === "attacker");
  const baits = nodes.filter((n) => n.bait);
  const forecasts = nodes.filter((n) => n.type === "forecast");
  const maintEdgeTargets = new Set(edges.filter((e) => e.kind === "maintenance").map((e) => e.target));
  const captureOf = new Map<string, string>();
  nodes.forEach((n) => { if ((n as any).capture_of) captureOf.set(n.id, (n as any).capture_of); });
  edges.filter((e) => e.kind === "capture").forEach((e) => captureOf.set(e.target, e.source));

  const servers = nodes.filter((n) => n.type === "asset" && n.role === "server" && !maintEdgeTargets.has(n.id) && !THREAT.has(n.status || "") && !/-DECOY$/i.test(n.id));
  const clients = nodes.filter((n) => n.type === "asset" && ["client", "host", "other"].includes(n.role || "") && !maintEdgeTargets.has(n.id) && !THREAT.has(n.status || ""));
  const threats = nodes.filter((n) => n.type === "asset" && !maintEdgeTargets.has(n.id) && THREAT.has(n.status || "") && !captureOf.has(n.id));
  const decoys = nodes.filter((n) => n.type === "asset" && (n.role === "decoy" || /-DECOY$/i.test(n.id)) && !n.bait && !captureOf.has(n.id));
  const captures = nodes.filter((n) => captureOf.has(n.id));
  const maint = nodes.filter((n) => maintEdgeTargets.has(n.id));

  // LAN band under the spine
  servers.forEach((n, i) => { pos[n.id] = { x: 280 + (i % 5) * 120, y: 168 + Math.floor(i / 5) * 88 }; });
  clients.forEach((n, i) => { pos[n.id] = { x: 560 + (i % 5) * 110, y: 150 + Math.floor(i / 5) * 80 }; });

  // Contained origins — left theater lane
  const cbox = ZONE_BOX.CONTAINED;
  threats.forEach((n, i) => {
    pos[n.id] = {
      x: cbox.x + 50 + (i % 2) * 80,
      y: cbox.y + 55 + Math.floor(i / 2) * 78,
    };
  });

  // Attackers — threat theater, spaced in a row
  const tbox = ZONE_BOX["THREAT-ZONE"];
  attacks.forEach((n, i) => {
    const cols = Math.min(2, Math.max(1, attacks.length));
    pos[n.id] = {
      x: tbox.x + 70 + (i % cols) * 140,
      y: tbox.y + 90 + Math.floor(i / cols) * 100,
    };
  });

  // Capture decoys sit beside their attacker inside the threat theater
  captures.forEach((n, i) => {
    const owner = captureOf.get(n.id);
    const op = owner ? pos[owner] : null;
    if (op) {
      pos[n.id] = { x: op.x + 110, y: op.y };
    } else {
      pos[n.id] = { x: tbox.x + 160 + (i % 2) * 90, y: tbox.y + 160 };
    }
  });

  // Honeynet farm — twins + REPL replicas in a clean grid
  const hbox = ZONE_BOX.HONEYNET;
  decoys.forEach((n, i) => {
    pos[n.id] = {
      x: hbox.x + 55 + (i % 3) * 100,
      y: hbox.y + 55 + Math.floor(i / 3) * 85,
    };
  });

  // Maintenance lane
  const mbox = ZONE_BOX.MAINTENANCE;
  maint.forEach((n, i) => {
    pos[n.id] = {
      x: mbox.x + 50 + (i % 2) * 90,
      y: mbox.y + 55 + Math.floor(i / 2) * 80,
    };
  });

  // Bait ring — wide orbit so labels clear the attacker + capture decoy
  baits.forEach((b) => {
    const center = pos[b.ring_of || ""];
    if (!center) {
      pos[b.id] = { x: hbox.x + 80, y: hbox.y + 170 };
      return;
    }
    const siblings = baits.filter((x) => x.ring_of === b.ring_of);
    const idx = siblings.indexOf(b);
    const a = (idx / Math.max(1, siblings.length)) * Math.PI * 2 - Math.PI / 2;
    const r = 92;
    pos[b.id] = { x: center.x + Math.cos(a) * r, y: center.y + Math.sin(a) * r };
  });

  forecasts.forEach((n, i) => {
    let cx = 390, cy = 170;
    if (n.id.startsWith("PRED-")) {
      const ownerEdge = edges.find((e) => e.kind === "prediction" && e.target === n.id);
      const owner = attacks.find((x) => x.id === ownerEdge?.source);
      if (owner && pos[owner.id]) { cx = pos[owner.id].x; cy = pos[owner.id].y; }
    }
    const dir = i % 2 === 0 ? -1 : 1;
    pos[n.id] = { x: cx + dir * 78, y: cy - 70 - Math.floor(i / 2) * 40 };
  });

  // Label-aware collision: approximate each live node's text footprint.
  const halfSize = (n: Node) => {
    const label = (n.label || n.id || "").length;
    if (n.type === "attacker") return { hx: Math.max(48, label * 3.2), hy: 42 };
    if (n.bait) return { hx: 36, hy: 28 };
    if (n.type === "forecast") return { hx: 40, hy: 28 };
    return { hx: Math.max(42, label * 2.9 + 8), hy: 36 };
  };
  const movable = nodes.filter((n) => n.type !== "infra");
  const zoneTitles = ["CONTAINED", "THREAT-ZONE", "HONEYNET", "MAINTENANCE"];
  let pass = 0;
  while (pass++ < 320) {
    let moved = false;
    for (let i = 0; i < movable.length; i++) {
      const na = movable[i];
      const a = pos[na.id];
      if (!a) continue;
      const sa = halfSize(na);
      // Keep clear of zone title markers
      for (const zid of zoneTitles) {
        const z = pos[zid];
        if (!z) continue;
        const dx = a.x - z.x, dy = a.y - z.y;
        const needX = sa.hx + 36, needY = sa.hy + 16;
        if (Math.abs(dx) < needX && Math.abs(dy) < needY) {
          const sx = dx === 0 ? (i % 2 ? 1 : -1) : Math.sign(dx);
          const sy = dy === 0 ? 1 : Math.sign(dy);
          a.x += sx * (needX - Math.abs(dx) + 1) * 0.55;
          a.y += sy * (needY - Math.abs(dy) + 1) * 0.55;
          moved = true;
        }
      }
      for (let j = i + 1; j < movable.length; j++) {
        const nb = movable[j];
        const b = pos[nb.id];
        if (!b) continue;
        const sb = halfSize(nb);
        const dx = b.x - a.x, dy = b.y - a.y;
        const needX = sa.hx + sb.hx + 6, needY = sa.hy + sb.hy + 4;
        if (Math.abs(dx) < needX && Math.abs(dy) < needY) {
          const sx = dx === 0 ? (i % 2 ? 1 : -1) : Math.sign(dx);
          const sy = dy === 0 ? (j % 2 ? 1 : -1) : Math.sign(dy);
          const px = (needX - Math.abs(dx)) / 2 + 0.8;
          const py = (needY - Math.abs(dy)) / 2 + 0.8;
          a.x -= sx * px; a.y -= sy * py;
          b.x += sx * px; b.y += sy * py;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }

  let maxX = 1080, maxY = 520;
  for (const p of Object.values(pos)) {
    maxX = Math.max(maxX, p.x + 70);
    maxY = Math.max(maxY, p.y + 56);
  }
  return { pos, viewBox: `0 0 ${Math.ceil(maxX + 20)} ${Math.ceil(maxY + 16)}` };
}

/** Truncate a line so it stops at the node radius instead of piercing the disc. */
function edgeEnds(
  ax: number, ay: number, bx: number, by: number,
  ra = 16, rb = 16,
): { x1: number; y1: number; x2: number; y2: number } {
  const dx = bx - ax, dy = by - ay;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  return {
    x1: ax + ux * ra,
    y1: ay + uy * ra,
    x2: bx - ux * rb,
    y2: by - uy * rb,
  };
}

const convColor = (lvl?: string | null) =>
  lvl === "critical" ? "#ff5c7a" : lvl === "high" ? "#ff9d4d" : lvl === "medium" ? "#d8a63b" : "#8c6bff";

// Node status pill rendered above stateful nodes so risk/attack/build/recover
// transitions are readable at a glance instead of encoded in color alone.
const pillFor = (n: Node): { text: string; fg: string; bg: string } | null => {
  if (n.type === "attacker") {
    return n.status === "trapped"
      ? { text: "TRAPPED", fg: "#ff4d6d", bg: "rgba(30,8,16,0.92)" }
      : { text: "ACTIVE", fg: "#ff5c5c", bg: "rgba(30,10,10,0.92)" };
  }
  if (n.bait) return { text: "SEG·BAIT", fg: "#b44cff", bg: "rgba(20,8,30,0.9)" };
  if (n.type === "forecast" || n.type === "infra") return null;
  if ((n as any).recovering) return { text: "RECOVERING", fg: "#f0b429", bg: "rgba(26,20,8,0.92)" };
  if ((n as any).last_restore_at) {
    const age = Date.now() - Date.parse((n as any).last_restore_at as string);
    if (!Number.isNaN(age) && age >= 0 && age < 45_000) {
      return { text: "RE-ADDED · FRESH SNAP", fg: "#16c784", bg: "rgba(10,26,20,0.92)" };
    }
  }
  if ((n as any).serving && (n.status === "healthy" || n.status === "serving" || n.status === "recovered")) {
    return { text: "SERVING", fg: "#16c784", bg: "rgba(10,26,20,0.92)" };
  }
  switch (n.status) {
    case "under_attack": return { text: "UNDER ATTACK", fg: "#ff5c5c", bg: "rgba(30,10,10,0.9)" };
    case "suspicious": return { text: "SUSPECTED", fg: "#f0b429", bg: "rgba(26,20,8,0.9)" };
    case "compromised": return { text: "COMPROMISED", fg: "#ff2d55", bg: "rgba(30,8,16,0.9)" };
    case "contained": return { text: "CONTAINED", fg: "#4c8dff", bg: "rgba(8,16,32,0.92)" };
    case "deception": return { text: "DECOY", fg: "#b44cff", bg: "rgba(20,8,30,0.9)" };
    case "maintenance": return { text: "MAINTENANCE", fg: "#f0b429", bg: "rgba(26,20,8,0.9)" };
    case "serving": case "recovered": return { text: "SERVING", fg: "#16c784", bg: "rgba(10,26,20,0.92)" };
    case "registering": return { text: "BOOTING", fg: "#4cd7ff", bg: "rgba(8,20,28,0.92)" };
    default: return null;
  }
};

const EDGE_LEGEND: { label: string; color: string }[] = [
  { label: "ingress", color: "#7c8aa6" },
  { label: "foothold", color: "#ffb15c" },
  { label: "prediction", color: "#8c6bff" },
  { label: "traffic", color: "#47d7ff" },
  { label: "capture", color: "#ff6a80" },
  { label: "bait", color: "#9b7dff" },
  { label: "maintenance", color: "#d3a233" },
  { label: "soft-404", color: "#ff6a80" },
];
const NODE_LEGEND: { label: string; color: string }[] = [
  { label: "SUSPECTED", color: "#d3a233" },
  { label: "UNDER ATTACK", color: "#ff6a80" },
  { label: "COMPROMISED", color: "#ff3d68" },
  { label: "CONTAINED", color: "#5f8bff" },
  { label: "DECOY", color: "#9b7dff" },
  { label: "RECOVERING", color: "#d3a233" },
  { label: "RE-ADDED", color: "#28c98b" },
  { label: "SERVING", color: "#28c98b" },
];

function KillChain({ actor }: { actor: ThreatRow }) {
  const idx = kcIndex(actor.stage);
  const trapped = !!actor.trapped;
  const ahead = (actor.predicted_stages || actor.prediction?.predicted_stages || []).filter(Boolean);
  return (
    <div className="killchain">
      {KC.map(([short], i) => {
        const on = i <= idx;
        const future = i > idx && ahead.includes(KC[i][1]);
        return (
          <span className="kc" key={short}>
            <span className={`kc-seg ${on ? "on" : future ? "future" : ""}`}>{on && "●"}</span>
            <span className="kc-lbl">{short.toUpperCase()}</span>
            {i < KC.length - 1 && <span className={`kc-arrow ${on ? "on" : ""}`}>→</span>}
          </span>
        );
      })}
      {trapped && <span className="kc kc-trap"><span className="kc-seg on trap">✕</span><span className="kc-lbl">TRAPPED</span></span>}
    </div>
  );
}

function HealthStrip({ health }: { health: Health | null }) {
  const dot = (ok: boolean | undefined) => <span className={`health-dot ${ok == null ? "unknown" : ok ? "ok" : "bad"}`} aria-hidden="true" />;
  const status = (ok: boolean | undefined) => ok == null ? "unknown" : ok ? "ready" : "unavailable";
  return (
    <div className="health-strip" aria-label="Demo service health">
      <span className="h-item">{dot(health?.db)} Database {status(health?.db)}</span>
      <span className="h-item">{dot(health?.model)} Model {status(health?.model)}{health?.model_version ? ` · ${health.model_version}` : ""}</span>
      <span className="h-item">{dot(health?.sse)} Event service {status(health?.sse)}</span>
      <span className="h-item">Simulation {health ? health.simulation ? "active" : "inactive" : "unknown"}</span>
      <span className="watermark">Demo range</span>
    </div>
  );
}

function Severity({ ov }: { ov: Overview }) {
  const risk = ov.prediction?.risk_score ?? 0;
  const sev = Math.min(100, Math.max(risk, (ov.threats || 0) * 18, (ov.contained || 0) * 30, (ov.trapped || 0) * 42));
  const cls = sev >= 80 ? "critical" : sev >= 60 ? "high" : sev >= 40 ? "medium" : "low";
  return (
    <div className="severity">
      <div className="sev-top">
        <span className="sev-lbl">SEVERITY</span>
        <b className={`sev-val sev-${cls}`}>{Math.round(sev)}</b>
        <Badge tone={cls === "critical" || cls === "high" ? "bad" : cls === "medium" ? "warn" : "good"}>{cls.toUpperCase()}</Badge>
      </div>
      <div className="sev-bar"><i style={{ width: `${sev}%` }} /></div>
    </div>
  );
}

function WhyContent({ pred }: { pred: Forecast | null | undefined }) {
  if (!pred) return <p className="muted">No world-model forecast recorded yet — it appears once the flow-wm model scores the current trajectory.</p>;
  const why = pred.explanation;
  const whyText = typeof why === "string" ? why : (typeof why === "object" && why ? (why as any).natural_language : "") || "";
  const factors = (typeof why === "object" && why && Array.isArray((why as any).top_factors)) ? (why as any).top_factors : undefined;
  const branches = pred.belief?.branches || [];
  return (
    <div className="why-list">
      {whyText && <p className="small" style={{ color: "#c9d6ef" }}>{whyText}</p>}
      {factors && factors.length > 0 && (
        <div className="why-factors">
          {factors.map((f: { feature: string; contribution: number }) => (
            <em key={f.feature} title={`contribution ${Math.round(f.contribution * 100)}%`}>
              {f.feature.replace(/_/g, " ")} {Math.round(f.contribution * 100)}%
            </em>
          ))}
        </div>
      )}
      {branches.length > 0 && (
        <table className="mini-table">
          <thead><tr><th>branch</th><th>stage</th><th>p</th><th>risk</th></tr></thead>
          <tbody>
            {branches.map((b) => (
              <tr key={b.branch}>
                <td className="mono">{b.branch}</td>
                <td>{b.stage || "—"}</td>
                <td>{Math.round((b.confidence || 0) * 100)}%</td>
                <td><b className={b.risk >= 80 ? "text-bad" : b.risk >= 60 ? "text-warn" : ""}>{Math.round(b.risk)}</b></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted tiny mt8">World-model output — never a scripted guess. Forecasts are recomputed per actor whenever the trajectory advances.</p>
    </div>
  );
}

function DefensiveResponse({ ov, focus }: { ov: Overview; focus: boolean }) {
  const steps = [
    { label: "Detection", on: (ov.incidents || []).length > 0 },
    { label: "Forecast", on: !!ov.prediction },
    { label: "Risk evaluation", on: !!ov.prediction },
    { label: "Containment", on: (ov.contained || 0) > 0 },
    { label: "Service failover", on: (ov.service?.serving || 0) > 0 && (ov.contained || 0) > -1 },
    { label: "Deception", on: (ov.decoys || 0) > 0 },
    { label: "Evidence", on: (ov.evidence_count || 0) > 0 },
  ];
  const cur = steps.findIndex((s) => !s.on);
  return (
    <div className={`def-steps ${focus ? "dimmed" : ""}`}>
      {steps.map((s, i) => {
        const state = s.on ? "done" : i === cur ? "cur" : "todo";
        return (
          <div className={`def-step ${state}`} key={s.label}>
            <span className="def-mark">{s.on ? "✓" : i === cur ? "●" : "○"}</span>
            <span className="def-label">{s.label}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function CommandCenter() {
  return <RangeTheater />;
}

/** Original range theatre implementation used by the demo command center. */
function RangeTheater() {
  const [selActor, setSelActor] = useState<string | null>(null);
  const [selAsset, setSelAsset] = useState<string | null>(null);
  const [convSel, setConvSel] = useState<string | null>(null);
  const [focusOn, setFocusOn] = useState(false);
  const [hold, setHold] = useState(false);
  const [wiresOn, setWiresOn] = useState(false);
  const [pinOpen, setPinOpen] = useState(false);
  const [pin, setPin] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [adminBusy, setAdminBusy] = useState<string | null>(null);
  const [pinBusy, setPinBusy] = useState(false);
  const [pinError, setPinError] = useState("");
  const presenterDialog = useRef<HTMLDivElement>(null);
  const holdRef = useRef(false);
  holdRef.current = hold;

  const live = useLiveRange({ paused: holdRef, intervalMs: 3000, toastAlerts: true });
  const { ov, topo, health, toasts, pushToast, dismissToast, lastUpdatedAt, error, refreshing, refresh } = live;
  const now = useNow();
  const stale = lastUpdatedAt !== null && now - lastUpdatedAt > 15000;
  const connectionLabel = hold ? "Feed paused" : error || stale ? "Reconnecting" : lastUpdatedAt ? "Telemetry connected" : "Connecting";

  useEffect(() => {
    if (!pinOpen) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    const dialog = presenterDialog.current;
    const focusable = () => Array.from(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), a[href], [tabindex="0"]') || []);
    focusable()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setPinOpen(false);
      }
      if (event.key === "Tab") {
        const targets = focusable();
        const first = targets[0];
        const last = targets[targets.length - 1];
        if (!first) { event.preventDefault(); dialog?.focus(); }
        else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousFocus?.focus();
    };
  }, [pinOpen, authorized]);

  const doAdmin = async (fn: (p: string) => Promise<unknown>, msg: string) => {
    if (!pin || adminBusy) return;
    setAdminBusy(msg);
    try {
      await fn(pin);
      pushToast({ tone: "info", title: msg, body: "The demo range accepted the request. Refreshing the latest status." });
      await refresh();
    } catch (e: any) {
      pushToast({ tone: "crit", title: "ADMIN FAILED", body: String(e?.message || e) });
    } finally {
      setAdminBusy(null);
    }
  };

  const layoutMemo = useMemo(() => (topo ? layout(topo.nodes, topo.edges) : null), [topo]);
  const pos = layoutMemo?.pos || {};

  const predTarget = ov?.incident?.predicted_target_id || undefined;
  const predictedNodes = useMemo(() => {
    const s = new Set<string>();
    if (predTarget) s.add(predTarget);
    (topo?.edges || []).forEach((e) => { if (e.kind === "prediction") s.add(e.target); });
    return s;
  }, [topo, predTarget]);
  const maintNodeIds = useMemo(() => new Set((topo?.edges || []).filter((e) => e.kind === "maintenance").map((e) => e.target)), [topo]);
  const originActors = useMemo(() => {
    const m = new Map<string, string>();
    (ov?.incidents || []).forEach((i) => { if (i.origin) m.set(i.origin, i.actor || ""); });
    return m;
  }, [ov]);

  const incByActor = useMemo(() => new Map((ov?.incidents || []).map((i) => [i.actor || "", i])), [ov]);

  const focusId = focusOn && selActor ? selActor : null;
  const focusInc = focusId ? incByActor.get(focusId) : null;

  const pk = (k?: string) => k === "capture" ? 6 : k === "bait" ? 5 : k === "deception" ? 4 : k === "foothold" ? 3 : k === "prediction" ? 3 : (k === "traffic" || k === "maintenance") ? 2 : k === "ingress" ? 1 : k === "service" ? 1 : (k === "zone" || k === "membership") ? 0 : 0;
  const visibleEdges = useMemo(() => {
    const bud: Record<string, Edge> = {};
    for (const e of topo?.edges || []) {
      // Zone/membership spokes are geography, not story — hide unless wires on.
      if ((e.kind === "zone" || e.kind === "membership") && !wiresOn) continue;
      const key = `${e.source}->${e.target}`;
      const prev = bud[key];
      if (!prev || pk(e.kind) >= pk(prev.kind)) bud[key] = e;
    }
    return Object.values(bud);
  }, [topo, wiresOn]);

  const forecastByInc = useMemo(() => {
    const m = new Map<string, Forecast>();
    (topo?.predictions || []).forEach((f) => { if (f.incident_id) m.set(f.incident_id, f); });
    return m;
  }, [topo]);
  const forecastFor = useCallback((incId?: string) => (incId ? forecastByInc.get(incId) : undefined), [forecastByInc]);

  const convByTarget = useMemo(() => {
    const m = new Map<string, NonNullable<Topology["convergence"]>[number]>();
    (topo?.convergence || []).forEach((c) => m.set(c.target, c));
    return m;
  }, [topo]);
  const predActorFor = useMemo(() => {
    const m = new Map<string, string>();
    (topo?.edges || []).forEach((e) => { if (e.kind === "prediction" && e.actor_id) m.set(e.target, e.actor_id); });
    return m;
  }, [topo]);
  const convActorIdx = useCallback((target: string, actor?: string) => {
    const g = convByTarget.get(target);
    if (!g || (g.count || 0) < 2) return -1;
    const i = g.actors.findIndex((x) => x.actor === actor);
    return i < 0 ? -1 : i;
  }, [convByTarget]);

  const threatRows = useMemo(() => {
    const briefs = new Map((topo?.actors || []).map((a) => [a.actor, a]));
    return (ov?.actors || []).map((a) => {
      const brief = briefs.get(a.actor);
      const f = forecastFor(a.incident_id);
      const row: ThreatRow = {
        ...a,
        ...(brief || {}),
        confidence: brief?.confidence ?? a.confidence ?? undefined,
        risk_level: brief?.risk_level ?? a.risk_level ?? undefined,
        risk_score: brief?.risk_score ?? a.risk_score ?? undefined,
        predicted_stages: f?.predicted_stages ?? a.prediction?.predicted_stages,
        lead_time: f?.lead_time ?? a.prediction?.lead_time,
        belief: f?.belief ?? a.prediction?.belief,
      };
      return row;
    });
  }, [ov, topo, forecastFor]);

  const isDimNode = (n: Node) => {
    if (!focusInc) return false;
    if (n.id === focusId) return false;
    if (n.ring_of === focusId) return false;
    if (n.id === focusInc.origin || n.id === focusInc.decoy) return false;
    const owner = predActorFor.get(n.id);
    if (owner && owner === focusId) return false;
    if (n.type === "infra") return false;
    return true;
  };
  const isDimEdge = (e: Edge) => {
    if (!focusInc) return false;
    return !(e.source === focusId || e.target === focusId
      || e.target === focusInc.origin || e.target === focusInc.decoy
      || (e.target === focusInc.predicted_target_id)
      || (e.source === focusInc.origin));
  };

  const boxes = useMemo(() => {
    if (!topo) return [] as { x: number; y: number; w: number; h: number; label: string; color: string }[];
    const ids = new Set(topo.nodes.map((n) => n.id));
    const out: { x: number; y: number; w: number; h: number; label: string; color: string }[] = [];
    if (ids.has("CONTAINED")) out.push({ ...ZONE_BOX.CONTAINED, label: "CONTAINED", color: "#4c8dff" });
    if (ids.has("THREAT-ZONE")) out.push({ ...ZONE_BOX["THREAT-ZONE"], label: "THREAT ZONE", color: "#ff5c5c" });
    if (ids.has("HONEYNET")) out.push({ ...ZONE_BOX.HONEYNET, label: "HONEYNET", color: "#b44cff" });
    if (ids.has("MAINTENANCE")) out.push({ ...ZONE_BOX.MAINTENANCE, label: "MAINTENANCE", color: "#f0b429" });
    return out;
  }, [topo]);

  const selInc = useMemo(() => (ov && selActor ? (incByActor.get(selActor) || null) : null), [ov, selActor, incByActor]);

  const panelInc = selActor ? (incByActor.get(selActor) || null) : (ov?.incidents?.[0] || null);
  const panelPred = (panelInc ? forecastFor(panelInc.id) : undefined) || panelInc?.prediction || ov?.prediction;
  const panelThreat = selActor ? (ov?.actors || []).find((a) => a.actor === selActor) : (ov?.actors || [])[0];
  const panelAction = panelPred
    ? (["high", "critical"].includes(panelPred.risk_level) ? "CONTAIN_AND_DECEIVE" : panelPred.risk_level === "medium" ? "ISOLATE_AND_MONITOR" : "MONITOR")
    : "—";

  const selAssetBrief = useMemo(() => (topo?.assets || []).find((a) => a.id === selAsset), [topo, selAsset]);
  const selAssetNode = useMemo(() => (topo?.nodes || []).find((n) => n.id === selAsset), [topo, selAsset]);
  const selAssetConvs = useMemo(() => (topo?.convergence || []).filter((c) => c.target === selAsset && (c.count || 0) >= 2), [topo, selAsset]);
  const selAssetPreds = useMemo(() => (topo?.convergence || []).filter((c) => c.target === selAsset && (c.count || 0) === 1), [topo, selAsset]);
  const selAssetActors = useMemo(() => (topo?.actors || []).filter((a) => a.origin === selAsset), [topo, selAsset]);
  const selAssetContainment = useMemo(() => (topo?.containment || []).filter((c) => c.asset_id === selAsset), [topo, selAsset]);
  const selAssetDeception = useMemo(() => (topo?.deception || []).filter((d) => d.predicted_target_id === selAsset), [topo, selAsset]);

  const markerFor = (kind?: string) => {
    switch (kind) {
      case "foothold": return "url(#aFoothold)";
      case "prediction": return "url(#aPred)";
      case "capture": return "url(#aCapture)";
      case "bait": return "url(#aBait)";
      case "traffic": return "url(#aTraffic)";
      case "ingress": return "url(#aIngress)";
      case "maintenance": return "url(#aMaint)";
      case "deception": return "url(#aDecoy)";
      default: return undefined;
    }
  };

  return (
    <div className="page command demo-console-shell main-replica">
      <a href="#demo-workspace" className="demo-skip-link">Skip to workspace</a>
      <header className="topbar demo-console-header main-replica-header">
        <div className="demo-console-brand">
          <span className="demo-console-mark main-replica-mark" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z" /><path d="m8 12 3 3 5-6" /></svg>
          </span>
          <div>
            <h1>Predictive Cyber Defence</h1>
            <span className="demo-console-subtitle">Demo operations console</span>
          </div>
        </div>
        <div className="demo-header-actions">
          <span className={`demo-connection ${hold || error || stale ? "is-warning" : lastUpdatedAt ? "is-connected" : ""}`} role="status">
            <span aria-hidden="true" />{connectionLabel}
          </span>
          <button className="demo-access-button" aria-haspopup="dialog" aria-expanded={pinOpen} onClick={() => { setPinError(""); setPinOpen(true); if (!pin && !authorized) setPin(""); }}>
            {authorized ? "Presenter controls" : "Presenter sign in"}
          </button>
        </div>
      </header>

      <nav className="demo-nav main-replica-nav" aria-label="Demo command center navigation">
        <Link href="/command-center" className="active" aria-current="page">Command Center</Link>
        <Link href="/action-center">Investigations</Link>
        <Link href="/ai-intelligence">AI Intelligence</Link>
        <Link href="/" >Join &amp; Scanner</Link>
        <Link href="/admin">Administration</Link>
      </nav>

      <div className="demo-console-toolbar" aria-label="Workspace controls">
        <div className="demo-toolbar-context">
          <span className="demo-environment-label">Demo range</span>
          <span className="muted small">{ov ? `${ov.incidents?.length || 0} active incident${ov.incidents?.length === 1 ? "" : "s"}` : "Waiting for telemetry"}</span>
        </div>
        <div className="demo-toolbar-actions">
        {authorized && (
          <div className="demo-presenter-actions" aria-busy={!!adminBusy}>
            <button className="tiny" disabled={!!adminBusy} onClick={() => doAdmin((p) => demoApi.admin.reset(p), "RANGE RESET")}>Reset</button>
            <button className="tiny" disabled={!!adminBusy} onClick={() => doAdmin((p) => demoApi.admin.deception(p), "DECEPTION ON")}>Decoys</button>
            <button className="tiny" disabled={!!adminBusy} onClick={() => doAdmin((p) => demoApi.admin.rollback(p), "DECEPTION OFF")}>Rollback</button>
            <button className="tiny" disabled={!!adminBusy} onClick={() => doAdmin((p) => demoApi.admin.exportTraining(p), "EXPORT EVENT LOG")}>Export</button>
            {adminBusy && <span className="muted small" role="status">Request in progress…</span>}
          </div>
        )}
        <button className={`tiny ${hold ? "danger" : ""}`} onClick={() => setHold((h) => !h)}>{hold ? "▶ Resume" : "❚❚ Hold"}</button>
        <button className={`tiny ${focusOn ? "primary" : ""}`} onClick={() => setFocusOn((f) => !f)} title="Focus a single actor's path">{focusOn ? "◎ focus" : "○ focus"}</button>
        <Link href="/action-center" className="btn tiny">Open investigations</Link>
        </div>
      </div>

      {toasts.length > 0 && (
        <div className="toast-stack" role="region" aria-label="Demo notifications" aria-live="polite" aria-relevant="additions">
          {toasts.map((t) => (
            <div className={`toast toast-${t.tone}`} key={t.id}>
              <b>{t.title}</b>
              <span className="small">{t.body}</span>
              <button className="toast-close" onClick={() => dismissToast(t.id)} aria-label={`Dismiss ${t.title}`}>×</button>
            </div>
          ))}
        </div>
      )}

      <HealthStrip health={health} />

      {!hold && (error || stale) && (
        <div className="demo-telemetry-notice" role="status">
          <div><b>Telemetry connection interrupted</b><span>{error || "The last snapshot is more than 15 seconds old. Retrying automatically."}</span></div>
          <button className="tiny" disabled={refreshing} onClick={() => void refresh()}>{refreshing ? "Reconnecting…" : "Retry now"}</button>
        </div>
      )}

      {hold && (
        <div className="hold-banner">
          <b>⏸ FEED ON HOLD — present this frame. </b>
          <button className="primary" onClick={() => setHold(false)}>▶ resume live</button>
        </div>
      )}

      <div className="kpis kpis-compact main-replica-kpis">
        <Kpi label="Range service"
          value={ov ? <span title={`${ov?.service?.serving || 0}/${ov?.service?.replicas || 0} replicas · fallback ${ov?.service?.fallback || "—"}`}>{ov.service?.status?.toUpperCase() || "—"}</span> : "—"}
          accent={ov?.service?.status === "serving" ? "#16c784" : "#ff5c5c"} />
        <Kpi label="Threats" value={ov ? ov.threats : "—"} accent="#ff5c5c" />
        <Kpi label="Contained" value={ov ? ov.contained : "—"} accent="#4c8dff" />
        <Kpi label="Decoys" value={ov ? ov.decoys : "—"} accent="#b44cff" />
        <Kpi label="Actors" value={ov ? ov.attackers : "—"} accent="#f0b429" />
        <Kpi label="Trapped" value={ov ? ov.trapped : "—"} accent="#ff4d6d" />
        <Kpi label="Observed assets" value={ov ? ov.online_assets : "—"} />
        <Kpi label="Live nodes" value={topo ? topo.nodes.filter((n) => n.type !== "infra").length : "—"} accent="#4cd7ff" />
      </div>

      <div className="operator-workspace-note">
        <b>Observed devices · simulated scenarios</b>
        <span>The scanner and enrolled devices supply network observations. Threat scenarios and defensive responses belong to the demo range.</span>
        <span className="demo-snapshot-time">{lastUpdatedAt ? `Last received ${new Date(lastUpdatedAt).toLocaleTimeString()}` : "Awaiting first snapshot"}</span>
      </div>

      <main id="demo-workspace" tabIndex={-1} aria-label="Demo command center workspace" className="main-replica-body">
      {!ov ? (
        error ? <div className="demo-empty-state"><h2>Waiting for demo telemetry</h2><p>Keep this page open while the demo service reconnects. Use Retry now to check again.</p></div> : <Spinner label="Connecting to demo telemetry…" />
      ) : (
        <>
          <div className="stage-hero main-replica-workspace">
            <aside className="demo-sidebar main-replica-sidebar">
              <Panel className="demo-side-panel" title="Incident queue">
                <div className="demo-side-list">
                  {(ov.incidents || []).slice(0, 6).map((incident) => (
                    <button key={incident.id} className="demo-side-item" aria-pressed={!!incident.actor && selActor === incident.actor} onClick={() => setSelActor(incident.actor || null)}>
                      <span className={`demo-side-dot ${incident.trapped ? "bad" : incident.status === "contained" ? "good" : "warn"}`} />
                      <span className="grow">
                        <b>{incident.actor || incident.id}</b>
                        <small>{incident.stage.replace(/_/g, " ")} · {incident.status}</small>
                      </span>
                    </button>
                  ))}
                  {!ov.incidents?.length && <div className="demo-empty-state compact"><b>No active incidents</b><p>New demo incidents will appear here when a scenario starts.</p></div>}
                </div>
              </Panel>

              <Panel className="demo-side-panel" title="Range status">
                <div className="demo-side-stats">
                  <div><span>Observed</span><b>{ov.online_assets}</b></div>
                  <div><span>Attackers</span><b>{ov.attackers}</b></div>
                  <div><span>Contained</span><b>{ov.contained}</b></div>
                  <div><span>Decoys</span><b>{ov.decoys}</b></div>
                  <div><span>Trapped</span><b>{ov.trapped}</b></div>
                  <div><span>Service</span><b>{ov.service?.status?.toUpperCase() || "—"}</b></div>
                </div>
                <div className="demo-side-links">
                  <Link href="/" className="tiny primary">Join / scanner</Link>
                  <Link href="/action-center" className="tiny">Evidence replay</Link>
                </div>
              </Panel>
            </aside>

            <div className="relative">
            <Panel className="topo-panel main-replica-topology" title={`Network topology · LIVE (${(ov.incidents || []).length} active incident${(ov.incidents || []).length === 1 ? "" : "s"})`}
              right={
                <div className="flex" style={{ gap: 8, alignItems: "center" }}>
                  {focusOn && selActor
                    ? <span className="mono small muted">focused · {selActor}{selAsset ? ` · asset ${selAsset}` : ""}</span>
                    : selAsset
                      ? <button className="tiny" onClick={() => setSelAsset(null)}>✕ close asset</button>
                      : <span className="mono small muted">click any node for detail</span>}
                  <button className={`tiny ${wiresOn ? "primary" : ""}`} onClick={() => setWiresOn((w) => !w)} title="Show/hide the plain connectivity wires between infrastructure and every host">
                    {wiresOn ? "wires on" : "wires off"}
                  </button>
                </div>
              }>
              {topo && (
                <svg viewBox={layoutMemo?.viewBox || "0 0 1000 440"} className="topology topology-polished">
                  <defs>
                    <pattern id="topologyGrid" width="28" height="28" patternUnits="userSpaceOnUse">
                      <path d="M 28 0 L 0 0 0 28" fill="none" stroke="#22324b" strokeOpacity="0.45" strokeWidth="1" />
                    </pattern>
                    <radialGradient id="topologyGlow" cx="50%" cy="34%" r="72%">
                      <stop offset="0%" stopColor="#16253e" stopOpacity="0.95" />
                      <stop offset="55%" stopColor="#08101d" stopOpacity="0.88" />
                      <stop offset="100%" stopColor="#03060b" stopOpacity="1" />
                    </radialGradient>
                    <linearGradient id="zoneContained" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#19396c" stopOpacity="0.9" />
                      <stop offset="100%" stopColor="#0d1525" stopOpacity="0.7" />
                    </linearGradient>
                    <linearGradient id="zoneThreat" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#3a1c25" stopOpacity="0.92" />
                      <stop offset="100%" stopColor="#120d17" stopOpacity="0.76" />
                    </linearGradient>
                    <linearGradient id="zoneHoney" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#2d1d4b" stopOpacity="0.92" />
                      <stop offset="100%" stopColor="#120c22" stopOpacity="0.76" />
                    </linearGradient>
                    <linearGradient id="zoneMaint" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#4a3612" stopOpacity="0.9" />
                      <stop offset="100%" stopColor="#130f0a" stopOpacity="0.76" />
                    </linearGradient>
                    <marker id="aBait" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#9b7dff" /></marker>
                    <marker id="aCapture" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#ff6a80" /></marker>
                    <marker id="aFoothold" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#ffb15c" /></marker>
                    <marker id="aPred" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#8c6bff" /></marker>
                    <marker id="aTraffic" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4.5" markerHeight="4.5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#47d7ff" /></marker>
                    <marker id="aIngress" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#7c8aa6" /></marker>
                    <marker id="aMaint" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#d3a233" /></marker>
                    <marker id="aDecoy" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#9b7dff" /></marker>
                  </defs>
                  <rect x="0" y="0" width="100%" height="100%" fill="url(#topologyGlow)" />
                  <rect x="0" y="0" width="100%" height="100%" fill="url(#topologyGrid)" opacity="0.42" />
                  <ellipse cx="360" cy="104" rx="260" ry="82" fill="#1d355f" opacity="0.08" />
                  <ellipse cx="805" cy="148" rx="280" ry="92" fill="#5d2d82" opacity="0.08" />
                  {boxes.map((b, i) => (
                    <g key={i}>
                      <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={16}
                        fill={b.label === "CONTAINED" ? "url(#zoneContained)" : b.label === "THREAT ZONE" ? "url(#zoneThreat)" : b.label === "HONEYNET" ? "url(#zoneHoney)" : "url(#zoneMaint)"}
                        stroke={b.color} strokeOpacity={0.5}
                        strokeWidth={1.4} strokeDasharray="6 5" />
                      <rect x={b.x + 10} y={b.y + 10} width={b.w - 20} height="24" rx={8}
                        fill={b.color} opacity="0.12" />
                      <text x={b.x + 16} y={b.y + 26} fontSize={9.5} fontWeight={800}
                        letterSpacing={1.2} fill={b.color}>{b.label}</text>
                    </g>
                  ))}
                  {visibleEdges.map((e: Edge, i) => {
                    const a = pos[e.source], b = pos[e.target];
                    if (!a || !b) return null;
                    const flow = e.flow || 0;
                    const isWire = !e.kind || e.kind === "zone" || e.kind === "membership";
                    let opacity = 1;
                    if (isWire) opacity = wiresOn ? 0.28 : 0.04;
                    else if (isDimEdge(e)) opacity = 0.06;
                    const dim = opacity < 1 ? { opacity } : {};
                    const style = (() => {
                      switch (e.kind) {
                        case "capture": return { stroke: "#ff6a80", dash: "7 6", width: 3.8, dur: Math.max(0.55, 1.3 - flow * 0.22) };
                        case "bait": return { stroke: "#9b7dff", dash: "3 6", width: 2.8, dur: Math.max(0.7, 1.6 - flow * 0.2) };
                        case "foothold": return { stroke: "#ffb15c", dash: "6 5", width: 3.2, dur: Math.max(0.7, 1.5 - flow * 0.18) };
                        case "prediction": {
                          const level = convByTarget.get(e.target);
                          const col = level && (level.count || 0) >= 2 ? "#8c6bff" : "#ffb15c";
                          return { stroke: col, dash: "2 7", width: 2.4, dur: 1.4 };
                        }
                        case "traffic": return { stroke: "#47d7ff", dash: "4 6", width: 2.2, dur: Math.max(0.9, 2 - flow * 0.4) };
                        case "ingress": return { stroke: "#7c8aa6", dash: "3 6", width: 2.1, dur: 1.6 };
                        case "deception": return { stroke: "#9b7dff", dash: "6 5", width: 3, dur: 1.2 };
                        case "service": return { stroke: "#28c98b", dash: "4 6", width: 2.1, dur: 1.6 };
                        case "maintenance": return { stroke: "#d3a233", dash: "5 5", width: 2.4, dur: 1.8 };
                        case "zone":
                        case "membership": return { stroke: "#24415f", dash: "2 7", width: 1.4, dur: 2 };
                        default: return { stroke: flow ? "#355577" : "#1d2a3d", dash: flow ? "3 5" : null, width: flow ? 2 : 1.4, dur: 1.4 };
                      }
                    })();
                    const srcNode = topo.nodes.find((n) => n.id === e.source);
                    const dstNode = topo.nodes.find((n) => n.id === e.target);
                    const ra = srcNode?.type === "attacker" ? (srcNode.status === "trapped" ? 20 : 12) : srcNode?.bait ? 7 : srcNode?.type === "infra" ? 8 : 14;
                    const rb = dstNode?.type === "attacker" ? (dstNode.status === "trapped" ? 20 : 12) : dstNode?.bait ? 7 : dstNode?.type === "infra" ? 8 : 14;
                    const ends = edgeEnds(a.x, a.y, b.x, b.y, ra + 2, rb + 2);
                    const moving = flow > 0 || e.kind === "capture" || e.kind === "bait" || e.kind === "foothold" || e.kind === "traffic";
                    const cidx = e.kind === "prediction" ? convActorIdx(e.target, e.actor_id) : -1;
                    const curve = e.kind === "ingress" || e.kind === "foothold" || cidx >= 0;
                    if (curve) {
                      const dx = ends.x2 - ends.x1, dy = ends.y2 - ends.y1;
                      const len = Math.hypot(dx, dy) || 1;
                      const off = cidx >= 0
                        ? (cidx % 2 === 0 ? 1 : -1) * (14 + 8 * Math.floor(cidx / 2))
                        : e.kind === "ingress" ? 36 : 18;
                      const mx = (ends.x1 + ends.x2) / 2 + (-dy / len) * off;
                      const my = (ends.y1 + ends.y2) / 2 + (dx / len) * off;
                      return (
                        <g key={i} {...dim}>
                          <path d={`M ${ends.x1} ${ends.y1} Q ${mx} ${my} ${ends.x2} ${ends.y2}`} fill="none"
                            stroke={style.stroke} strokeWidth={style.width}
                            strokeDasharray={style.dash || undefined} className={moving ? "edge-flow" : ""}
                            markerEnd={!isWire ? markerFor(e.kind) : undefined}
                            style={moving && style.dash ? { animationDuration: `${style.dur}s` } : undefined} />
                          {e.confidence != null && (
                            <text x={mx} y={my - 7} textAnchor="middle" fontSize={8} fill="#f0b429" className="edge-lbl">
                              {Math.round(e.confidence * 100)}%
                            </text>
                          )}
                        </g>
                      );
                    }
                    return (
                      <g key={i} {...dim}>
                        <line
                          x1={ends.x1} y1={ends.y1} x2={ends.x2} y2={ends.y2}
                          stroke={style.stroke} strokeWidth={style.width}
                          strokeDasharray={style.dash || undefined}
                          markerEnd={!isWire ? markerFor(e.kind) : undefined}
                          className={moving ? "edge-flow" : ""}
                          style={moving && style.dash ? { animationDuration: `${style.dur}s` } : undefined}
                        />
                        {e.kind === "prediction" && e.confidence != null && (
                          <text x={(ends.x1 + ends.x2) / 2} y={(ends.y1 + ends.y2) / 2 - 6} textAnchor="middle" fontSize={8} fill="#f0b429" className="edge-lbl">
                            {Math.round(e.confidence * 100)}%
                          </text>
                        )}
                      </g>
                    );
                  })}
                  {topo.nodes.map((n) => {
                    const p = pos[n.id];
                    if (!p) return null;
                    const inMaint = maintNodeIds.has(n.id);
                    const actor = originActors.get(n.id);
                    const conv = convByTarget.get(n.id);
                    const isConv = !!conv && (conv.count || 0) >= 2;
                    const isPred = predictedNodes.has(n.id);
                    const c = statusColor(n.status);
                    const dim = isDimNode(n) ? { opacity: 0.08 } : {};
                    const pill = pillFor(n);
                    const isZoneTitle = n.type === "infra" && (n.id.includes("ZONE") || n.id.includes("HONEY") || n.id === "CONTAINED" || n.id === "MAINTENANCE");
                    if (isZoneTitle) {
                      // Titles are drawn on the theater boxes — skip the disc so
                      // labels never fight the zone header text.
                      return null;
                    }
                    if (n.type === "attacker") {
                      const trapped = n.status === "trapped";
                      return (
                        <g key={n.id} className={`clickable ${dim.opacity ? "dim" : ""}`}
                          onClick={() => { setSelActor((id) => (id === n.id ? null : n.id)); setSelAsset(null); }}>
                          <circle cx={p.x} cy={p.y} r={22} fill="none"
                            stroke={actorColor(n.id)} strokeWidth={1} strokeDasharray="4 5" className="orbit-ring" />
                          {!trapped && <circle cx={p.x} cy={p.y} r={12}
                            fill="none" stroke={actorColor(n.id)} strokeWidth={1} className="spawn-ripple" />}
                          <circle cx={p.x} cy={p.y} r={trapped ? 18 : 12} fill={trapped ? "#22111a" : "#101823"}
                            stroke={trapped ? "#ff6a80" : actorColor(n.id)} strokeWidth={2.5} className={trapped ? "capture-pull" : ""} />
                          {trapped && <circle cx={p.x} cy={p.y} r={2.5} fill="#ff6a80" />}
                          <text x={p.x} y={p.y + 4} textAnchor="middle" fontSize={11} fontWeight={800}
                            fill={trapped ? "#ff4d6d" : actorColor(n.id)}>⚠</text>
                          <text x={p.x} y={p.y + 32} textAnchor="middle" fontSize={9} fill={trapped ? "#ff4d6d" : actorColor(n.id)}>
                            {n.label.replace(/^ATK · /, "")}
                          </text>
                          {pill && (
                            <g>
                              <rect x={p.x - pill.text.length * 3.05 - 4} y={p.y - 34} width={pill.text.length * 6.1 + 8} height={12} rx={6}
                                fill={pill.bg} stroke={pill.fg} strokeWidth={0.6} strokeOpacity={0.7} />
                              <text x={p.x} y={p.y - 25} textAnchor="middle" fontSize={7} fontWeight={700} fill={pill.fg}>{pill.text}</text>
                            </g>
                          )}
                        </g>
                      );
                    }
                    if (n.type === "forecast") {
                      return (
                        <g key={n.id} className={dim.opacity ? "dim" : ""}>
                          <rect x={p.x - 22} y={p.y - 9} width={44} height={18} rx={5}
                            fill="#171229" stroke="#8c6bff" strokeWidth={1.2} strokeDasharray="3 4" className="forecast-bob" />
                          <text x={p.x} y={p.y + 3} textAnchor="middle" fontSize={8.5} fontWeight={700} fill="#8c6bff">PRED</text>
                          <text x={p.x} y={p.y + 25} textAnchor="middle" fontSize={8.5} fill="#cfd9ff">{n.label}</text>
                        </g>
                      );
                    }
                    if (n.bait) {
                      return (
                        <g key={n.id} className={dim.opacity ? "dim" : ""}>
                          <circle cx={p.x} cy={p.y} r={7} fill="#161224" stroke="#9b7dff" strokeWidth={1.5} strokeDasharray="3 2" className="bait-bob" />
                          <text x={p.x} y={p.y + 20} textAnchor="middle" fontSize={7.5} fill="#9b7dff">{n.presented_as || "SEG"}</text>
                        </g>
                      );
                    }
                    return (
                      <g key={n.id} className={`${n.type === "asset" ? "clickable" : ""} ${dim.opacity ? "dim" : ""}`}
                        onClick={n.type === "asset" ? () => setSelAsset(n.id) : undefined}>
                        {isConv && (
                          <g className="clickable" onClick={(ev) => { ev.stopPropagation(); setConvSel(n.id); }}>
                            <circle cx={p.x} cy={p.y} r={28} fill={`rgba(140,107,255,0.12)`} stroke="#8c6bff"
                              strokeWidth={2} strokeDasharray="4 4" className="pulse-ring" />
                            <text x={p.x} y={p.y - 38} textAnchor="middle" fontSize={8} fontWeight={700} fill="#8c6bff">
                              ⚠ ×{conv?.count || 0}
                            </text>
                          </g>
                        )}
                        {isPred && <circle cx={p.x} cy={p.y} r={24} fill="rgba(255,106,128,0.10)" stroke="#ff6a80" strokeWidth={1.5} strokeDasharray="4 4" className="pulse-ring slow" />}
                        {inMaint && <circle cx={p.x} cy={p.y} r={24} fill="rgba(211,162,51,0.10)" stroke="#d3a233" strokeWidth={1.5} strokeDasharray="6 4" className="maintenance-spin" />}
                        <circle cx={p.x} cy={p.y} r={n.type === "infra" ? 9 : 13}
                          fill={n.type === "infra" ? "#16253b" : c}
                          stroke={actor ? actorColor(actor) : inMaint ? "#d3a233" : (n.status === "serving" || n.status === "healthy" ? "#28c98b" : "#182235")}
                          strokeWidth={actor ? 2.6 : 2} />
                        <text x={p.x} y={p.y + 28} textAnchor="middle" fontSize={9.5}
                          fill={actor ? actorColor(actor) : inMaint ? "#d3a233" : "#96a5bf"}>
                          {n.label}{isPred ? " ⚠" : inMaint ? " ⛃" : ""}
                        </text>
                        {pill && (
                          <g>
                            <rect x={p.x - pill.text.length * 3.05 - 4} y={p.y - 26} width={pill.text.length * 6.1 + 8} height={12} rx={6}
                              fill={pill.bg} stroke={pill.fg} strokeWidth={0.6} strokeOpacity={0.7} />
                            <text x={p.x} y={p.y - 17} textAnchor="middle" fontSize={7} fontWeight={700} fill={pill.fg}>{pill.text}</text>
                          </g>
                        )}
                      </g>
                    );
                  })}
                  {topo && topo.nodes.every((n) => n.type === "infra") && (
                    <text x={450} y={200} textAnchor="middle" fontSize={12} fill="#6f809f">
                      waiting for devices / engagements — spine only
                    </text>
                  )}
                </svg>
              )}
              {topo && topo.nodes.every((n) => n.type === "infra") && (
                <div className="note mt8">
                  <b>Range spine ready.</b> Join as a device or open an attacker engagement — live nodes appear the moment they heartbeat.
                </div>
              )}
              <div className="legend mt8">
                <span className="legend-title">LEGEND</span>
                {EDGE_LEGEND.map((l) => (
                  <span className="legend-chip" key={l.label}><i style={{ background: l.color }} />{l.label}</span>
                ))}
                <span className="legend-sep" />
                {NODE_LEGEND.map((l) => (
                  <span className="legend-chip" key={l.label}><i className="node" style={{ background: l.color }} />{l.label}</span>
                ))}
                <span className="legend-sep" />
                <span className="legend-chip"><i className="node wire" style={{ background: wiresOn ? "#7e8db0" : "transparent" }} />wires {wiresOn ? "on" : "off"}</span>
              </div>
            </Panel>

            {selAsset && (
              <div className="asset-panel">
                <Panel title={`Node detail · ${selAsset || ""}`}
                  right={<button className="tiny" onClick={() => setSelAsset(null)}>✕</button>}>
                  <div className="rows">
                    <div className="row"><span className="grow">Hostname</span><b>{selAssetNode?.label || selAssetBrief?.name || "—"}</b></div>
                    <div className="row"><span className="grow">Role / type</span><b>{selAssetNode?.role || selAssetBrief?.role || "—"} · {selAssetNode?.asset_type || selAssetBrief?.asset_type || "—"}</b></div>
                    <div className="row"><span className="grow">Status</span>
                      <Badge tone={selAssetNode?.status === "healthy" || selAssetNode?.status === "serving" || selAssetNode?.status === "recovered" ? "good" : ["compromised", "contained", "trapped", "deception"].includes(selAssetNode?.status || "") ? "bad" : selAssetNode?.status === "suspicious" || selAssetNode?.status === "under_attack" ? "warn" : "plain"}>
                        {(selAssetNode?.status || selAssetBrief?.status || "—").toUpperCase()}
                      </Badge>
                    </div>
                    <div className="row"><span className="grow">Zone / IP</span><b className="mono">{selAssetNode?.zone || "—"} · {selAssetNode?.ip || selAssetBrief?.ip || "—"}</b></div>
                    <div className="row"><span className="grow">Criticality</span><b>{selAssetNode?.criticality || selAssetBrief?.criticality || "—"}</b></div>
                  </div>
                  {selAssetActors.length > 0 && (
                    <div className="note mt8">
                      <b className="text-bad">ATTACK ORIGIN</b>
                      {selAssetActors.map((a) => (
                        <div className="small mono" key={a.actor}>{a.actor} · stage {a.stage}{a.trapped ? " · TRAPPED" : ""}</div>
                      ))}
                    </div>
                  )}
                  {selAssetConvs.length > 0 && (
                    <div className="note mt8">
                      <b className="text-bad">CONVERGENCE TARGET</b>
                      {selAssetConvs.map((g) => (
                        <div className="small" key={g.target}>
                          {g.actors.map((x) => x.actor).join(" + ")} converging · aggregate {g.aggregate_risk_level?.toUpperCase()} ({Math.round(g.aggregate_risk_score || 0)})
                        </div>
                      ))}
                    </div>
                  )}
                  {selAssetPreds.length > 0 && (
                    <div className="note mt8">
                      <b className="text-warn">PREDICTED NEXT TARGET</b>
                      {selAssetPreds.map((g) => (
                        <div className="small" key={g.target}>{g.actors.map((x) => `${x.actor} (${x.stage})`).join(" · ")}</div>
                      ))}
                    </div>
                  )}
                  {selAssetDeception.length > 0 && (
                    <div className="note mt8">
                      <b className="text-purple">DECOY TWIN ACTIVE</b>
                      {selAssetDeception.map((d) => (
                        <div className="small" key={d.decoy_id}>steered to {d.decoy_name} ({d.decoy_id})</div>
                      ))}
                    </div>
                  )}
                  {selAssetContainment.length > 0 && (
                    <div className="note mt8">
                      <b className="text-blue">CONTAINED BY {selAssetContainment[0].actor}</b>
                      <div className="small muted">Quarantined in THREAT ZONE — the server only ever answers a soft 404; traffic failed over to a replica. Restore & re-add from clean snapshot when diagnostics pass.</div>
                    </div>
                  )}
                  <div className="note mt8">
                    <b>RECOMMENDED</b>
                    <div className="small">
                      {selAssetContainment.length > 0 ? "Complete diagnostics → restore from clean snapshot → re-add → re-snapshot."
                        : selAssetConvs.length > 0 ? "Reinforce deception at this target — multiple trajectories converge here; isolate and steer to the honeynet."
                          : selAssetActors.length > 0 ? "Contain origin, fail the service over to a continuity replica, stage the predictive decoy."
                            : selAssetPreds.length > 0 ? "Pre-stage a predictive decoy twin; route the converging paths to the deception farm."
                              : "Healthy — continue monitoring. No action required."}
                    </div>
                  </div>
                </Panel>
              </div>
            )}
            </div>

          <div className="stage-hero-side main-replica-right">
            <Panel title="ACTIVE THREAT ACTORS" right={focusOn && selActor ? <button className="tiny" onClick={() => { setFocusOn(false); setSelActor(null); }}>✕ unfocus</button> : <Link href="/action-center" className="tiny">deep tools →</Link>}>
              <div className="threat-list">
                {threatRows.map((a) => {
                  const conf = topo?.actors?.find((x) => x.actor === a.actor)?.confidence ?? a.confidence;
                  return (
                    <div key={a.actor} className={`actor-card ${selActor === a.actor ? "selected" : ""}`}>
                      <button className="row actor-row" style={{ textAlign: "left" }} onClick={() => { setSelActor((id) => (id === a.actor ? null : a.actor)); setSelAsset(null); }}>
                        <span className={`dot ${a.trapped ? "trap-dot" : ""}`} style={{ background: a.trapped ? "#ff4d6d" : actorColor(a.actor), flex: "none" }} />
                        <span className="grow">
                          <b>{a.actor}</b>
                          {conf != null && <span className="mono tiny" style={{ color: "#f0b429" }}> {Math.round(conf * 100)}%</span>}
                          <span className="muted small"> at {a.origin || "?"}</span>
                          {a.trapped ? <span className="badge tone-bad">trapped</span> : null}
                          {a.converging && <span className="badge tone-purple">converging</span>}
                        </span>
                        <b className="muted small">→ {a.predicted_target || "?"}</b>
                      </button>
                      <div className="actor-meta">
                        <Badge tone={a.trapped ? "bad" : a.deception ? "purple" : a.status === "contained" ? "good" : "warn"}>{a.trapped ? "captured" : a.stage || "recon"}</Badge>
                        {a.risk_level && <span className={`badge risk-tag`} style={{ background: convColor(a.risk_level), color: "#0b0f1a" }}>{a.risk_level.toUpperCase()}</span>}
                        {a.lead_time != null && <span className="muted tiny mono">lead ~{Math.max(0, Math.round(a.lead_time))}s</span>}
                      </div>
                      <KillChain actor={a} />
                    </div>
                  );
                })}
                {!threatRows.length && <p className="muted">No active threat actors.</p>}
              </div>
            </Panel>

            <Panel title={`WORLD MODEL FORECAST${panelThreat ? ` · ${panelThreat.actor}` : ""}`}>
              {panelPred ? (
                <div className="rows">
                  <div className="row"><span className="grow">Current asset · stage</span><b className="mono small">{panelInc?.origin || "?"} · {panelPred.current_stage.replace(/_/g, " ")}</b></div>
                  <div className="row"><span className="grow">Predicted target</span><b className="text-warn">{panelPred.predicted_target || "—"}</b></div>
                  <div className="row"><span className="grow">Confidence</span><b>{(panelPred.confidence || 0) * 100 >= 0 ? `${Math.round((panelPred.confidence || 0) * 100)}%` : "—"}</b></div>
                  <div className="row"><span className="grow">Lead time</span><b className="mono">~{Math.max(0, Math.round(panelPred.lead_time || 0))}s</b></div>
                  <div className="row"><span className="grow">Risk</span><Badge tone={["high", "critical"].includes(panelPred.risk_level) ? "bad" : panelPred.risk_level === "medium" ? "warn" : "good"}>{(panelPred.risk_level || "").toUpperCase()}</Badge></div>
                  <div className="row"><span className="grow">Stages ahead</span><span className="mono small">{(panelPred.predicted_stages || []).join(" → ") || "—"}</span></div>
                  <div className="row"><span className="grow">Recommended reply</span><b>{panelAction}</b></div>
                </div>
              ) : (
                <p className="muted">No forecast yet — the flow-wm model issues one once an attacker starts moving.</p>
              )}
            </Panel>

            <Panel title="WHY THIS TARGET? · evidence trail">
              <div className="scroll-soft">
                <WhyContent pred={panelPred} />
              </div>
            </Panel>

            <Panel title="DEFENSIVE RESPONSE">
              <DefensiveResponse ov={ov} focus={focusOn && !selActor} />
              <p className="muted tiny mt8">Step pulse runs live as the playbook advances; the current step is marked ●.</p>
            </Panel>

            <Panel title={`Service continuity · ${ov.service?.domain || "range"}`}>
              <Severity ov={ov} />
              <div className="note mt8 maint-strong">
                <b className="blink-text text-warn">MAINTENANCE IS ACTIVE —</b>{" "}
                <span>contained servers stay visible, diagnostics keep running, and restore-to-production remains gated behind admin approval until checks pass.</span>
              </div>
              <div className="rows mt8">
                <div className="row"><span className="grow">Availability</span><Badge tone={ov.service?.status === "serving" ? "good" : "bad"}>{ov.service?.status?.toUpperCase() || "—"}</Badge></div>
                <div className="row"><span className="grow">Replicas serving</span><b>{ov.service?.serving || 0}/{ov.service?.replicas || 0}</b></div>
                <div className="row"><span className="grow">Client load</span><b className="mono small">
                  {ov.service?.client_load ? Object.entries(ov.service.client_load).map(([sid, n]) => `${sid}×${n}`).join(" · ") : "—"}
                </b></div>
                <div className="row"><span className="grow">Real / honeypot</span><b>{ov.service?.continuity ? `${ov.service.continuity.real_serving} / ${ov.service.continuity.honeypot}` : "—"}</b></div>
                <div className="row"><span className="grow">Failover</span><b className="text-good">{ov.service?.fallback || "—"}</b></div>
                <div className="row"><span className="grow">Clean backups</span><b>{ov.service?.backups?.count || 0}</b></div>
                <div className="row"><span className="grow">Restores</span><b>{ov.service?.restores || 0}</b></div>
              </div>
              <div className="scroll-soft maint-list">
                {(ov.maintenance || []).map((m) => (
                  <div className="note mt8 maint-strong" key={m.asset}>
                    <b className="text-warn">MAINTENANCE {m.asset}</b>
                    <div className="small muted">{m.job} · {m.degraded ? "degraded diagnosis" : m.recoverable ? "recoverable · restore & re-add ready" : "diagnostics running"}</div>
                    {m.checks && (
                      <div className="small" style={{ marginTop: 4 }}>
                        {m.checks.map((c) => (
                          <span className="mono" key={c.check || c.label} style={{ color: ["clean", "quarantined"].includes(c.verdict || "running") ? "#16c784" : "#f0b429", marginRight: 10 }}>
                            {(c.check || c.label)?.replace(/_/g, " ")}:{c.verdict || "running"}
                          </span>
                        ))}
                      </div>
                    )}
                    {m.data_loss && <div className="small text-bad" style={{ marginTop: 4 }}>⚠ estimated data loss: {m.data_loss.severity || "suspected"} · {m.data_loss.estimated_records_at_risk ?? "?"} records · ~{(m.data_loss.exposure_window_seconds ?? 0) / 60} min exposure</div>}
                  </div>
                ))}
              </div>
            </Panel>
          </div>
          </div>

          {selInc && (
            <Panel title={`Threat card · ${selInc.actor}`} className="mt8">
              <div className="grid cols-2">
                <div className="rows">
                  <div className="row"><span className="grow">Incident</span><b>{selInc.id}</b></div>
                  <div className="row"><span className="grow">Status</span><Badge tone={selInc.trapped ? "bad" : selInc.status === "contained" ? "good" : selInc.deception ? "purple" : "warn"}>{selInc.trapped ? "TRAPPED" : selInc.status.toUpperCase()}</Badge></div>
                  <div className="row"><span className="grow">Origin</span><b>{selInc.origin}</b> <StatusDot status={selInc.stage} /></div>
                  <div className="row"><span className="grow">Stage</span><b>{selInc.stage.replace(/_/g, " ")}</b></div>
                  <div className="row"><span className="grow">Pivots</span><b>{selInc.pivot_count || 0}</b></div>
                  <div className="row"><span className="grow">Deception</span><b className={selInc.deception ? "text-warn" : ""}>{selInc.deception ? `active — ${selInc.decoy}` : "no"}</b></div>
                </div>
                {selInc.prediction ? (
                  <div className="rows">
                    <div className="row"><span className="grow">Predicted next target</span><b className="text-bad">{selInc.prediction.predicted_target || "—"}</b></div>
                    <div className="row"><span className="grow">Confidence</span><b>{Math.round(selInc.prediction.confidence * 100)}%</b></div>
                    <div className="row"><span className="grow">Risk</span><Badge tone={["low", "medium", "high", "critical"].includes(selInc.prediction.risk_level) ? selInc.prediction.risk_level === "critical" || selInc.prediction.risk_level === "high" ? "bad" : selInc.prediction.risk_level === "medium" ? "warn" : "good" : "accent"}>{selInc.prediction.risk_level.toUpperCase()}</Badge></div>
                    <div className="row"><span className="grow">Actions ahead</span><span className="mono small">{selInc.prediction.predicted_stages.join(" → ")}</span></div>
                  </div>
                ) : (
                  <p className="muted">No prediction recorded yet for this actor.</p>
                )}
              </div>
            </Panel>
          )}

          <section className="operator-evidence main-replica-lower" aria-label="Live telemetry, evidence and model operations">
            <div className="operator-section-head">
              <div>
                <span className="operator-kicker">Operator console</span>
                <h2>Live telemetry, evidence &amp; model operations</h2>
                <p>Inspect the event stream and its sources, review model forecasts, verify recorded evidence, and replay a trajectory.</p>
              </div>
              <Link href="/ai-intelligence" className="tiny primary">Open AI status →</Link>
            </div>
            <LivePanels live={live} scope="evidence" />
          </section>
        </>
      )}
      </main>

      <p className="muted small mt8">
        Demo range{health?.model_version ? ` · ${health.model_version}` : ""}. Network observations and simulated events are identified by source in the evidence stream.
      </p>

      {convSel && (
        <div className="modal-overlay" onClick={() => setConvSel(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>⚠ Convergence analysis · {convSel}</h3>
            {(() => {
              const g = convByTarget.get(convSel);
              if (!g) return <p className="muted">No convergence data.</p>;
              return (
                <div className="rows">
                  <div className="row"><span className="grow">Target</span><b>{g.target_name || g.target}</b></div>
                  <div className="row"><span className="grow">Trajectories converging</span><b>×{g.count}</b></div>
                  <div className="rows mt8">
                    {g.actors.map((a) => (
                      <div className="row" key={a.actor}>
                        <span className="dot" style={{ background: actorColor(a.actor), flex: "none" }} />
                        <span className="grow">{a.actor}</span>
                        <span className="mono small muted">{a.stage}</span>
                        <b>{a.confidence != null ? `${Math.round(a.confidence * 100)}%` : "—"}</b>
                        {a.risk_level && <span className="badge" style={{ background: convColor(a.risk_level), color: "#0b0f1a" }}>{a.risk_level}</span>}
                      </div>
                    ))}
                  </div>
                  <div className="row mt8"><span className="grow">Aggregate risk</span>
                    <Badge tone={["critical", "high"].includes(g.aggregate_risk_level || "") ? "bad" : "purple"}>{g.aggregate_risk_level?.toUpperCase()} · {Math.round(g.aggregate_risk_score || 0)}</Badge>
                  </div>
                  {g.correlation_id && <div className="note mt8"><div className="mono tiny">{g.correlation_id}</div><div className="small muted">correlation recorded in the event log · method: convergence/botnet</div></div>}
                  <div className="note mt8"><b>RECOMMENDED</b><div className="small">Steer all converging paths to the deception farm, isolate this asset, and preserve the business service via failover replicas.</div></div>
                </div>
              );
            })()}
            <div className="flex mt8"><button className="primary" onClick={() => setConvSel(null)}>close</button></div>
          </div>
        </div>
      )}

      {pinOpen && (
        <div className="modal-overlay" onClick={() => setPinOpen(false)}>
          <div ref={presenterDialog} className="modal demo-presenter-dialog" role="dialog" aria-modal="true" aria-labelledby="presenter-title" aria-describedby="presenter-description" tabIndex={-1} onClick={(e) => e.stopPropagation()}>
            <h3 id="presenter-title">Presenter access</h3>
            <p id="presenter-description" className="muted small">Viewing does not require a PIN. Presenter access enables range reset, deception, rollback and export controls.</p>
            {authorized ? (
              <div className="rows">
                <p className="muted small">Presenter PIN authorized. Range controls are in the top bar (Reset · Decoys · Rollback · Export).</p>
                <button className="primary" onClick={() => { setPinOpen(false); }}>close</button>
              </div>
            ) : (
              <form onSubmit={async (e) => {
                e.preventDefault();
                if (pinBusy || !pin.trim()) return;
                setPinBusy(true);
                setPinError("");
                try {
                  await demoApi.admin.health(pin);
                  setAuthorized(true);
                  try { window.localStorage.setItem("demo_presenter_pin", pin); } catch { /* ignore */ }
                } catch {
                  setPin("");
                  setPinError("Unable to authorize. Check the presenter PIN and demo service connection.");
                } finally {
                  setPinBusy(false);
                }
              }}>
                <label>Presenter PIN<input type="password" autoComplete="off" required value={pin} onChange={(e) => setPin(e.target.value)} aria-invalid={!!pinError} aria-describedby={pinError ? "presenter-error" : undefined} autoFocus /></label>
                {pinError && <p id="presenter-error" className="text-bad small" role="alert">{pinError}</p>}
                <div className="flex mt8"><button className="primary" type="submit" disabled={pinBusy || !pin.trim()}>{pinBusy ? "Signing in…" : "Sign in as presenter"}</button><button type="button" onClick={() => setPinOpen(false)}>Cancel</button></div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
