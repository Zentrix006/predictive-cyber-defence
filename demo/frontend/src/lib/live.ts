import { useCallback, useEffect, useRef, useState } from "react";
import {
  demoApi,
  type Overview,
  type Topology,
  type DemoTimelineItem,
  type Health,
  type ParticipantBoard,
} from "@/lib/api";
import { useSSE } from "@/lib/sse";

export type Toast = { id: string; tone: string; title: string; body: string };

export type LiveRange = {
  ov: Overview | null;
  topo: Topology | null;
  timeline: DemoTimelineItem[];
  board: ParticipantBoard;
  health: Health | null;
  toasts: Toast[];
  pushToast: (t: Omit<Toast, "id">) => void;
  dismissToast: (id: string) => void;
  lastUpdatedAt: number | null;
  error: string | null;
  refreshing: boolean;
  refresh: () => Promise<void>;
};

type Options = {
  paused?: React.MutableRefObject<boolean>;
  replaying?: React.MutableRefObject<number | null>;
  intervalMs?: number;
  toastAlerts?: boolean;
};

/**
 * Shared live-range data loop used by the command center and the Action
 * Center page: overview + topology + timeline + participant board poll every
 * few seconds, SSE wakes it instantly on a new event, health polls slower,
 * and toast alerts fire exactly once per state change (intrusion, forecast,
 * containment, deception, trap, maintenance, convergence).
 */
export function useLiveRange(opts: Options = {}): LiveRange {
  const pausedRef = opts.paused;
  const replayRef = opts.replaying;
  const intervalMs = opts.intervalMs ?? 3000;
  const toastAlerts = opts.toastAlerts ?? true;

  const [ov, setOv] = useState<Overview | null>(null);
  const [topo, setTopo] = useState<Topology | null>(null);
  const [timeline, setTimeline] = useState<DemoTimelineItem[]>([]);
  const [board, setBoard] = useState<ParticipantBoard>({ participants: [], live: 0, max_score: 100 });
  const [health, setHealth] = useState<Health | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const mounted = useRef(true);
  const inFlight = useRef(false);
  const toastTimers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const live = useSSE<any>("stream");
  const last = useRef<string>("");
  const prev = useRef({ risk: "", decoys: 0, contained: 0, trapped: 0, convergence: 0, maintCount: 0, incidents: [] as string[] });

  const dismissToast = useCallback((id: string) => {
    clearTimeout(toastTimers.current.get(id));
    toastTimers.current.delete(id);
    if (mounted.current) setToasts((items) => items.filter((item) => item.id !== id));
  }, []);

  const pushToast = useCallback((t: Omit<Toast, "id">) => {
    if (!mounted.current) return;
    const id = Math.random().toString(36).slice(2);
    setToasts((prevT) => [...prevT.slice(-2), { ...t, id }]);
    toastTimers.current.set(id, setTimeout(() => dismissToast(id), 7000));
  }, [dismissToast]);

  const refresh = useCallback(async () => {
    if (pausedRef?.current || replayRef?.current != null || inFlight.current) return;
    inFlight.current = true;
    setRefreshing(true);
    try {
      const [o, t, tl, sb] = await Promise.all([
        demoApi.overview(),
        demoApi.topology(),
        demoApi.timeline(80),
        demoApi.participants(),
      ]);
      if (!mounted.current || pausedRef?.current || replayRef?.current != null) return;
      setOv(o);
      setTopo(t);
      setTimeline(tl.length ? tl : (prevT) => prevT);
      setBoard(sb);
      setLastUpdatedAt(Date.now());
      setError(null);
    } catch {
      if (mounted.current) setError("Telemetry is unavailable. Retrying automatically; any displayed values are the last received snapshot.");
    } finally {
      inFlight.current = false;
      if (mounted.current) setRefreshing(false);
    }
  }, [pausedRef, replayRef]);

  useEffect(() => {
    mounted.current = true;
    refresh();
    const t = setInterval(refresh, intervalMs);
    const refreshHealth = async () => {
      try {
        const nextHealth = await demoApi.health();
        if (mounted.current) setHealth(nextHealth);
      } catch {
        if (mounted.current) setHealth(null);
      }
    };
    refreshHealth();
    const h = setInterval(refreshHealth, 8000);
    return () => {
      mounted.current = false;
      clearInterval(t);
      clearInterval(h);
      toastTimers.current.forEach(clearTimeout);
      toastTimers.current.clear();
    };
  }, [refresh, intervalMs]);

  useEffect(() => {
    if (live.length && live[0].event_id !== last.current) {
      last.current = live[0].event_id;
      if (!pausedRef?.current && replayRef?.current == null) refresh();
    }
  }, [live, refresh, pausedRef, replayRef]);

  useEffect(() => {
    if (!ov || !toastAlerts) return;
    const b = prev.current;
    const incs = ov.incidents || [];
    const freshIncs = incs.filter((i) => !b.incidents.includes(i.id));
    for (const inc of freshIncs) {
      pushToast({ tone: "crit", title: "INTRUSION DETECTED", body: `${inc?.actor || "actor"} targeting ${inc?.origin || "a node"} — stage ${inc?.stage || "recon"}.` });
    }
    const risk = ov.prediction?.risk_level || "";
    if (risk && risk !== b.risk && ["high", "critical"].includes(risk)) {
      pushToast({ tone: "warn", title: `${risk.toUpperCase()} RISK FORECAST`, body: `World model predicts next target: ${ov.prediction?.predicted_target || "?"} (${Math.round((ov.prediction?.confidence || 0) * 100)}% confidence).` });
    }
    if ((ov.contained || 0) > b.contained) {
      pushToast({ tone: "info", title: "CONTAINMENT ACTIVE", body: `${ov.contained - b.contained} origin(s) isolated and drawn into the THREAT ZONE.` });
    }
    if ((ov.decoys || 0) > b.decoys) {
      pushToast({ tone: "accent", title: "DECEPTION STAGED", body: `${ov.decoys - b.decoys} decoy/segment bait node(s) minted — attackers are being steered into the honeynet.` });
    }
    if ((ov.trapped || 0) > b.trapped) {
      pushToast({ tone: "crit", title: "ATTACKER TRAPPED", body: "Bait decoy engaged — attacker is encased in the honeypot and fully monitored." });
    }
    if ((ov.maintenance || []).length > b.maintCount) {
      pushToast({ tone: "warn", title: "SERVER IN MAINTENANCE", body: `${ov.maintenance[0].asset} contained → diagnostics + data-loss audit running (~6s), then restore & re-add.` });
    }
    if ((ov.convergence || []).length > b.convergence) {
      pushToast({ tone: "crit", title: "MULTI-ACTOR CONVERGENCE", body: `${ov.convergence.map((c) => `${c.target} under ${c.actors.length} trajectories · ${c.risk_level.toUpperCase()} fused`).join("; ")}` });
    }
    prev.current = {
      risk,
      decoys: ov.decoys || 0,
      contained: ov.contained || 0,
      trapped: ov.trapped || 0,
      convergence: (ov.convergence || []).length,
      incidents: incs.map((i) => i.id),
      maintCount: (ov.maintenance || []).length,
    };
  }, [ov, pushToast, toastAlerts]);

  return { ov, topo, timeline, board, health, toasts, pushToast, dismissToast, lastUpdatedAt, error, refreshing, refresh };
}
