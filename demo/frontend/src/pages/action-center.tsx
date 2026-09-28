import Link from "next/link";
import { useRef } from "react";
import { Badge, Kpi, Panel, Spinner } from "@/components/ui";
import LivePanels from "@/components/LivePanels";
import { useLiveRange } from "@/lib/live";

export default function ActionCenter() {
  const paused = useRef(false);
  const replaying = useRef<number | null>(null);
  const live = useLiveRange({ paused, replaying });
  const { ov, health } = live;

  const dots = [
    { k: "db", ok: !!health?.db },
    { k: "model", ok: !!health?.model },
    { k: "sse", ok: !!health?.sse },
    { k: "sim", ok: !!health?.simulation },
  ];

  return (
    <div className="page command">
      <div className="topbar">
        <span className="brand">PREDICTIVE CYBER DEFENCE</span>
        <span className="sub-brand">LIVE NETWORK DIGITAL TWIN</span>
        <Badge tone="accent">flow-wm-v3.0.0</Badge>
        {(ov?.incidents || []).length > 1
          ? <Badge tone="bad">{ov!.incidents.length} CONCURRENT INCIDENTS</Badge>
          : ov?.incident?.id
            ? <Badge tone={ov.incident.status || ""}>{ov.incident.status}</Badge>
            : <Badge>NO INCIDENT</Badge>}
        <div className="push" />
        <span className="dt-stamp">● LIVE · ACTION CENTER</span>
        <Link href="/command-center" className="tiny primary">🔗 Live topology</Link>
      </div>

      {live.toasts.length > 0 && (
        <div className="toast-stack">
          {live.toasts.map((t) => (
            <div className={`toast toast-${t.tone}`} key={t.id}>
              <b className="blink-text">{t.title}</b>
              <span className="small">{t.body}</span>
              <button className="toast-close" onClick={() => { /* handled in hook */ }} aria-label="dismiss">×</button>
            </div>
          ))}
        </div>
      )}

      <div className="health-strip">
        {dots.map((d) => (
          <span className="h-item" key={d.k}>
            <span className={`health-dot ${d.ok ? "ok" : "bad"}`} /> {d.k}
          </span>
        ))}
        <span className="h-item"><span className="dt-pulse" /> digital-twin</span>
        <span className="watermark">● SIMULATED RANGE</span>
      </div>

      <div className="kpis">
        <Kpi label="Business service"
          value={ov ? <span title={`${ov?.service?.serving || 0}/${ov?.service?.replicas || 0} replicas serving · fallback ${ov?.service?.fallback || "—"}`}>{ov.service?.status?.toUpperCase()}</span> : "—"}
          accent={ov?.service?.status === "serving" ? "#16c784" : "#ff5c5c"} />
        <Kpi label="Active threats" value={ov ? ov.threats : "—"} accent="#ff5c5c" />
        <Kpi label="Contained" value={ov ? ov.contained : "—"} accent="#4c8dff" />
        <Kpi label="Deception" value={ov ? ov.decoys : "—"} accent="#b44cff" />
        <Kpi label="Threat actors" value={ov ? ov.attackers : "—"} accent="#f0b429" />
        <Kpi label="Trapped" value={ov ? ov.trapped : "—"} accent="#ff4d6d" />
        <Kpi label="Evidence events" value={ov ? ov.evidence_count : "—"} accent="#8b9cfc" />
        <Kpi label="Participants" value={ov ? ov.participants : "—"} />
      </div>

      <Panel title="Action Center · deep tools"
        right={<span className="mono small muted">scoreboard · evidence rail · timeline · playbook · heat map · trajectory replay · believes/knows · convergence</span>}>
        <div className="flex ac-links" style={{ gap: 8, flexWrap: "wrap" }}>
          <Link href="/command-center" className="tiny primary">🔗 Network topology (command center)</Link>
        </div>
      </Panel>

      {!ov ? (
        <Spinner label="Loading action center…" />
      ) : (
        <LivePanels live={live} scope="full" />
      )}

      <p className="muted small mt8">
        The Action Center is the deep-dive workspace — scoring, full timeline, playbook, replay and convergence.
        The command center keeps the live topology and the core story on the canvas.
      </p>
    </div>
  );
}