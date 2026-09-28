import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/router";
import { demoApi, type AssetState } from "@/lib/api";
import { getSession } from "@/lib/session";
import { Panel, StatusDot, Badge, useNow, useMounted } from "@/components/ui";

const ZONE_LABEL: Record<string, string> = {
  lan: "protected LAN",
  threat: "THREAT ZONE",
  honeynet: "honeynet (decoy)",
};

const ATTACKING = new Set(["suspicious", "under_attack", "compromised"]);

export default function DevicePage() {
  const router = useRouter();
  const assetId = String(router.query.assetId || "");
  const session = getSession();
  const mounted = useMounted();
  const now = useNow(2000);
  const [state, setState] = useState<AssetState | null>(null);
  const [online, setOnline] = useState(false);
  const [err, setErr] = useState("");

  const beat = useCallback(async () => {
    if (!assetId) return;
    try {
      const r = await demoApi.heartbeat({
        asset_id: assetId,
        hostname: session?.hostname,
        device_type: session?.device_type,
        page_endpoint: `/device/${assetId}`,
      });
      setOnline(r.online !== false);
      setErr("");
      const s = await demoApi.assetState(assetId);
      setState(s);
    } catch (e: any) {
      setOnline(false);
      setErr(e.message || "Range unreachable");
    }
  }, [assetId, session]);

  useEffect(() => {
    if (!assetId) return;
    beat();
    const t = setInterval(beat, 4000);
    return () => clearInterval(t);
  }, [assetId, beat]);

  const status = state?.status || "offline";
  const zone = state?.zone || "lan";
  const isServer = state?.role === "server";
  const alarmed = ATTACKING.has(status);
  const contained = !!state?.contained || status === "contained";
  const underMaintenance = !!state?.maintenance;

  return (
    <div className={`page ${isServer ? "device-white" : ""} ${alarmed ? "alarmed" : contained ? "contained-page" : ""}`} style={{ maxWidth: 720 }}>
      <div className="topbar">
        <span className="brand">DEVICE &middot; {assetId}</span>
        <StatusDot status={status} />
        {online ? <Badge tone="good">ONLINE</Badge> : <Badge tone="bad">OFFLINE</Badge>}
        {state?.registered ? <Badge tone="accent">REGISTERED</Badge> : <Badge tone="warn">UNREGISTERED</Badge>}
        <div className="push" />
        {mounted ? <span className="muted small">{new Date(now).toLocaleTimeString()}</span> : <span className="muted small" />}
      </div>

      {alarmed && (
        <div className="attack-alert">
          <b className="blink-text">⚠ LIVE ATTACK SIMULATED &mdash;</b>{" "}
          <span>this node is the target of a simulated intrusion at stage <b>{state?.stage || status.replace(/_/g, " ")}</b>. Defender response is in progress &mdash; do not panic, this is the cyber-range.</span>
        </div>
      )}
      {contained && !alarmed && (
        <div className="contained-alert">
          <b>🛡 CONTAINED &mdash;</b>{" "}
          <span>the defensive response isolated this node and drew it into the THREAT ZONE.</span>
        </div>
      )}

      {state?.trapped && (
        <div className="contained-alert" style={{ borderColor: "#b44cff", background: "rgba(180,76,255,0.12)", color: "#ecd9ff" }}>
          <b>◉ ENCASED IN HONEYNET &mdash;</b>{" "}
          <span>the attacker lands here but every route onward is a honeypot; this console is fully monitored and leads nowhere.</span>
        </div>
      )}

      {state?.maintenance && (
        <div className="contained-alert maint-strong" style={{ borderColor: "#f0b429", background: "rgba(240,180,41,0.12)", color: "#ffe9b0" }}>
          <b className="blink-text">⛃ MAINTENANCE &mdash;</b>{" "}
          <span>this replica is being rebuilt from clean state. Diagnostics {state.maintenance.recoverable ? "passed — restore & re-add is ready" : (state.maintenance.checks?.length || 0) >= 5 ? "finished — recoverable" : "in progress…"}.</span>
          <div className="small mt8 mono" style={{ color: "#ffda7a" }}>
            containment remains visible until the admin restores this node to production.
          </div>
          {state.maintenance.checks && state.maintenance.checks.length > 0 && (
            <div className="small mt8" style={{ fontFamily: "var(--mono)" }}>
              {state.maintenance.checks.map((ch) => (
                <span key={ch.check || ch.label} style={{ color: ["clean", "quarantined"].includes(ch.verdict || "running") ? "#16c784" : "#f0b429", marginRight: 12 }}>
                  {(ch.check || ch.label)?.replace(/_/g, " ")}:{ch.verdict || "running"}
                </span>
              ))}
            </div>
          )}
          {state.maintenance.data_loss && (
            <div className="small" style={{ color: "#ff8c42", marginTop: 6 }}>
              ⚠ estimated data loss: {state.maintenance.data_loss.severity || "suspected"} · {state.maintenance.data_loss.estimated_records_at_risk ?? "?"} records · ~{(state.maintenance.data_loss.exposure_window_seconds ?? 0) / 60} min exposure
            </div>
          )}
        </div>
      )}

      {typeof state?.service === "object" && state.service && (
        <div className={`alert service-alert ${state.service.serving ? "" : "service-alert-down"}`}>
          {state.service.serving ? (
            <b>SERVING &mdash;</b>
          ) : (
            <b className="blink-text">FAILED OVER &mdash;</b>
          )}{" "}
          <span>
            shared domain <b className="mono">{state.service.domain}</b> is{" "}
            {state.service.serving ? "still being served from this replica" : "no longer served from here (failover)"}
            {state.service.fallback ? ` · fallback: ${state.service.fallback}` : ""}.{" "}
            Zero-downtime continuity — the domain stays up even while servers are contained.
          </span>
        </div>
      )}

      <Panel title="Node status" className={alarmed ? "panel-alarmed" : ""}>
        <div className="row">
          <StatusDot status={status} />
          <div className="grow">
            <b>{state?.hostname || assetId}</b>
            <div className="muted small">{state?.asset_type || "device"} · {state?.role || "other"}</div>
          </div>
          <b className="blink-text" style={{ textTransform: "uppercase", fontSize: 12, color: statusColorHex(status) }}>{status}</b>
        </div>
        <div className="row mt8">
          <span className="grow muted small">Zone</span>
          <b className="small">{ZONE_LABEL[zone] || zone}</b>
        </div>
        {state?.predicted_target && (
          <div className="note mt8 warn">
            <b className="text-bad">The world model predicts an attack is landing here next.</b>
            {" "}<span className="muted">Simulated and controlled — this is the prediction the defender will steer away from you.</span>
          </div>
        )}
        {contained && !alarmed && (
          <div className="note mt8 warn">
            <b className="text-bad">CONTAINED —</b>{" "}
            <span>this device remains isolated while the rebuild/restore path runs. The node is still part of the containment workflow.</span>
          </div>
        )}
        {underMaintenance && (
          <div className="note mt8">
            <b className="text-warn">MAINTENANCE MODE —</b>{" "}
            <span>contained server is being restored from the clean snapshot and will re-enter production once diagnostics pass.</span>
          </div>
        )}
        {state?.stage && (
          <div className="note mt8">
            <b className="text-warn">This node is the attack origin and is at stage:</b> {state.stage}
          </div>
        )}
        {contained && state?.maintenance && (
          <div className="note mt8 warn">
            <b className="text-bad">CONTAINED + MAINTENANCE —</b>{" "}
            <span>the server is still treated as contained while the repair workflow is running.</span>
          </div>
        )}
        {status === "compromised" && (
          <div className="note mt8 warn">
            <b className="text-bad">COMPROMISED —</b>
            {" "}<span>the attacker owns this node; it has been drawn into the THREAT ZONE in the topology.</span>
          </div>
        )}
        {err && <p className="text-bad small mt8">{err}</p>}
      </Panel>

      <Panel title="Details" className="mt8">
        <div className="rows">
          <div className="row"><span className="grow muted">Role</span><b>{state?.role || "—"}</b></div>
          <div className="row"><span className="grow muted">Device type</span><b>{state?.asset_type || "—"}</b></div>
          <div className="row"><span className="grow muted">IP</span><span className="mono">{state?.ip || "—"}</span></div>
          <div className="row"><span className="grow muted">Service</span><b>{typeof state?.service === "string" ? state.service : typeof state?.service === "object" && state.service ? state.service.domain : "—"}</b></div>
          <div className="row"><span className="grow muted">Page endpoint</span><span className="mono small">{state?.page_endpoint || "/device/" + assetId}</span></div>
          <div className="row"><span className="grow muted">Registered</span><b>{state?.registered ? "yes" : "no"}</b></div>
          <div className="row"><span className="grow muted">Last seen</span><span className="mono">{mounted ? (state?.last_seen ? new Date(state.last_seen.replace(" ", "T") + (state.last_seen.includes("+") ? "" : "Z")).toLocaleTimeString() : "never") : "—"}</span></div>
        </div>
      </Panel>

      <Panel title="How discovery works" className="mt8">
        <p className={`small ${isServer ? "text-dark" : "muted"}`}>
          This page is the device agent. It registers your identity and heartbeats every 4s;
          while it stays open, this node is <b>connected</b> and visible to the attacker terminal. Close it and the
          node goes gray/offline — no fake devices are ever injected.
        </p>
        {underMaintenance && (
          <p className="small mt8 text-warn">
            Because this is a server replica, maintenance keeps the containment context visible until the restore button is used in Admin.
          </p>
        )}
      </Panel>
    </div>
  );
}

function statusColorHex(status: string) {
  return (
    {
      healthy: "#16c784",
      registering: "#f0b429",
      suspicious: "#f0b429",
      under_attack: "#ff5c5c",
      compromised: "#ff2d55",
      contained: "#4c8dff",
      deception: "#b44cff",
      offline: "#5b6681",
    } as Record<string, string>
  )[status] || "#5b6681";
}
