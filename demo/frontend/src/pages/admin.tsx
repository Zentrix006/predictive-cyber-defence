import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { demoApi } from "@/lib/api";
import { Panel, Badge, StatusDot } from "@/components/ui";

const PIN_KEY = "demo:admin:pin";

export default function Admin() {
  const [pin, setPin] = useState("");
  const [saved, setSaved] = useState(false);
  const [health, setHealth] = useState<any>(null);
  const [participants, setParticipants] = useState<any[]>([]);
  const [devices, setDevices] = useState<any[]>([]);
  const [offlineTotal, setOfflineTotal] = useState(0);
  const [showOffline, setShowOffline] = useState(false);
  const [deviceQuery, setDeviceQuery] = useState("");
  const [maint, setMaint] = useState<any[]>([]);
  const [force, setForce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string[]>([]);

  useEffect(() => {
    const p = window.sessionStorage.getItem(PIN_KEY);
    if (p) { setPin(p); setSaved(true); }
  }, []);

  const addLog = (m: string) => setLog((l) => [m, ...l].slice(0, 30));

  const call = async (fn: () => Promise<any>, label: string) => {
    setBusy(true);
    try {
      const r = await fn();
      addLog(`✓ ${label} → ${JSON.stringify(r).slice(0, 140)}`);
      const [nextHealth, nextParticipants] = await Promise.all([
        demoApi.admin.health(pin),
        demoApi.admin.participants(pin),
      ]);
      setHealth(nextHealth);
      setParticipants(nextParticipants);
      await refreshDevices(showOffline);
    } catch (e: any) {
      addLog(`✗ ${label} → ${e.message}`);
      // A changed/expired presenter PIN must return the operator to the unlock
      // prompt rather than leave every control apparently unresponsive.
      if (e?.status === 403) {
        window.sessionStorage.removeItem(PIN_KEY);
        setSaved(false);
      }
    }
    setBusy(false);
  };

  const refreshDevices = async (offline = showOffline) => {
    try {
      const r = await demoApi.admin.devices(pin, { include_offline: offline });
      setDevices(r.devices || []);
      setOfflineTotal(r.offline_total || 0);
    } catch { /* */ }
    try { setMaint(((await demoApi.overview()).maintenance || [])); } catch { /* */ }
  };

  const unlock = async () => {
    // A presenter credential must not survive a closed event-floor browser.
    window.sessionStorage.setItem(PIN_KEY, pin);
    setSaved(true);
    await call(() => demoApi.admin.health(pin), "health check");
    try { setParticipants(await demoApi.admin.participants(pin)); } catch { /* */ }
    await refreshDevices(false);
  };

  const refreshParticipants = async () => {
    try { setParticipants(await demoApi.admin.participants(pin)); } catch { /* */ }
  };

  useEffect(() => {
    if (saved && pin) {
      demoApi.admin.health(pin).then(setHealth).catch((error: any) => {
        if (error?.status === 403) {
          window.sessionStorage.removeItem(PIN_KEY);
          setSaved(false);
          setHealth(null);
        }
      });
      refreshParticipants();
      refreshDevices(showOffline);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [saved, pin, showOffline]);

  const filteredDevices = useMemo(() => {
    const q = deviceQuery.trim().toLowerCase();
    if (!q) return devices;
    return devices.filter((d) =>
      [d.asset_id, d.hostname, d.role, d.ip, d.status, d.page_endpoint]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(q));
  }, [devices, deviceQuery]);

  const maintenanceRoster = useMemo(() => {
    const byAsset = new Map<string, any>();
    maint.forEach((m) => {
      byAsset.set(m.asset, { ...m, source: "maintenance" });
    });
    devices.forEach((d) => {
      const isContained = d.status === "contained" || d.contained;
      const hasMaint = !!d.maintenance;
      if (!isContained && !hasMaint) return;
      const current = byAsset.get(d.asset_id) || { asset: d.asset_id, name: d.hostname, source: "device" };
      byAsset.set(d.asset_id, {
        ...current,
        asset: d.asset_id,
        name: d.hostname || current.name,
        job: d.maintenance?.job || (isContained ? "diagnosing" : current.job),
        recoverable: d.maintenance?.recoverable ?? current.recoverable ?? false,
        degraded: d.maintenance?.degraded ?? current.degraded ?? isContained,
        checks: d.maintenance?.checks || current.checks || [],
        data_loss: d.maintenance?.data_loss || current.data_loss,
        status: d.status,
        contained: isContained,
        source: current.source,
      });
    });
    return Array.from(byAsset.values()).sort((a, b) => Number(Boolean(b.recoverable)) - Number(Boolean(a.recoverable)));
  }, [maint, devices]);

  if (!saved) {
    return (
      <div className="page" style={{ maxWidth: 480 }}>
        <Panel title="Admin access">
          <div className="field">
            <label>Presenter PIN</label>
            <input type="password" value={pin} onChange={(e) => setPin(e.target.value)} placeholder="••••" />
          </div>
          <button className="primary mt8" disabled={!pin} onClick={unlock}>Unlock</button>
        </Panel>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="topbar">
        <span className="brand">RANGE ADMIN</span>
        {health && (
          <>
            <Badge tone="good">DB: {health.demo_db ? "ok" : "down"}</Badge>
            <Badge tone={health.world_model ? "accent" : "warn"}>world model: {health.world_model ? health.model_version || "ready" : "offline"}</Badge>
            <Badge>{health.feature_dim} features</Badge>
            <Badge>{health.incidents} incidents</Badge>
          </>
        )}
        <div className="push" />
        <Link className="tiny" href="/command-center">Command Center</Link>
        <Link className="tiny" href="/ai-intelligence">AI Intelligence</Link>
        <button onClick={() => { setSaved(false); window.sessionStorage.removeItem(PIN_KEY); }}>Lock</button>
      </div>

      <div className="grid cols-2">
        <Panel title="Controls">
          <div className="rows">
            <button className="primary" disabled={busy} onClick={() => call(() => demoApi.admin.start(pin), "range ready")}>
              Check range readiness
            </button>
            <button disabled={busy} onClick={() => call(() => demoApi.admin.reset(pin, false), "reset incident (keep layout)")}>
              Reset incident / decoys
            </button>
            <button className="danger" disabled={busy} onClick={() => call(() => demoApi.admin.clear(pin), "clear telemetry")}>
              Clear all telemetry
            </button>

            <div className="row" style={{ flexDirection: "column", alignItems: "stretch" }}>
              <label>Predictive deception</label>
              <button className="primary" disabled={busy} onClick={() => call(() => demoApi.admin.deception(pin), "stage decoy at predicted target")}>
                Stage decoy (post-prediction)
              </button>
              <span className="muted small">
                Only available once the world model has predicted a target — the decoy is a twin of that exact device.
              </span>
            </div>
          </div>

          <Panel title="Log" className="mt8">
            <div className="monitor" style={{ maxHeight: 180, overflow: "auto" }}>
              {log.length === 0 && <span className="muted">No actions yet.</span>}
              {log.map((l, i) => <div key={i}>{l}</div>)}
            </div>
          </Panel>
        </Panel>

        <Panel
          title="Registered devices"
          right={
            <span className="mono small muted">
              {filteredDevices.length} shown
              {offlineTotal > 0 ? ` · ${offlineTotal} offline hidden` : ""}
            </span>
          }
        >
          <div className="flex mb8" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <input
              className="grow"
              placeholder="search id / hostname / role…"
              value={deviceQuery}
              onChange={(e) => setDeviceQuery(e.target.value)}
            />
            <button className="small" onClick={() => refreshDevices(showOffline)}>refresh</button>
            <label className="row" style={{ margin: 0, padding: "4px 8px", gap: 6, alignItems: "center", width: "auto" }}>
              <input
                type="checkbox"
                checked={showOffline}
                onChange={(e) => setShowOffline(e.target.checked)}
                style={{ width: "auto" }}
              />
              <span className="small muted">include offline history</span>
            </label>
          </div>
          <p className="muted tiny mb8">
            Live physical joins only by default. Contained servers are surfaced with their maintenance state so restore-to-production never feels ambiguous.
          </p>
          <div className="rows device-list">
            {filteredDevices.map((d) => (
              <div className="row" key={d.asset_id}>
                <StatusDot status={d.status} />
                <span className="grow">
                  <b>{d.asset_id}</b> <span className="muted small">· {d.hostname} · {d.role}</span>
                  {d.ip ? <span className="muted small"> · {d.ip}</span> : null}
                </span>
                {d.status === "offline" ? <Badge>offline</Badge> : null}
                {d.contained ? <Badge tone="warn">contained</Badge> : null}
                {d.maintenance ? <Badge tone={d.maintenance.recoverable ? "good" : "accent"}>{d.maintenance.recoverable ? "restore ready" : "maintenance"}</Badge> : null}
                {d.status !== "offline" && d.status !== "contained" ? (
                  <Badge tone="good">{d.status}</Badge>
                ) : null}
                {(d.role === "server" && (d.contained || d.status === "maintenance" || d.maintenance)) && (
                  <button
                    className="tiny primary"
                    disabled={busy || (!force && !(d.maintenance?.recoverable))}
                    title={!force && !d.maintenance?.recoverable ? "Diagnostics still running. Use the maintenance panel or enable Force restore." : "Restore this server to production"}
                    onClick={() => call(() => demoApi.admin.restore(pin, d.asset_id, force), `move ${d.asset_id} to production`)}
                  >
                    move to production
                  </button>
                )}
                <span className="muted small">{d.page_endpoint || "—"}</span>
              </div>
            ))}
            {filteredDevices.length === 0 && (
              <p className="muted">
                {showOffline
                  ? "No matching devices in history."
                  : "No devices online right now. Guests appear here the moment they join and heartbeat — toggle “include offline history” to browse past registrations."}
              </p>
            )}
          </div>
        </Panel>

        <Panel
          title="Maintenance & restore (presenter)"
          right={<span className="mono small muted">{maintenanceRoster.length} tracked</span>}
          className="mt8"
        >
          <p className="muted tiny mb8">
            Containment automatically opens maintenance. Restore stays gated until diagnostics finish, unless you explicitly force it.
          </p>
          <div className="rows scroll-soft">
            {maintenanceRoster.map((m) => (
              <div className="row" key={m.asset} style={{ flexDirection: "column", alignItems: "stretch", gap: 8 }}>
                <div className="flex" style={{ gap: 8 }}>
                  <b>{m.asset}</b>
                  <Badge tone={m.recoverable ? "good" : m.job === "diagnosing" ? "accent" : "warn"}>
                    {m.recoverable ? "restore ready" : m.job || "diagnosing"}
                  </Badge>
                  {m.contained ? <Badge tone="warn">contained</Badge> : null}
                  <span className="muted small grow">{m.degraded ? "rebuild in progress" : (m.checks || []).length}/5 checks</span>
                </div>
                <div className="small muted">
                  {m.recoverable
                    ? "Diagnostics passed. The server can be moved back to production."
                    : "This server is still under maintenance. When checks finish, the restore button becomes available."}
                </div>
                <div className="flex" style={{ gap: 6, flexWrap: "wrap" }}>
                  <button className="tiny" disabled={busy} onClick={() => call(() => demoApi.admin.maintenanceDiagnose(pin, m.asset), `diagnose ${m.asset}`)}>re-run diagnostics</button>
                  <button className="tiny" disabled={busy} onClick={() => call(() => demoApi.admin.maintenanceRelease(pin, m.asset), `release ${m.asset}`)}>release (override)</button>
                  <button
                    className="tiny primary"
                    disabled={busy || (!force && !m.recoverable)}
                    title={!force && !m.recoverable ? "Wait for diagnostics to finish or enable Force restore." : "Restore this server to production"}
                    onClick={() => call(() => demoApi.admin.restore(pin, m.asset, force), `move ${m.asset} to production`)}>
                    move to production
                  </button>
                </div>
              </div>
            ))}
            {maintenanceRoster.length === 0 && <p className="muted">No servers are currently contained or in maintenance.</p>}
            <label className="row" style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
              <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} style={{ width: "auto" }} />
              <span className="small muted">Force restore (bypass diagnostics gate)</span>
            </label>
          </div>
        </Panel>
      </div>

      <div className="grid cols-2 mt8">
        <Panel title="Participants" right={<button className="small" onClick={refreshParticipants}>refresh</button>}>
          <div className="rows scroll-soft">
            {participants.map((p) => (
              <div className="row" key={p.participant_id}>
                <StatusDot status={p.status === "active" ? "active" : "offline"} />
                <span className="grow"><b>{p.participant_id}</b> <span className="muted small">· {p.role}</span></span>
                <span className="muted small">{p.browser} · {p.platform}</span>
              </div>
            ))}
            {participants.length === 0 && <p className="muted">No participants yet — share the QR.</p>}
          </div>
        </Panel>

        <Panel title="Demo architecture note">
          <p className="muted small" style={{ lineHeight: 1.8 }}>
            The range starts <b>empty</b>. Devices register on join and heartbeat to stay online; the attacker
            picks from the devices actually connected; THREAT ZONE / CONTAINED / HONEYNET and decoy twins are
            created dynamically as consequences of the world model&apos;s predictions.
          </p>
        </Panel>
      </div>
    </div>
  );
}
