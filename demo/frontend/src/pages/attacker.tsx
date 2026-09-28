import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { demoApi, type AssetInfo } from "@/lib/api";
import { getSession, clearSession } from "@/lib/session";
import { Panel, Badge, StatusDot, Spinner, useNow, useMounted } from "@/components/ui";
import { Outage404 } from "@/components/SiteSkin";

type Incident = {
  incident_id: string;
  status: string;
  stage: string;
  level: number;
  origin: string;
  origin_name?: string;
  pivot_count: number;
  deception_active?: boolean;
  decoy?: string | null;
  trapped?: boolean;
  monitoring?: { decoy?: string; decoy_name?: string; since?: string; type?: string };
  predicted_target?: string;
};

type State = {
  state: string;
  incident: Incident | null;
};

type HopInfo = {
  origin: string;
  pivot_options: AssetInfo[];
  hint: string;
};

function clientIntel() {
  if (typeof navigator === "undefined") return {};
  return {
    browser: navigator.userAgent.split(" ").slice(-2).join(" ").slice(0, 40),
    platform: navigator.platform,
    language: (navigator.language || "") as string,
  };
}

export default function Attacker() {
  const session = getSession();
  const mounted = useMounted();
  const now = useNow(3000);
  const [st, setSt] = useState<State>({ state: "loading", incident: null });
  const [targets, setTargets] = useState<AssetInfo[]>([]);
  const [target, setTarget] = useState("");
  const [question, setQuestion] = useState("");
  const [questionOptions, setQuestionOptions] = useState<{ id: string; value: string; label: string }[]>([]);
  const [answer, setAnswer] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [hops, setHops] = useState<HopInfo | null>(null);
  const [decoyed, setDecoyed] = useState<null | { host?: string; msg?: string }>(null);
  const [tunnelLog, setTunnelLog] = useState<{ ts: string; label: string }[]>([]);
  const [lastPrediction, setLastPrediction] = useState<string>("");

  const refresh = useCallback(async () => {
    if (!session) return;
    try {
      const s = await demoApi.attackerState(session.token);
      setSt(s);
      if (s.challenge?.question) {
        setQuestion((q) => q || s.challenge.question);
        if (s.challenge?.options?.length) setQuestionOptions(s.challenge.options);
      }
      if (s.state === "idle") {
        const opts = await demoApi.attackerOptions(session.token);
        setTargets(opts.targets || []);
        setHops(null);
      } else if (s.state === "active" || s.state === "trapped") {
        const level = s.incident?.level ?? 0;
        const canSweep = level >= 3 || !!s.incident?.deception_active || s.state === "trapped";
        if (canSweep) {
          try {
            setHops(await demoApi.attackerPivotOptions(session.token));
          } catch {
            setHops(null);
          }
        } else {
          setHops(null);
        }
      }
    } catch {
      setSt((prev) => (prev.state === "loading" ? { state: "idle", incident: null } : prev));
    }
  }, [session]);

  useEffect(() => {
    if (!session || session.role !== "attacker") return;
    refresh();
    const t = setInterval(refresh, 2500);
    return () => clearInterval(t);
  }, [session, refresh]);

  if (!mounted || !session) {
    return (
      <div className="page" style={{ maxWidth: 680 }}>
        <Panel title="Attacker console">
          <p className="muted">{!mounted ? "Restoring session…" : "You need to join as an attacker first."}</p>
          {mounted && <Link className="btn" href="/join">Join the range</Link>}
        </Panel>
      </div>
    );
  }
  if (session.role !== "attacker") {
    return (
      <div className="page">
        <Panel title="Wrong role">
          <p>You joined as <b>{session.role}</b>. Only attackers can open an engagement.</p>
          <Link className="btn" href="/join">Switch role</Link>
        </Panel>
      </div>
    );
  }

  const startAttack = async () => {
    if (!target) {
      setErr("Select a foothold first.");
      return;
    }
    setBusy(true);
    setErr(""); setMsg(""); setDecoyed(null);
    try {
      const r = await demoApi.attackerStart(session.token, target);
      setQuestion(r.challenge?.question || "");
      setQuestionOptions(r.challenge?.options || []);
      setAnswer("");
      setMsg(`Engagement ${r.incident_id} open against ${r.target?.name || target}. Complete the handshake.`);
      await refresh();
    } catch (e: any) {
      setErr(e.message || "Could not open engagement");
      setMsg("");
    }
    setBusy(false);
  };

  const submitAnswer = async () => {
    if (!st.incident) return;
    setBusy(true); setErr(""); setMsg("");
    try {
      const r = await demoApi.attackerAnswer(session.token, st.incident.incident_id, answer);
      setAnswer("");
      setQuestion("");
      setQuestionOptions([]);
      if (r.trapped) {
        setMsg(r.message || "Captured inside the service console — everything is recorded.");
      } else {
        const pred = r.prediction?.predicted_target;
        const decoyOn = r.deception?.activated;
        setLastPrediction(pred || "");
        setMsg(
          decoyOn
            ? `Stage advanced to ${r.stage} (L${r.level}). Deception staged — sweep the segment and hop.`
            : `Stage advanced to ${r.stage} (L${r.level}).${pred ? ` Model watches ${pred}.` : ""}`,
        );
      }
      await refresh();
    } catch (e: any) {
      setErr(e.message || "Handshake rejected");
    }
    setBusy(false);
  };

  const doHop = async (targetId: string) => {
    if (!st.incident) return;
    setBusy(true); setErr(""); setMsg("");
    try {
      const tgt = hops?.pivot_options.find((t) => t.id === targetId);
      const r = await demoApi.attackerPivot(session.token, st.incident.incident_id, targetId);
      if (r.deceived) {
        setDecoyed({ host: r.hostname || targetId, msg: r.message });
        setQuestion("");
        setQuestionOptions([]);
        await refresh();
        setBusy(false);
        return;
      }
      setDecoyed(null);
      if (r.trapped) {
        setMsg(r.message || `Hop into ${tgt?.name || targetId} — you are inside a monitored honeypot.`);
        setQuestion("");
        setQuestionOptions([]);
      } else {
        setMsg(`Hop established → ${tgt ? `${tgt.name} (${tgt.role})` : targetId}. Fresh handshake required.`);
        setQuestion(r.challenge?.question || "");
        setQuestionOptions(r.challenge?.options || []);
        setAnswer("");
      }
      await refresh();
    } catch (e: any) {
      setErr(e.message || "Hop failed");
    }
    setBusy(false);
  };

  const intel = clientIntel();
  const foothold = st.incident?.origin_name || st.incident?.origin || "—";
  const trapped = st.state === "trapped" || !!st.incident?.trapped;
  const active = (st.state === "active" || st.state === "trapped") && !!st.incident;

  const tunnel = async (label: string) => {
    if (!session || !st.incident) return;
    try {
      await demoApi.decoyInteract(session.token, st.incident.incident_id, [{ question: "decoy session", answer: label }], {
        platform: intel.platform || null,
        language: intel.language || null,
        user_agent: typeof navigator !== "undefined" ? navigator.userAgent : null,
        tunnel: label,
      });
      setTunnelLog((l) => [{ ts: new Date().toISOString().slice(11, 19), label }, ...l].slice(0, 10));
    } catch (e: any) {
      setErr(e.message || "Decoy action failed");
    }
  };

  return (
    <div className="page">
      <div className="topbar">
        <span className="brand">ATTACKER CONSOLE</span>
        <Badge tone="bad">A-{session.participant_id.replace(/^A-/, "")}</Badge>
        {trapped && <Badge tone="bad">TRAPPED</Badge>}
        {st.incident?.deception_active && !trapped && <Badge tone="purple">DECEPTION LIVE</Badge>}
        <div className="push" />
        <Link className="btn small" href="/command-center">Command Center</Link>
        <button onClick={() => { clearSession(); window.location.reload(); }}>Disconnect</button>
      </div>

      {st.state === "loading" && <Spinner label="Contacting network…" />}

      {st.state === "idle" && (
        <div className="grid cols-2">
          <Panel title="Workspace">
            <p className="muted">No engagement in progress. Pick a foothold on the perimeter, then complete the handshake to advance the kill chain.</p>
            {msg && <p className="mono mt8">{msg}</p>}
            {err && <p className="text-bad small mt8">{err}</p>}
          </Panel>
          <Panel title="Perimeter — discovered assets">
            <p className="muted small mb8">Select a foothold to open an engagement against it.</p>
            <div className="rows scroll-soft perimeter-list">
              {targets.map((t) => (
                <label key={t.id} className="row">
                  <input type="radio" name="target" value={t.id} checked={target === t.id} onChange={() => setTarget(t.id)} style={{ width: "auto" }} />
                  <StatusDot status={t.status} />
                  <span className="grow"><b>{t.id}</b> <span className="muted small">· {t.name}</span></span>
                  <span className="muted small">{t.role}{t.ip ? ` · ${t.ip}` : ""}</span>
                </label>
              ))}
            </div>
            {targets.length === 0 && <Spinner label="Waiting for assets to come online on the perimeter…" />}
            <div className="mt8 flex">
              <button className="primary" disabled={busy || !target} onClick={startAttack}>
                Open engagement
              </button>
              <span className="muted small">{target || "no target selected"}</span>
            </div>
          </Panel>
        </div>
      )}

      {trapped && st.incident && (
        <>
          <div className="kpis kpis-compact">
            <div className="kpi"><span className="kpi-label">Engagement</span><span className="kpi-value" style={{ fontSize: 15 }}>{st.incident.incident_id}</span></div>
            <div className="kpi"><span className="kpi-label">Status</span><span className="kpi-value" style={{ fontSize: 15, color: "#ff4d6d" }}>CAPTURED</span></div>
            <div className="kpi"><span className="kpi-label">Decoy</span><span className="kpi-value" style={{ fontSize: 15 }}>{st.incident.monitoring?.decoy_name || st.incident.monitoring?.decoy || st.incident.decoy || "?"}</span></div>
            <div className="kpi"><span className="kpi-label">Since</span><span className="kpi-value" style={{ fontSize: 15 }}>{st.incident.monitoring?.since ? new Date(st.incident.monitoring.since.replace(" ", "T")).toLocaleTimeString() : "—"}</span></div>
          </div>
          <div className="contained-alert mt8" style={{ borderColor: "#b44cff", background: "rgba(180,76,255,0.10)", color: "#ecd9ff" }}>
            <b className="blink-text">◉ HONEYPOT — YOU ARE TRAPPED</b>
            <p className="small" style={{ margin: "6px 0 0" }}>
              Every route from this console is a decoy. Actions are recorded for attribution. There is no path back to the real network.
            </p>
          </div>
          <div className="grid cols-2 mt8">
            <Panel title="Decoy session — keep working">
              <p className="muted small mb8">
                The honeypot answers everything. Probe it — SQL, exports, creds — so the defender&apos;s ledger fills up.
              </p>
              <div className="flex" style={{ gap: 8, flexWrap: "wrap" }}>
                <button className="btn small" disabled={busy} onClick={() => tunnel("read:sql accounts TABLE")}>Run SQL</button>
                <button className="btn small" disabled={busy} onClick={() => tunnel("grab:merchant_export.csv")}>Export CSV</button>
                <button className="btn small" disabled={busy} onClick={() => tunnel("write:credential dump /etc/passwd")}>Dump creds</button>
                <button className="btn small" disabled={busy} onClick={() => tunnel("pivot:ssh replica 22")}>SSH replica</button>
                <button className="btn small" disabled={busy} onClick={() => tunnel("download:backup creds bundle")}>Pull backup</button>
              </div>
              <Link className="btn primary mt8" style={{ display: "block" }} href="/target">
                Continue hacking →
              </Link>
              {err && <p className="text-bad small mt8">{err}</p>}
            </Panel>
            <Panel title="Ledger — recorded actions">
              {tunnelLog.length === 0 ? (
                <p className="muted small">No decoy actions yet. Use the buttons or continue hacking through the portal.</p>
              ) : (
                <div className="rail ledger-scroll">
                  {tunnelLog.map((e, i) => (
                    <div className="rail-item" key={i}>
                      <span className="mono tiny muted" style={{ flex: "none" }}>{e.ts}</span>
                      <div className="grow small" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.label}</div>
                    </div>
                  ))}
                </div>
              )}
              {hops && hops.pivot_options.length > 0 && (
                <div className="mt8">
                  <p className="muted small mb8">{hops.hint}</p>
                  <div className="rows sweep-scroll" style={{ maxHeight: 180 }}>
                    {hops.pivot_options.map((t) => (
                      <div key={t.id} className="row">
                        <StatusDot status={t.status} />
                        <span className="grow"><b>{t.name}</b> <span className="muted small">· {t.id}</span></span>
                        <button className="btn small" disabled={busy} onClick={() => doHop(t.id)}>Hop →</button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Panel>
          </div>
        </>
      )}

      {active && !trapped && st.incident && (
        <>
          <div className="kpis kpis-compact">
            <div className="kpi"><span className="kpi-label">Engagement</span><span className="kpi-value" style={{ fontSize: 15 }}>{st.incident.incident_id}</span></div>
            <div className="kpi"><span className="kpi-label">Stage</span><span className="kpi-value" style={{ fontSize: 15 }}>{st.incident.stage}</span></div>
            <div className="kpi"><span className="kpi-label">Depth</span><span className="kpi-value" style={{ fontSize: 15 }}>{st.incident.level}/6</span></div>
            <div className="kpi"><span className="kpi-label">Foothold</span><span className="kpi-value" style={{ fontSize: 15 }}>{foothold}</span></div>
            <div className="kpi"><span className="kpi-label">Hops</span><span className="kpi-value" style={{ fontSize: 15 }}>{st.incident.pivot_count}</span></div>
          </div>

          <div className="grid cols-2 mt8">
            <Panel title="Session console">
              <p className="mono">{msg || "Engagement active. Complete the handshake or hop when the sweep opens."}</p>
              {lastPrediction && <p className="muted small mt8">Predicted interest: <b>{lastPrediction}</b></p>}
              {decoyed && (
                <div className="mt8">
                  <Outage404 hostname={decoyed.host} />
                  <p className="small muted mt8">{decoyed.msg}</p>
                  <p className="muted small mt8">That host is isolated — only segment replicas answer. Hop to a decoy/replica instead.</p>
                  <button className="btn mt8" onClick={() => setDecoyed(null)}>Dismiss</button>
                </div>
              )}
              {question && (
                <div className="field mt8">
                  <label>Step handshake · {question}</label>
                  {questionOptions.length > 1 ? (
                    <div className="rows">
                      {questionOptions.map((opt) => {
                        const selected = answer === opt.id;
                        return (
                          <button
                            key={opt.id}
                            className={`row handshake-opt${selected ? " selected" : ""}`}
                            onClick={() => { setAnswer(opt.id); }}
                          >
                            <StatusDot status={selected ? "active" : ""} />
                            <span className="grow small">{opt.label}</span>
                            {selected && <b className="text-good small">✓</b>}
                          </button>
                        );
                      })}
                    </div>
                  ) : (
                    <input
                      value={answer}
                      onChange={(e) => setAnswer(e.target.value)}
                      placeholder="Technique / answer token"
                      onKeyDown={(e) => { if (e.key === "Enter" && answer && !busy) submitAnswer(); }}
                    />
                  )}
                  <button className="primary" disabled={busy || !answer} onClick={submitAnswer}>
                    Execute
                  </button>
                  <p className="muted tiny mt8">Pick a technique from the segment map. The strongest move advances the kill chain.</p>
                </div>
              )}
              {!question && (st.incident.level ?? 0) >= 3 && (
                <p className="muted small mt8">Handshake complete for this foothold. Use the network sweep to hop — baits and replicas are waiting.</p>
              )}
              {err && <p className="text-bad small mt8">{err}</p>}
              {(st.incident.deception_active || (st.incident.level ?? 0) >= 4) && (
                <Link className="btn primary mt8" style={{ display: "block" }} href="/target">
                  Open service console →
                </Link>
              )}
            </Panel>

            <Panel title="Network sweep — reachable hosts">
              {hops && hops.pivot_options.length > 0 ? (
                <>
                  <p className="muted small mb8">{hops.hint}</p>
                  <div className="rows sweep-scroll">
                    {hops.pivot_options.map((t) => (
                      <div key={t.id} className="row">
                        <StatusDot status={t.status} />
                        <span className="grow">
                          <b>{t.name}</b> <span className="muted small">· {t.id}</span>
                          {t.isolated && <Badge tone="warn">ISOLATED</Badge>}{" "}
                          {t.trap && <Badge tone="bad">DECOY</Badge>}
                        </span>
                        <span className="muted small">{t.role}{t.ip ? ` · ${t.ip}` : ""}</span>
                        <button className="btn small primary" disabled={busy} onClick={() => doHop(t.id)}>Hop →</button>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <p className="muted small">
                  {(st.incident.level ?? 0) < 3
                    ? "Sweep unlocks after you advance past initial access (complete a stronger handshake)."
                    : "No reachable hosts yet — waiting for deception / segment map."}
                </p>
              )}
            </Panel>
          </div>
        </>
      )}

      <p className="muted small mt8">
        Session · {intel.browser || "browser"} · {intel.platform || "platform"} · {mounted ? new Date(now).toLocaleTimeString() : ""}
      </p>
    </div>
  );
}
