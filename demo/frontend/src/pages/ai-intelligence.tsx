import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { demoApi, type AiObservability, type AssetInfo } from "@/lib/api";
import { Badge, Kpi, Panel, Spinner, StatusDot } from "@/components/ui";

const PIN_KEY = "demo:admin:pin";
const fmt = (v?: string) => v ? new Date(v).toLocaleString() : "—";

export default function AiIntelligence() {
  const [data, setData] = useState<AiObservability | null>(null);
  const [devices, setDevices] = useState<AssetInfo[]>([]);
  const [pin, setPin] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const requestId = useRef(0);
  const load = useCallback(async () => {
    const id = ++requestId.current;
    setLoading(true);
    try {
      const [ai, rows] = await Promise.all([demoApi.ai(), demoApi.assets()]);
      if (id !== requestId.current) return;
      setData(ai); setDevices(rows); setError("");
    } catch (e: any) { if (id === requestId.current) setError(e.message || "Unable to refresh AI observability."); }
    finally { if (id === requestId.current) setLoading(false); }
  }, []);
  useEffect(() => { setPin(sessionStorage.getItem(PIN_KEY) || ""); load(); const id = setInterval(load, 5000); return () => { requestId.current++; clearInterval(id); }; }, [load]);
  const action = async (run: () => Promise<any>) => {
    if (!pin) { setMessage("Enter the presenter PIN to run intake actions."); return; }
    if (busy) return;
    setMessage("");
    setBusy(true);
    try { const result = await run(); setMessage(result.message || `AI action: ${result.status || "complete"}`); await load(); }
    catch (e: any) { setMessage(e.message || "AI action failed."); }
    finally { setBusy(false); }
  };
  const training = data?.training;
  const plan = training?.plan;
  const live = training?.status;
  const progress = live?.progress_percent ?? plan?.progress_percent ?? 0;
  const eta = live?.eta_minutes ?? plan?.eta_minutes ?? null;
  if (!data) return <main className="page ai-page"><div className="topbar"><span className="brand">AI Intelligence</span><Link className="btn tiny" href="/command-center">Command Center</Link></div><Panel title="Model observability">{error ? <><p role="alert">{error}</p><button onClick={load} disabled={loading}>{loading ? "Retrying…" : "Retry connection"}</button></> : <Spinner label="Loading checkpoint and range telemetry…" />}</Panel></main>;
  const intake = data.schema_intake;
  return <main className="page ai-page">
    <div className="topbar">
      <span className="brand">AI Intelligence</span>
      <Badge tone="accent">Demo range</Badge>
      <Badge tone={!error && data.model.ready ? "good" : "warn"}>{error ? "Status out of date" : data.model.ready ? "Serving checkpoint ready" : "Model unavailable"}</Badge>
      <Badge tone="accent">{data.model.version || "unknown"}</Badge>
      <div className="push" />
      <Link className="btn tiny" href="/command-center">Command Center</Link>
      <Link className="btn tiny" href="/admin">Admin</Link>
    </div>
    <section className="ai-hero panel">
      <div><h1>Temporal cyber world model</h1><p className="muted">Real range devices supply the live topology. The model consumes bounded telemetry, compares plausible futures, and recommends contained simulation responses.</p></div>
      <button onClick={load} disabled={busy || loading}>{loading ? "Refreshing…" : "Refresh status"}</button>
    </section>
    <p className="muted small">Snapshot: {fmt(data.generated_at)} · Refreshes every 5 seconds · Real joined devices, simulated engagement events</p>
    {error && <p role="alert" className="ai-message">{error} Displaying the last successful snapshot.</p>}
    {message && <p role="status" className="ai-message">{message}</p>}
    <div className="kpis">
      <Kpi label="Real range devices" value={data.range.real_devices} accent="var(--accent)" />
      <Kpi label="Range events" value={data.range.live_telemetry_events} accent="var(--accent-2)" />
      <Kpi label="Model features" value={data.model.feature_dim} accent="var(--good)" />
      <Kpi label="Exported training records" value={training?.demo_records || 0} accent="var(--warn)" />
    </div>
    <div className="grid cols-2 mt8">
      <Panel title="Range scanner · observed devices" right={<Badge tone={error ? "warn" : "accent"}>{devices.length} reported</Badge>}>
        <p className="muted small">This scanner reports devices that joined by QR or registered through the range heartbeat. It does not invent assets or actively probe the Wi-Fi network.</p>
        <div className="rows mt8 scroll-soft">{devices.map(d => <div className="row" key={d.id}><StatusDot status={d.status}/><span className="grow"><b>{d.hostname}</b><span className="muted small"> · {d.ip || "IP pending"} · {d.role}</span></span><Badge tone={d.status === "healthy" ? "good" : "warn"}>{d.status}</Badge></div>)}{!devices.length && <p className="muted">No live devices. Scan the QR code to join a device to the range.</p>}</div>
      </Panel>
      <Panel title="Serving model & promotion gate">
        <div className="rows">
          <div className="row"><span className="grow">Model</span><b className="mono">{data.model.version || "—"}</b></div>
          <div className="row"><span className="grow">Architecture</span><span>{data.model.kind}</span></div>
          <div className="row"><span className="grow">Serving state</span><Badge tone={data.model.ready ? "good" : "warn"}>{data.model.ready ? "checkpoint loaded" : "unavailable"}</Badge></div>
          <div className="row"><span className="grow">Promotion policy</span><span className="small muted">{training?.promotion}</span></div>
        </div>
      </Panel>
    </div>
    <div className="grid cols-2 mt8">
      <Panel title="Public schema intake · presenter controlled" right={<Badge tone={intake.status === "completed" ? "good" : intake.status === "running" ? "warn" : "accent"}>{intake.status}</Badge>}>
        <p className="muted small">The scan reads a small allow-listed set of public STIX JSON schemas. It records field contracts and provenance; schemas do not automatically alter model weights.</p>
        <div className="flex mt8" style={{ gap: 8, flexWrap: "wrap" }}>
          <label className="muted small" style={{ display: "grid", gap: 4 }}>
            Presenter PIN
            <input aria-label="Presenter PIN for AI actions" type="password" autoComplete="current-password" placeholder="Presenter PIN" value={pin} onChange={e => setPin(e.target.value)} style={{ width: 170 }} />
          </label>
          <button className="primary" disabled={busy || !pin || intake.status === "running"} onClick={() => action(() => demoApi.admin.scanSchemas(pin))}>
            {intake.status === "running" ? "Scanning schemas…" : busy ? "Working…" : "Scan public schemas"}
          </button>
          <button disabled={busy || !pin || intake.status === "running"} onClick={() => action(() => demoApi.admin.prepareTraining(pin))}>Prepare training manifest</button>
          <button disabled={busy || !pin} onClick={() => action(() => demoApi.admin.trainAI(pin))}>Train AI</button>
        </div>
        <p className="muted small">A manifest records candidate inputs. Train AI exports the demo telemetry, validates the schema gate, and starts an isolated candidate retrain without replacing the serving checkpoint.</p>
        <p className="muted tiny mt8">Last intake: {fmt(intake.completed_at || intake.started_at)} · {intake.sources.length} retrieved contracts · {intake.errors.length} errors</p>
        <div className="rows mt8">{intake.sources.map(s => <div className="row" key={s.url}><StatusDot status="healthy"/><span className="grow"><b>{s.name}</b><span className="muted small"> · {s.property_count} fields · {(s.bytes / 1024).toFixed(1)} KB</span></span><Badge tone="accent">verified</Badge></div>)}{intake.errors.map(s => <div className="row" key={s.url}><StatusDot status="offline"/><span className="grow"><b>{s.name}</b><span className="muted small"> · {s.error}</span></span></div>)}</div>
      </Panel>
      <Panel title="Training plan · ETA, schema, runtime fallback">
        {plan ? <div className="rows">
          <div className="row"><span className="grow">Progress</span><b>{Math.max(0, Math.min(100, progress))}%</b></div>
          <div className="row"><span className="grow">ETA</span><b>{eta == null ? "—" : `${eta} min`}</b></div>
          <div className="row"><span className="grow">Device strategy</span><span className="small muted">{plan.device_strategy?.description || live?.device_preference || "Auto device selection"}</span></div>
          <div className="row"><span className="grow">CUDA available</span><Badge tone={plan.device_strategy?.cuda_available ? "good" : "warn"}>{plan.device_strategy?.cuda_available ? "yes" : "no"}</Badge></div>
          <div className="row"><span className="grow">CPU fallback</span><Badge tone={plan.device_strategy?.cpu_available ? "good" : "warn"}>{plan.device_strategy?.cpu_available ? "yes" : "no"}</Badge></div>
          <div className="row"><span className="grow">Training records</span><b>{plan.records ?? training?.demo_records ?? 0}</b></div>
          <div className="row"><span className="grow">Schema requirements</span><b>{plan.schema_requirements?.length || 0}</b></div>
          <div className="rows" style={{ gap: 8 }}>
            {plan.schema_requirements?.map(req => <div className="row" key={req.name} style={{ alignItems: "flex-start" }}>
              <span className="grow">
                <b>{req.name}</b>
                <span className="muted small"> · {req.required_fields.length} required fields</span>
                <div className="muted tiny">{req.required_fields.join(", ")}</div>
              </span>
              <Badge tone="accent">{req.sources.join(" · ")}</Badge>
            </div>)}
          </div>
          <div className="rows" style={{ gap: 8 }}>
            <b className="small">Why this is better than last time</b>
            {plan.expected_improvement?.map((item, idx) => <div className="muted small" key={idx}>• {item}</div>)}
          </div>
          <div className="rows" style={{ gap: 8 }}>
            <b className="small">Current metrics baseline</b>
            <div className="row"><span className="grow">Model version</span><b className="mono">{plan.current_metrics?.model_version || data.model.version || "—"}</b></div>
            <div className="row"><span className="grow">Stage accuracy</span><b>{plan.current_metrics?.stage_accuracy ?? "—"}</b></div>
            <div className="row"><span className="grow">Infiltration accuracy</span><b>{plan.current_metrics?.infiltration_accuracy ?? "—"}</b></div>
            <div className="row"><span className="grow">Macro F1</span><b>{plan.current_metrics?.macro_f1 ?? "—"}</b></div>
            <div className="row"><span className="grow">Validation loss</span><b>{plan.current_metrics?.validation_loss ?? "—"}</b></div>
          </div>
          <div className="rows" style={{ gap: 8 }}>
            <b className="small">Plan steps</b>
            {plan.steps?.map(step => <div className="row" key={step.phase}><span className="grow">{step.label}</span><span>{step.percent}% · {step.eta_minutes} min</span></div>)}
          </div>
        </div> : <p className="muted">No training plan yet. Use Train AI to export data, validate schemas, and launch the candidate retrain.</p>}
      </Panel>
    </div>
    <div className="grid cols-2 mt8">
      <Panel title="Candidate training manifest">
        {training?.candidate ? <div className="rows"><div className="row"><span className="grow">Candidate status</span><Badge tone="warn">{training.candidate.status}</Badge></div><div className="row"><span className="grow">Range records</span><b>{training.candidate.demo_telemetry_records}</b></div><div className="row"><span className="grow">Schema contracts</span><b>{training.candidate.schema_contracts?.length || 0}</b></div><p className="muted small">{training.candidate.next_step}</p></div> : <p className="muted">No candidate manifest yet. Export the demo telemetry, scan the approved schema sources, then prepare a candidate for review.</p>}
      </Panel>
    </div>
    <Panel title="Knowledge flow" className="mt8"><div className="ai-flow">{data.knowledge_flow.map((n, i) => <div key={n.label} className="ai-flow-step"><b>{n.label}</b><span className="muted small">{n.detail}</span>{i < data.knowledge_flow.length - 1 && <i>→</i>}</div>)}</div></Panel>
  </main>;
}
