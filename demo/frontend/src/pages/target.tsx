import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { demoApi } from "@/lib/api";
import { getSession } from "@/lib/session";
import { Panel, useMounted } from "@/components/ui";
import { SiteSkin, Outage404 } from "@/components/SiteSkin";

type Mode = "gate" | "portal" | "isolated";

const TABS = ["Overview", "Accounts & Billing", "Data & Queries", "Service Desk", "Settings"] as const;

const SQL_BANK = [
  "$ SELECT id, region, balance FROM production.accounts LIMIT 5;",
  " id | region  | balance",
  "----+---------+----------",
  "  1 | APAC    |  41,209.10",
  "  2 | EU-WEST |  12,884.42",
  "  3 | US-EAST |   9,011.87",
  "  4 | APAC    | 102,330.05",
  "  5 | EU-WEST |  71,552.90",
  "(5 rows)",
  "",
  "$ SELECT method, count(*) FROM production.payouts GROUP BY method;",
  " method  | count",
  "---------+-------",
  " wire    |  4123",
  " ach     | 76538",
  " crypto  |    201",
  "(3 rows)",
];

const TICKETS = [
  { id: "TCK-8812", subject: "Payout batch stuck in EU-WEST queue", status: "open" },
  { id: "TCK-8990", subject: "Merchant API key rotation requested", status: "open" },
  { id: "TCK-9051", subject: "Duplicate invoice on account 41", status: "in review" },
  { id: "TCK-9144", subject: "Finance team onboarding access", status: "resolved" },
];

const TRANSACTIONS = [
  ["2026-09-05 09:12", "txn_9f1c", "APAC", "incoming", "12,400.00"],
  ["2026-09-05 08:55", "txn_9e27", "EU-WEST", "payout", "-3,192.55"],
  ["2026-09-05 08:31", "txn_9dd8", "US-EAST", "refund", "-1,080.00"],
  ["2026-09-05 08:02", "txn_9c4b", "APAC", "incoming", "88,001.10"],
  ["2026-09-05 07:48", "txn_9b90", "EU-WEST", "invoice", "24,009.44"],
];

function deviceContext() {
  const out: Record<string, string> = {};
  if (typeof navigator === "undefined") return out;
  out.platform = navigator.platform;
  out.language = navigator.language || "";
  out.screen = `${window.screen?.width || 0}x${window.screen?.height || 0}`;
  out.viewport = `${window.innerWidth || 0}x${window.innerHeight || 0}`;
  out.timezone = new Date().getTimezoneOffset().toString();
  out.user_agent = navigator.userAgent;
  out.referrer = document.referrer || "";
  return out;
}

export default function TargetPage() {
  const session = getSession();
  const mounted = useMounted();
  const [mode, setMode] = useState<Mode>("gate");
  const [isolatedInfo, setIsolatedInfo] = useState<{ name: string; id: string; replica: string } | null>(null);
  const [questions, setQuestions] = useState<string[]>([]);
  const [answers, setAnswers] = useState<string[]>([]);
  const [startedAt, setStartedAt] = useState<number>(Date.now());
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState<(typeof TABS)[number]>("Overview");
  const [log, setLog] = useState<{ ts: string; label: string }[]>([]);
  const [sqlQuery, setSqlQuery] = useState(0);

  useEffect(() => {
    if (!session) return;
    demoApi.decoyQuestions(session.token).then((r) => setQuestions(r.questions.map((q) => q.question))).catch(() => {});
    (async () => {
      try {
        const st = await demoApi.attackerState(session.token);
        const inc = st?.incident;
        const live = !!inc?.incident_id && (
          !!inc.deception_active || !!inc.trapped || st?.state === "trapped" || (inc.level ?? 0) >= 4
        );
        if (!live || !inc) return;
        setIncidentId(inc.incident_id);

        // Trapped attackers are already inside the honeypot — never show the
        // real-server soft-404; take them straight to the decoy gate/portal.
        if (inc.trapped || st?.state === "trapped") {
          setMode("gate");
          return;
        }

        const originId = (inc as any).origin_asset_id || inc.origin || (session.asset_id ?? null);
        if (!originId) return;
        try {
          const ast = await demoApi.assetState(originId);
          // Soft-404 only for a *real* contained production server the attacker
          // still thinks they own — not for decoy/bait origins.
          const isRealIsolated = ast.role === "server" && ast.status === "contained" && !String(originId).includes("DECOY") && !String(originId).includes("BAIT") && !String(originId).startsWith("REPL-");
          if (isRealIsolated) {
            setMode("isolated");
            setIsolatedInfo({
              id: originId,
              name: ast.hostname,
              replica: typeof (ast as any).service === "object" && (ast as any).service
                ? (ast as any).service.fallback || "continuity replica"
                : "continuity replica",
            });
          }
        } catch {
          /* keep gate */
        }
      } catch {
        /* keep */
      }
    })();
  }, [session]);

  const record = useCallback(async (label: string, detail = "") => {
    if (!session || !incidentId) return;
    try {
      await demoApi.decoyInteract(session.token, incidentId, [{ question: "portal action", answer: label }], {
        ...deviceContext(),
        portal: label,
        detail: detail || null,
      });
      setLog((l) => [{ ts: new Date().toISOString().slice(11, 19), label }, ...l].slice(0, 8));
    } catch {
      /* keep */
    }
  }, [session, incidentId]);

  const submit = async () => {
    if (!session || !incidentId) return;
    setBusy(true); setErr("");
    const elapsed = Math.round((Date.now() - startedAt) / 1000);
    const payload = answers.map((a, i) => ({
      question: questions[i] || "?",
      answer: a,
      answered_at: new Date().toISOString(),
    }));
    try {
      const r = await demoApi.decoyInteract(session.token, incidentId, payload, deviceContext());
      setMode("portal");
      setLog([{ ts: new Date().toISOString().slice(11, 19), label: `session bound · ${r.session} (${elapsed}s)` }]);
    } catch (e: any) {
      setErr(e.message || "Handshake failed");
    }
    setBusy(false);
  };

  if (!mounted || !session) {
    return (
      <div className="page" style={{ maxWidth: 760 }}>
        <Panel title="Service console">
          <p className="muted">{!mounted ? "Restoring session…" : "Join first."}</p>
          {mounted && <Link className="btn" href="/join">Join the range</Link>}
        </Panel>
      </div>
    );
  }

  if (mode === "isolated") {
    return (
      <div className="page" style={{ maxWidth: 760 }}>
        <SiteSkin hostname={`${isolatedInfo?.name || ""} · srv-payg@app.payg.in`} role="server" status="unreachable" variant="outage">
          <Outage404 hostname={isolatedInfo?.name || "the server"} />
          <div className="note" style={{ marginTop: 14 }}>
            <b className="text-good">Service continuity active — {isolatedInfo?.replica || "a continuity replica"} absorbed the traffic.</b>
            <div className="small muted mt8">
              This host is quarantined after the confirmed intrusion. The operator&apos;s next hop is the segment replica that answered
              in its place; every action there is recorded for attribution.
            </div>
          </div>
          <div className="flex mt8">
            <Link className="btn" href="/attacker">Back to attacker console</Link>
          </div>
        </SiteSkin>
      </div>
    );
  }

  return (
    <div className="page" style={{ maxWidth: 780 }}>
      <SiteSkin
        hostname={incidentId ? "srv-payg@app.payg.in" : "connecting…"}
        role="server"
        status={mode === "portal" ? "session bound" : "reachable"}
        variant="decoy"
        fabricated
      >
        {mode === "portal" ? (
          <>
            <div className="portal-tabs" style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
              {TABS.map((t) => (
                <button key={t} className={`tiny ${tab === t ? "primary" : ""}`} onClick={() => { setTab(t); record(`tab:${t}`); }}>
                  {t}
                </button>
              ))}
              <span className="push" />
              <span className="badge tone-bad">SESSION MONITORED</span>
            </div>

            {tab === "Overview" && (
              <Panel title="Control center · hello, operator">
                <div className="kpis" style={{ marginBottom: 8 }}>
                  <div className="kpi"><span className="kpi-label">Accounts</span><b>41,209</b></div>
                  <div className="kpi"><span className="kpi-label">Pending payouts</span><b className="text-warn">1,206</b></div>
                  <div className="kpi"><span className="kpi-label">DB latency</span><b>2.1ms</b></div>
                  <div className="kpi"><span className="kpi-label">Failover state</span><b className="text-good">standby</b></div>
                </div>
                <p className="muted small">Welcome to the pay-as-you-go merchant console. Use the tabs to inspect accounts, run queries, or open service tickets.</p>
                <div className="flex mt8" style={{ gap: 8 }}>
                  <button className="btn primary" onClick={() => record("overview:generate-export", "merchant_export.csv")}>⬇ Export merchant_export.csv</button>
                  <button className="btn" onClick={() => record("overview:open-iaw", "ssrf-engine/iaw.sh read")}>Open deployment notes</button>
                  <button className="btn" onClick={() => record("overview:run-cron", "payouts nightly cron")}>Re-run nightly payouts</button>
                </div>
              </Panel>
            )}

            {tab === "Accounts & Billing" && (
              <Panel title="Recent transactions · live feed">
                <table className="mini-table">
                  <thead><tr><th>when</th><th>reference</th><th>region</th><th>type</th><th>amount</th></tr></thead>
                  <tbody>
                    {TRANSACTIONS.map((r) => (
                      <tr key={r[1]}>
                        <td className="mono">{r[0]}</td><td className="mono">{r[1]}</td><td>{r[2]}</td>
                        <td>{r[3]}</td><td className="mono" style={{ color: r[3] === "payout" || r[3] === "refund" ? "#ff9d3b" : "#16c784" }}>{r[4]}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="flex mt8" style={{ gap: 8 }}>
                  <button className="btn" onClick={() => record("billing:view-invoices", "invoice run APAC")}>View invoices</button>
                  <button className="btn" onClick={() => record("billing:download-statement", "statement eu-west 2026-08")}>⬇ Download statement</button>
                  <button className="btn" onClick={() => record("billing:adjust-balance", "adjust balance txn_9c4b")}>Post adjustment</button>
                </div>
              </Panel>
            )}

            {tab === "Data & Queries" && (
              <Panel title="SQL query runner · read-only mirror">
                <button className="tiny primary mb8" onClick={() => { setSqlQuery((q) => q + 1); record("sql:run-query", SQL_BANK[sqlQuery % 2 === 0 ? 0 : 8]?.trim() || "query"); }}>
                  ▶ Run query
                </button>
                <pre className="monitor" style={{ minHeight: 150 }}>
{SQL_BANK.slice(sqlQuery % 2 === 0 ? 0 : 8, (sqlQuery % 2 === 0 ? 0 : 8) + 8).join("\n")}
{"$ ".concat("_".repeat(8))}
                </pre>
                <div className="flex mt8" style={{ gap: 8 }}>
                  <button className="btn" onClick={() => { setSqlQuery(0); record("sql:select-accounts", "select accounts"); }}>accounts</button>
                  <button className="btn" onClick={() => { setSqlQuery(1); record("sql:select-payouts", "select payouts group by method"); }}>payouts by method</button>
                  <button className="btn" onClick={() => record("sql:dump-ddl", "information_schema ddl")}>schema dump</button>
                </div>
                <p className="muted tiny mt8">Mirror volume — commands are logged to the interaction ledger in real time.</p>
              </Panel>
            )}

            {tab === "Service Desk" && (
              <Panel title="Support queue">
                <div className="rows">
                  {TICKETS.map((t) => (
                    <div className="row" key={t.id} style={{ alignItems: "center" }}>
                      <span className="grow"><b className="small">{t.subject}</b><span className="muted tiny mono"> {t.id}</span></span>
                      <span className={`badge ${t.status === "open" ? "tone-bad" : t.status === "in review" ? "tone-warn" : "tone-good"}`}>{t.status}</span>
                      <button className="tiny" onClick={() => record("desk:assign", `assign ${t.id}`)}>assign</button>
                    </div>
                  ))}
                </div>
                <div className="flex mt8" style={{ gap: 8 }}>
                  <button className="btn" onClick={() => record("desk:open-ticket", "unlock customer 41")}>Open ticket</button>
                  <button className="btn" onClick={() => record("desk:escalate", "escalate TCK-8812")}>Escalate TCK-8812</button>
                </div>
              </Panel>
            )}

            {tab === "Settings" && (
              <Panel title="Operator account · session profile">
                <div className="rows">
                  <div className="row"><span className="grow">Session ref</span><b className="mono small">{incidentId || "—"}</b></div>
                  <div className="row"><span className="grow">Role</span><b>service operator · payouts</b></div>
                  <div className="row"><span className="grow">Regions</span><b>APAC · EU-WEST · US-EAST</b></div>
                </div>
                <div className="flex mt8" style={{ gap: 8 }}>
                  <button className="btn" onClick={() => record("settings:rotate-api-key", "rotate merchant api key")}>Rotate API key</button>
                  <button className="btn" onClick={() => record("settings:download-creds", "backup credentials bundle")}>⬇ Backup credentials</button>
                </div>
                <p className="muted tiny mt8">All operator actions on this mirror are captured for the defensive ledger.</p>
              </Panel>
            )}

            {log.length > 0 && (
              <Panel title="Session ledger · what your operator just did">
                <div className="rail" style={{ maxHeight: 150 }}>
                  {log.map((e, i) => (
                    <div className="rail-item" key={i}>
                      <span className="mono tiny muted" style={{ flex: "none" }}>{e.ts}</span>
                      <div className="grow small" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.label}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            )}
          </>
        ) : (
          <>
            {incidentId ? (
              <>
                <Panel title="Application console">
                  <pre className="monitor mt8">
$ whoami
srv-payg@app.payg.in
$ SELECT id, status FROM production.accounts LIMIT 2;
 id | first_name | last_name | region     | status
----+------------+-----------+------------+----------
  1 | ANA        | ROWE      | APAC       | active
  2 | RIK        | NOLAN     | EU-WEST    | active
(2 rows)
                  </pre>
                </Panel>
                <Panel title="Operator sign-in · session handshake" className="mt8">
                  <p className="muted small mb8">The application gate requires a handshake before full console access. Every keystroke here is part of the session record.</p>
                  <div className="portal-q" style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 220, overflowY: "auto", paddingRight: 4 }}>
                    {questions.map((q, i) => (
                      <div className="row" key={i} style={{ flexDirection: "column", alignItems: "stretch" }}>
                        <span className="muted small">{q}</span>
                        <input value={answers[i] || ""} onChange={(e) => setAnswers((a) => { const n = [...a]; n[i] = e.target.value; return n; })} placeholder="Input…" />
                      </div>
                    ))}
                  </div>
                  <button className="primary mt8" disabled={busy || !incidentId} onClick={submit}>Verify &amp; continue</button>
                  {err && <p className="text-bad small mt8">{err}</p>}
                </Panel>
              </>
            ) : (
              <Panel title="Application console">
                <p className="muted">No live application session yet. Open an engagement from the attacker console, advance past execution, then return here — or hop into a decoy first.</p>
                <Link className="btn mt8" href="/attacker">Back to attacker console</Link>
              </Panel>
            )}
          </>
        )}
      </SiteSkin>
      {mode !== "portal" && (
        <div className="flex mt8" style={{ gap: 8 }}>
          <Link className="btn" href="/attacker">Back to attacker console</Link>
          <Link className="btn" href="/command-center">Command Center</Link>
        </div>
      )}
    </div>
  );
}