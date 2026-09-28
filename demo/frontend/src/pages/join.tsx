import { useState } from "react";
import { useRouter } from "next/router";
import { demoApi, type Role } from "@/lib/api";
import { saveSession } from "@/lib/session";

const roles: { role: Role; label: string; hint: string }[] = [
  { role: "attacker", label: "Attacker", hint: "I will run the simulated attack" },
  { role: "observer", label: "Observer", hint: "I will watch the command center" },
  { role: "server", label: "Server", hint: "My device becomes a server node on the range" },
  { role: "host", label: "Host", hint: "My device becomes a workstation node on the range" },
  { role: "client", label: "Client", hint: "My device becomes a client node on the range" },
  { role: "other", label: "Other device", hint: "My device joins as an unclassified node" },
];

export default function Join() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const pick = async (role: Role) => {
    setBusy(true);
    setErr("");
    try {
      const s = await demoApi.join(role);
      saveSession(s);
      if (role === "attacker") router.push("/attacker");
      else if (role === "observer") router.push("/command-center");
      else {
        const id = s.asset_id || s.participant_id;
        if (id) router.push(`/device/${encodeURIComponent(id)}`);
        else router.push("/join");
      }
    } catch (e: any) {
      setErr(e.message || "Join failed");
      setBusy(false);
    }
  };

  return (
    <div className="page" style={{ maxWidth: 720 }}>
      <h1>Join the live cyber-range</h1>
      <p className="muted">
        Pick a role. Device roles register a node on the range — your browser page
        (heartbeat) is what makes that device appear in the live topology. Nothing
        leaves your browser except device context.
      </p>
      <div className="rows mt8">
        {roles.map((r) => (
          <button key={r.role} className="row" style={{ justifyContent: "space-between" }} disabled={busy} onClick={() => pick(r.role)}>
            <span>
              <b>{r.label}</b>
              <div className="muted small">{r.hint}</div>
            </span>
            <span className="text-accent">→</span>
          </button>
        ))}
      </div>
      {err && <p className="text-bad small mt8">{err}</p>}
    </div>
  );
}
