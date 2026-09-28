import { useEffect, useRef } from "react";
import QRCode from "qrcode";
import Link from "next/link";
import { Panel } from "@/components/ui";
import { demoApi } from "@/lib/api";

const roleMeta: Record<string, { color: string; desc: string }> = {
  attacker: { color: "#ff5c5c", desc: "Launches the simulated attack from a browser (challenge-driven, no real exploits)." },
  observer: { color: "#22d3ee", desc: "Watches the live command center and the world model predicting the next move." },
  server: { color: "#4c8dff", desc: "Physical node hosting a service that the simulated attacker moves toward." },
  host: { color: "#f0b429", desc: "Physical workstation node; the safest place to watch a node get attacked up close." },
  client: { color: "#16c784", desc: "Physical client device inside the simulated network." },
  other: { color: "#a78bfa", desc: "Any other physical device you want to bring onto the range." },
};

export default function Landing() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    let cancelled = false;
    const draw = async () => {
      // start-demo.sh configures this to the host wlan0 address. Do not use a
      // presenter's localhost origin for an audience QR code.
      let base = process.env.NEXT_PUBLIC_DEMO_PUBLIC_URL || window.location.origin;
      try {
        const config = await demoApi.config();
        if (config.public_base_url) base = config.public_base_url;
      } catch { /* retain explicit/browser fallback */ }
      if (!cancelled && canvasRef.current) {
        await QRCode.toCanvas(canvasRef.current, `${base.replace(/\/$/, "")}/join`, {
          width: 220, margin: 1, color: { dark: "#0b0f1a", light: "#dbe7ff" },
        });
      }
    };
    draw().catch(() => {});
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="page">
      <div className="topbar">
        <span className="brand">UXH &middot; PREDICTIVE CYBER RANGE</span>
        <span className="badge tone-warn">LIVE DEMO</span>
        <span className="badge">SIMULATION &middot; CONTROLLED</span>
        <div className="push" />
        <Link className="btn" href="/command-center">Command Center</Link>
        <Link className="btn" href="/ai-intelligence">AI Intelligence</Link>
        <Link className="btn" href="/admin">Admin</Link>
      </div>

      <div className="grid cols-2">
        <div>
          <h1 style={{ fontSize: 28 }}>Predict the attack<br /><span className="text-accent">before it lands.</span></h1>
          <p className="muted">
            The temporal World Model (flow-wm-v3.0.0) watches simulated telemetry, forecasts the
            attack&apos;s next target, and steers the simulation into a decoy environment — live, with real predictions.
          </p>
          <div className="rows mt8">
            {Object.keys(roleMeta).map((r) => (
              <div className="row" key={r}>
                <span className="dot" style={{ background: roleMeta[r].color }} />
                <b style={{ width: 80 }}>{r}</b>
                <span className="grow muted" style={{ fontSize: 12 }}>{roleMeta[r].desc}</span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <Panel title="Scan to join the range">
            <div className="flex" style={{ flexDirection: "column", alignItems: "center", gap: 0 }}>
              <canvas ref={canvasRef} style={{ borderRadius: 10 }} />
              <p className="muted small mt8">Join as an attacker, observer — or bring your device (server / host / client / other) and it appears in the topology.</p>
            </div>
          </Panel>
          <Panel title="What happens" className="mt8">
            <ol className="muted small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.9 }}>
              <li>Devices register the moment they join and heartbeat to stay online — nothing is pre-created.</li>
              <li>An attacker picks from the <b>devices actually connected</b> and starts a simulated engagement.</li>
              <li>The world model weighs the warning signs and predicts the next target with belief states.</li>
              <li>The defender isolates the origin and, only then, stages a decoy twin of the predicted target.</li>
              <li>Forensics capture every simulated touchpoint for the debrief.</li>
            </ol>
          </Panel>
        </div>
      </div>
    </div>
  );
}
