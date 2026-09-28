import React from "react";

export type SiteSkinProps = {
  hostname?: string;
  role?: string;
  status?: string;
  variant?: "live" | "decoy" | "outage";
  fabricated?: boolean;
  children?: React.ReactNode;
};

export function SiteSkin({
  hostname,
  role,
  status,
  variant = "live",
  fabricated,
  children,
}: SiteSkinProps) {
  const outage = variant === "outage";
  return (
    <div className={`site-skin ${outage ? "site-outage" : ""} ${fabricated ? "site-mirror" : ""}`}>
      <header className="site-nav">
        <div className="site-brand">
          <span className="site-logo">▚</span>
          <span className="site-name">PAYG SERVICES</span>
          <span className="site-domain">app.payg.in</span>
        </div>
        <div className="site-regions">
          {["APAC", "EU-WEST", "US-EAST"].map((r) => (
            <span key={r} className="site-region">{r}</span>
          ))}
        </div>
        <div className="push" />
        {hostname && <span className="muted small mono">{hostname}</span>}
        {role && <span className="muted small">· {role}</span>}
        {status && <span className="badge">{status}</span>}
        {fabricated && <span className="badge tone-accent">MIRROR FEED</span>}
        {outage && <span className="badge tone-bad">OUTAGE</span>}
      </header>
      <div className="site-body">{outage ? <Outage404 hostname={hostname} /> : children}</div>
      <footer className="site-footer">
        <span>© PAYG Financial Technologies Group</span>
        <span className="muted small">secure-banking demo environment · simulated traffic only</span>
      </footer>
    </div>
  );
}

export function Outage404({ hostname }: { hostname?: string }) {
  return (
    <div className="outage404">
      <div className="outage404-code">404</div>
      <h3>Service Unavailable</h3>
      <p className="muted">
        The host {hostname || "you requested"} is unreachable. The resource you requested does not
        exist or has been taken offline.
      </p>
      <ul className="outage404-list">
        <li>✓ No route to the requested endpoint</li>
        <li>✓ Server not found (name resolution returned nothing)</li>
        <li>✓ Service moved or decommissioned</li>
      </ul>
      <p className="small muted">If you believe this is an error, contact the operations desk. This domain is continuously monitored.</p>
    </div>
  );
}