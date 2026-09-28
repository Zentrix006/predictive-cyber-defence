import React from "react";

export function Panel({ title, children, className = "", right }: { title?: React.ReactNode; children: React.ReactNode; className?: string; right?: React.ReactNode }) {
  return (
    <section className={`panel ${className}`}>
      {title !== undefined && (
        <header className="panel-head">
          <h3>{title}</h3>
          {right && <div className="panel-right">{right}</div>}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

const statusColor: Record<string, string> = {
  healthy: "#16c784",
  registering: "#f0b429",
  suspicious: "#f0b429",
  under_attack: "#ff5c5c",
  compromised: "#ff2d55",
  contained: "#4c8dff",
  deception: "#b44cff",
  offline: "#5b6681",
  infra: "#5b6681",
  pending: "#f0b429",
  active: "#16c784",
  resolved: "#5b6681",
  low: "#16c784",
  medium: "#f0b429",
  high: "#ff8c42",
  critical: "#ff2d55",
};

export function StatusDot({ status }: { status?: string }) {
  const c = statusColor[status?.toLowerCase() || ""] || "#5b6681";
  return <span className="dot" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />;
}

export function Badge({ children, tone }: { children: React.ReactNode; tone?: string }) {
  return <span className={`badge ${tone ? `tone-${tone}` : ""}`}>{children}</span>;
}

export function Kpi({ label, value, accent }: { label: string; value: React.ReactNode; accent?: string }) {
  return (
    <div className="kpi">
      <span className="kpi-label">{label}</span>
      <span className="kpi-value" style={accent ? { color: accent } : undefined}>
        {value}
      </span>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="spinner-wrap">
      <div className="spinner" />
      {label && <span className="muted">{label}</span>}
    </div>
  );
}

export function Time({ iso }: { iso?: string }) {
  if (!iso) return <span className="muted">—</span>;
  const d = new Date(iso.replace(" ", "T"));
  return <span className="mono muted">{d.toLocaleTimeString()}</span>;
}

export function useNow(intervalMs = 1000) {
  const [now, setNow] = React.useState(Date.now());
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

// True only after hydration. Lets pages defer client-only content (session,
// live clocks) so SSR markup and the first client render stay identical —
// otherwise React throws "text content did not match server".
export function useMounted() {
  const [mounted, setMounted] = React.useState(false);
  React.useEffect(() => setMounted(true), []);
  return mounted;
}