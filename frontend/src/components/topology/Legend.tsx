"use client";

import { useState } from "react";
import { Info, X } from "lucide-react";

const statuses = [
  ["Normal", "#28C98B"],
  ["Suspicious", "#D3A233"],
  ["Compromised", "#FF6A80"],
  ["Contained", "#5F8BFF"],
  ["Deception", "#9B7DFF"],
  ["Offline", "#5F6B82"],
] as const;

const criticality = [
  ["Least critical", "#28C98B"],
  ["Medium", "#D3A233"],
  ["High", "#FF9D4D"],
  ["Most critical", "#FF5C7A"],
] as const;

/** Compact by default so topology information is never obscured. */
export function Legend() {
  const [open, setOpen] = useState(false);

  return (
    <div className="absolute bottom-3 left-3 z-30">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex items-center gap-2 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-secondary)]/95 px-3 py-2 text-xs font-medium text-[var(--text-primary)] shadow-lg backdrop-blur hover:bg-[var(--bg-tertiary)]"
      >
        <Info className="h-4 w-4 text-[var(--accent-blue)]" />
        Legend
      </button>

      {open && (
        <section className="absolute bottom-12 left-0 w-[min(19rem,calc(100vw-2rem))] max-h-[min(32rem,calc(100dvh-8rem))] overflow-y-auto rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)]/95 p-3 shadow-xl backdrop-blur animate-fade-in">
          <div className="mb-3 flex items-center justify-between border-b border-[var(--border-primary)] pb-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-[var(--text-secondary)]">Topology legend</h4>
            <button type="button" onClick={() => setOpen(false)} className="rounded p-1 hover:bg-[var(--bg-tertiary)]" aria-label="Close legend">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="space-y-3 text-xs">
            <div>
              <p className="mb-1.5 font-medium text-[var(--text-secondary)]">Status</p>
              <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                {statuses.map(([label, color]) => <span key={label} className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />{label}</span>)}
              </div>
            </div>
            <div className="border-t border-[var(--border-primary)] pt-3">
              <p className="mb-1.5 font-medium text-[var(--text-secondary)]">Criticality layers</p>
              <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                {criticality.map(([label, color]) => <span key={label} className="flex items-center gap-1.5"><i className="h-3 w-3 rounded-full border-2" style={{ borderColor: color }} />{label}</span>)}
              </div>
            </div>
            <div className="border-t border-[var(--border-primary)] pt-3 text-[var(--text-secondary)]">
              <p><span className="mr-2 inline-block h-px w-7 align-middle bg-[var(--border-primary)]" />Observed connection</p>
              <p className="mt-1"><span className="mr-2 inline-block w-7 border-t-2 border-dashed border-[var(--accent-purple)] align-middle" />Predicted path</p>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
