"use client";

import { useIncidentStore } from '@/store/incidentStore';
import { cn } from '@/utils/classnames';

interface IncidentListProps {
  incidents: any[];
  onSelect: (inc: any) => void;
}

export function IncidentList({ incidents, onSelect }: IncidentListProps) {
  if (incidents.length === 0) {
    return (
      <div className={cn("h-full flex items-center justify-center text-[var(--text-muted)]")}>
        No incidents
      </div>
    );
  }

  return (
    <div className={cn("h-full flex flex-col p-4 bg-[var(--bg-secondary)] overflow-auto")}>
      <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Incidents</h3>
      <div className="space-y-2 flex-1 overflow-auto">
        {incidents.map((inc: any) => (
          <div
            key={inc.id}
            onClick={() => onSelect(inc)}
            className={cn(
              "p-3 rounded cursor-pointer transition-colors border",
              "hover:bg-[var(--bg-tertiary)] border-[var(--border-primary)]"
            )}
          >
            <div className="flex items-center justify-between">
              <span className="font-medium text-sm">{inc.title}</span>
              <span
                className={cn(
                  "px-2 py-0.5 text-xs rounded font-medium",
                  inc.severity === 'critical' && 'bg-red-500/20 text-red-400',
                  inc.severity === 'high' && 'bg-orange-500/20 text-orange-400',
                  inc.severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
                  inc.severity === 'low' && 'bg-green-500/20 text-green-400'
                )}
              >
                {inc.severity}
              </span>
            </div>
            <div className="text-xs text-[var(--text-muted)] mt-1">
              {new Date(inc.detected_at).toLocaleString()} • {inc.status}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}