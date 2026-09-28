"use client";

import { useIncidentStore } from '@/store/incidentStore';
import { cn } from '@/utils/classnames';

interface TimelineProps {
  className?: string;
}

export function Timeline({ className }: TimelineProps) {
  const { activeIncident } = useIncidentStore();
  const timelineEvents = Array.isArray(activeIncident?.timeline_events) ? activeIncident.timeline_events : [];

  return (
    <div className={cn("h-full flex flex-col p-4 bg-[var(--bg-secondary)]", className)}>
      <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Timeline</h3>
      
      {timelineEvents.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-[var(--text-muted)]">
          No timeline events
        </div>
      ) : (
        <div className="flex-1 overflow-auto space-y-3">
          {timelineEvents
            .sort((a: any, b: any) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .map((event: any, i: number) => (
              <div key={i} className={cn("p-3 rounded border border-[var(--border-primary)] bg-[var(--bg-tertiary)]")}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm">{event.title}</span>
                      <span className={cn(
                        "px-1.5 py-0.5 text-xs rounded font-medium",
                        event.severity === 'critical' && 'bg-red-500/20 text-red-400',
                        event.severity === 'high' && 'bg-orange-500/20 text-orange-400',
                        event.severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
                        event.severity === 'low' && 'bg-green-500/20 text-green-400'
                      )}>
                        {event.severity}
                      </span>
                    </div>
                    <p className="text-sm text-[var(--text-secondary)]">{event.description}</p>
                  </div>
                  <div className="text-xs text-[var(--text-muted)] whitespace-nowrap">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                {event.source && (
                  <div className="mt-1 text-xs text-[var(--text-muted)]">
                    Source: {event.source}
                  </div>
                )}
              </div>
            ))}
        </div>
      )}
    </div>
  );
}