"use client";

import React, { useState, useEffect } from 'react';
import { useIncidentStore } from '@/store/incidentStore';
import { demoApiBase } from '@/lib/demo-api';
import { cn } from '@/utils/classnames';
import { Clock, ShieldAlert, Cpu, Terminal, Radio } from 'lucide-react';

interface TimelineProps {
  className?: string;
}

interface TimelineEventItem {
  id?: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  source?: string;
  stage?: string;
  status?: string;
  incident_id?: string;
}

export function Timeline({ className }: TimelineProps) {
  const { activeIncident } = useIncidentStore();
  const [remoteEvents, setRemoteEvents] = useState<TimelineEventItem[]>([]);

  useEffect(() => {
    let cancelled = false;

    const fetchTimeline = async () => {
      try {
        const res = await fetch(`${demoApiBase()}/command/timeline?limit=60`);
        if (res.ok) {
          const data = await res.json();
          if (!cancelled && Array.isArray(data)) {
            const mapped: TimelineEventItem[] = data.map((evt: any) => ({
              id: evt.event_id || String(Math.random()),
              title: evt.title || evt.payload?.title || (evt.kind ? evt.kind.replace(/_/g, ' ').toUpperCase() : 'TELEMETRY EVENT'),
              description: evt.description || evt.payload?.description || evt.payload?.command || evt.payload?.detail || JSON.stringify(evt.payload || {}),
              severity: (evt.severity || evt.payload?.severity || (evt.kind?.includes('mitigation') ? 'high' : evt.kind?.includes('trapped') ? 'critical' : 'medium')) as any,
              timestamp: evt.timestamp,
              source: evt.source || evt.actor_id || 'system',
              stage: evt.stage || evt.payload?.stage || (evt.kind?.includes('recon') ? 'reconnaissance' : evt.kind?.includes('lateral') ? 'lateral_movement' : 'containment'),
              status: evt.payload?.status,
              incident_id: evt.incident_id,
            }));
            setRemoteEvents(mapped);
          }
        }
      } catch {
        // fallback
      }
    };

    fetchTimeline();
    const interval = setInterval(fetchTimeline, 3000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeIncident?.id]);

  const storeEvents: TimelineEventItem[] = Array.isArray(activeIncident?.timeline_events) ? activeIncident.timeline_events : [];
  
  const relevantRemote = activeIncident?.id
    ? remoteEvents.filter(e => !e.incident_id || e.incident_id === activeIncident.id)
    : remoteEvents;

  const seenTitles = new Set<string>();
  const combined: TimelineEventItem[] = [];

  for (const ev of storeEvents) {
    seenTitles.add(ev.title.trim().toLowerCase());
    combined.push(ev);
  }

  for (const ev of relevantRemote) {
    const key = (ev.title || '').trim().toLowerCase();
    if (!seenTitles.has(key)) {
      seenTitles.add(key);
      combined.push(ev);
    }
  }

  const sortedEvents = combined.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return (
    <div className={cn("h-full flex flex-col p-3.5 bg-[var(--bg-secondary)] overflow-hidden", className)}>
      <div className="flex items-center justify-between mb-2.5 border-b border-[var(--border-primary)] pb-2 shrink-0">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-[var(--accent-blue)]" />
            Incident Timeline
          </h3>
          <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-[var(--bg-tertiary)] border border-[var(--border-primary)] text-[var(--text-secondary)]">
            {sortedEvents.length} events
          </span>
        </div>
        <div className="flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400 font-mono">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
          Live Stream
        </div>
      </div>
      
      {sortedEvents.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center p-4 text-[var(--text-muted)]">
          <Radio className="w-6 h-6 mb-1.5 opacity-40 animate-pulse text-[var(--accent-blue)]" />
          <p className="text-xs font-medium">Awaiting security events...</p>
          <p className="text-[10px] text-[var(--text-muted)] mt-0.5">Trigger an executive scenario or run adversary scans to generate traces.</p>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {sortedEvents.map((event, i) => (
            <div 
              key={event.id || i} 
              className={cn(
                "p-2.5 rounded-lg border transition-all text-xs",
                event.severity === 'critical' ? 'border-red-500/30 bg-red-500/5' :
                event.severity === 'high' ? 'border-amber-500/30 bg-amber-500/5' :
                'border-[var(--border-primary)] bg-[var(--bg-tertiary)]'
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5 mb-1">
                    <span className="font-bold text-[var(--text-primary)] text-xs">{event.title}</span>
                    <span className={cn(
                      "px-1.5 py-0.2 text-[9px] rounded font-bold uppercase tracking-wider",
                      event.severity === 'critical' && 'bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/30',
                      event.severity === 'high' && 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30',
                      event.severity === 'medium' && 'bg-blue-500/15 text-blue-600 dark:text-blue-400 border border-blue-500/30',
                      event.severity === 'low' && 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                    )}>
                      {event.severity}
                    </span>
                    {event.stage && (
                      <span className="px-1.5 py-0.2 text-[9px] rounded bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30 font-mono">
                        {event.stage}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-[var(--text-secondary)] font-mono leading-relaxed break-words">{event.description}</p>
                </div>
                <div className="text-[10px] text-[var(--text-muted)] font-mono whitespace-nowrap pt-0.5">
                  {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'T+0.00s'}
                </div>
              </div>
              {event.source && (
                <div className="mt-1.5 pt-1 border-t border-[var(--border-primary)] flex items-center gap-1 text-[10px] text-[var(--text-muted)] font-mono">
                  <span>Source:</span>
                  <span className="text-[var(--text-primary)] font-semibold">{event.source}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}