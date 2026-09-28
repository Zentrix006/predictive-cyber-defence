"use client";

import { useEffect, useRef, useState } from 'react';
import { X, Search, Filter } from 'lucide-react';
import { cn } from '@/utils/classnames';
import { useIncidentStore } from '@/store/incidentStore';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
  incidents: any[];
  activeIncident: any;
  onSelectIncident: (incident: any) => void;
  dataAvailable: boolean;
}

export function Sidebar({ isOpen, onClose, incidents, activeIncident, onSelectIncident, dataAvailable }: SidebarProps) {
  const { setActiveIncident } = useIncidentStore();
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const sidebarRef = useRef<HTMLElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!isOpen || !window.matchMedia('(max-width: 1023px)').matches) return;
    const previous = document.activeElement as HTMLElement | null;
    sidebarRef.current?.querySelector<HTMLButtonElement>('button')?.focus();
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeRef.current();
      if (event.key !== 'Tab') return;
      const controls = sidebarRef.current?.querySelectorAll<HTMLElement>('button, input, select');
      if (!controls?.length) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', keyboard);
    return () => { document.removeEventListener('keydown', keyboard); previous?.focus(); };
  }, [isOpen]);
  const filteredIncidents = incidents.filter((incident) =>
    (!status || incident.status === status) &&
    (!severity || incident.severity === severity) &&
    (!query.trim() || `${incident.title ?? ''} ${incident.description ?? ''} ${incident.id ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()))
  );
  
  if (!isOpen) return null;

  return (
    <>
      {/* Overlay */}
      <div 
        className="fixed inset-0 bg-black/50 z-40 lg:hidden"
        onClick={onClose}
        aria-hidden="true"
      />
      
      {/* Sidebar */}
      <aside id="incident-sidebar" ref={sidebarRef} aria-label="Incident browser" className={cn(
        "console-shell-chrome fixed inset-y-0 left-0 z-50 h-[100dvh] lg:h-full max-w-[calc(100vw-2rem)] w-80 bg-[var(--bg-secondary)] border-r border-[var(--border-primary)] flex flex-col lg:inset-auto lg:w-72 xl:w-80 lg:shrink-0",
        "transform transition-transform duration-300 ease-in-out",
        "lg:relative lg:z-auto lg:transform-none"
      )}>
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-[var(--border-primary)]">
          <h2 className="text-lg font-semibold">Incidents</h2>
          <button 
            onClick={onClose}
            className="lg:hidden p-2 hover:bg-[var(--bg-tertiary)] rounded"
            aria-label="Close sidebar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        
        {/* Search & Filter */}
        <div className="p-4 border-b border-[var(--border-primary)] space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-secondary)]" />
            <input
              type="text"
              aria-label="Search incidents"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search incidents..."
              className="w-full pl-10 py-2 bg-[var(--bg-tertiary)] border border-[var(--border-primary)] rounded-lg text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)]"
            />
          </div>
          <div className="flex gap-2">
            <Filter className="w-4 h-4 text-[var(--text-secondary)] self-center" />
            <select aria-label="Filter incident status" value={status} onChange={(event) => setStatus(event.target.value)} className="min-w-0 flex-1 px-2 py-2 text-xs bg-[var(--bg-tertiary)] border border-[var(--border-primary)] rounded-lg text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)]">
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="contained">Contained</option>
              <option value="closed">Closed</option>
            </select>
            <select aria-label="Filter incident severity" value={severity} onChange={(event) => setSeverity(event.target.value)} className="min-w-0 flex-1 px-2 py-2 text-xs bg-[var(--bg-tertiary)] border border-[var(--border-primary)] rounded-lg text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-blue)]">
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
        
        {/* Incident List */}
        <div className="flex-1 overflow-y-auto p-4">
          {!dataAvailable && <p role="status" className="mb-3 text-xs text-[var(--text-secondary)]">Incident feed unavailable. Any listed incidents are from the last successful refresh.</p>}
          {filteredIncidents.length === 0 ? (
            <div className="text-center py-12 text-[var(--text-secondary)]">
              <p>{!dataAvailable ? 'Waiting for incident data' : incidents.length ? 'No matching incidents' : 'No incidents reported'}</p>
              {(query || status || severity) && <button className="mt-3 text-sm text-[var(--accent-blue)]" onClick={() => { setQuery(''); setStatus(''); setSeverity(''); }}>Clear filters</button>}
            </div>
          ) : (
            <ul className="space-y-2">
              {filteredIncidents.map((incident) => (
                <IncidentSidebarItem 
                  key={incident.id} 
                  incident={incident} 
                  isActive={activeIncident?.id === incident.id}
                  onClick={() => {
                    setActiveIncident(incident);
                    onSelectIncident(incident);
                    if (window.matchMedia('(max-width: 1023px)').matches) onClose();
                  }}
                />
              ))}
            </ul>
          )}
        </div>
        
        {/* Footer */}
        <div className="p-4 border-t border-[var(--border-primary)]">
          <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
            <span>{filteredIncidents.length} of {incidents.length} loaded</span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-[var(--accent-red)]" />
              <span>{incidents.filter(i => i.severity === 'critical').length} critical</span>
            </span>
          </div>
        </div>
      </aside>
    </>
  );
}

function IncidentSidebarItem({ incident, isActive, onClick }: { incident: any; isActive: boolean; onClick: () => void }) {
  const severityColors = {
    critical: 'bg-[var(--accent-red)]/15 text-[var(--accent-red)]',
    high: 'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]',
    medium: 'bg-[var(--accent-blue)]/15 text-[var(--accent-blue)]',
    low: 'bg-[var(--accent-green)]/15 text-[var(--accent-green)]',
  };
  
  const statusIcons = {
    open: <span className="w-2 h-2 rounded-full bg-[var(--accent-red)] animate-pulse" />,
    investigating: <span className="w-2 h-2 rounded-full bg-[var(--accent-blue)] animate-pulse" />,
    contained: <span className="w-2 h-2 rounded-full bg-[var(--accent-green)]" />,
    closed: <span className="w-2 h-2 rounded-full bg-[var(--text-secondary)]" />,
  };
  
  return (
    <li>
      <button
        onClick={onClick}
        aria-pressed={isActive}
        className={cn(
          "w-full p-3 rounded-lg text-left transition-all",
          "flex items-start gap-3",
          isActive 
            ? "bg-[var(--accent-blue)]/10 border-l-2 border-[var(--accent-blue)]" 
            : "hover:bg-[var(--bg-tertiary)]"
        )}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="font-medium truncate" title={incident.title}>{incident.title}</h4>
            {statusIcons[incident.status as keyof typeof statusIcons] || null}
          </div>
          <div className="flex items-center gap-2 text-xs text-[var(--text-secondary)] mt-1">
            <span className={cn("px-2 py-0.5 rounded", severityColors[incident.severity as keyof typeof severityColors] || 'bg-[var(--bg-tertiary)]')}>
              {incident.severity}
            </span>
            <span className="capitalize">{incident.status}</span>
          </div>
        </div>
        <div className="text-right text-xs text-[var(--text-secondary)]">
          <div>{new Date(incident.detected_at).toLocaleTimeString()}</div>
        </div>
      </button>
    </li>
  );
}
