"use client";

import { useEffect, useRef, useState } from 'react';
import {
  Brain, ChevronDown, Cpu, FileSearch, FlaskConical, LayoutDashboard,
  MonitorPlay, Network, RadioTower, Settings, ShieldAlert, TrendingUp, Users,
} from 'lucide-react';
import { useUIStore } from '@/store/uiStore';
import { cn } from '@/utils/classnames';

const NAV_GROUPS = [
  { label: 'Operations', items: [
    { view: 'command-center', label: 'Command Center', icon: LayoutDashboard },
    { view: 'attack', label: 'Attack Forecast', icon: TrendingUp },
    { view: 'threat-actors', label: 'Threat Actors', icon: Users },
  ] },
  { label: 'Investigations', items: [
    { view: 'passive-analysis', label: 'Passive Analysis', icon: FileSearch },
    { view: 'forensics', label: 'Forensics', icon: FileSearch },
    { view: 'graph-analysis', label: 'Graph Analysis', icon: Network },
    { view: 'deception', label: 'Deception', icon: ShieldAlert },
  ] },
  { label: 'Network', items: [
    { view: 'infrastructure', label: 'Infrastructure', icon: Network },
    { view: 'live-telemetry', label: 'Live Telemetry', icon: RadioTower },
    { view: 'mitigation-cache', label: 'Mitigation Cache', icon: Cpu },
  ] },
  { label: 'Intelligence', items: [
    { view: 'ai-intelligence', label: 'AI Intelligence', icon: Brain },
    { view: 'model-lab', label: 'Model Lab', icon: FlaskConical },
  ] },
  { label: 'System', items: [
    { view: 'presentation', label: 'Executive Demo', icon: MonitorPlay },
    { view: 'settings', label: 'Settings', icon: Settings },
  ] },
];

export function NavBar({ demoMode: _demoMode = false }: { demoMode?: boolean }) {
  const { activeView, setActiveView } = useUIStore();
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const [openSide, setOpenSide] = useState<'left' | 'right'>('left');
  const navRef = useRef<HTMLElement>(null);
  const activeGroup = NAV_GROUPS.find((group) => group.items.some((item) => item.view === activeView));
  const activeItem = activeGroup?.items.find((item) => item.view === activeView);

  useEffect(() => {
    const dismiss = (event: PointerEvent) => {
      if (!navRef.current?.contains(event.target as Node)) setOpenGroup(null);
    };
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpenGroup(null);
    };
    document.addEventListener('pointerdown', dismiss);
    document.addEventListener('keydown', keyboard);
    return () => {
      document.removeEventListener('pointerdown', dismiss);
      document.removeEventListener('keydown', keyboard);
    };
  }, []);

  return (
    <nav ref={navRef} aria-label="Workspace navigation" className="console-shell-chrome relative z-20 flex min-h-12 shrink-0 items-center gap-1 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] px-2 py-1 sm:px-3">
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1 overflow-visible">
        {NAV_GROUPS.map((group) => {
          const selected = group.label === activeGroup?.label;
          const expanded = openGroup === group.label;
          return (
            <div className="relative shrink-0" key={group.label}>
              <button type="button" aria-haspopup="menu" aria-expanded={expanded}
                onClick={(event) => {
                  if (expanded) { setOpenGroup(null); return; }
                  const rect = event.currentTarget.getBoundingClientRect();
                  setOpenSide(window.innerWidth - rect.left >= 224 ? 'left' : 'right');
                  setOpenGroup(group.label);
                }}
                className={cn('inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm transition-colors', selected ? 'bg-[var(--accent-blue)]/12 font-medium text-[var(--accent-blue)]' : 'text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)] hover:text-[var(--text-primary)]')}>
                {group.label}<ChevronDown className={cn('h-3.5 w-3.5 transition-transform', expanded && 'rotate-180')} />
              </button>
              {expanded && <div role="menu" aria-label={`${group.label} pages`} className={cn('absolute top-full z-50 mt-1 max-h-[min(70vh,32rem)] min-w-52 overflow-y-auto overflow-x-hidden rounded-xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-1.5 shadow-xl', openSide === 'right' ? 'right-0' : 'left-0')}>
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active = activeView === item.view;
                  return <button type="button" role="menuitem" key={item.view} aria-current={active ? 'page' : undefined}
                    onClick={() => { setActiveView(item.view as any); setOpenGroup(null); }}
                    className={cn('flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm transition-colors', active ? 'bg-[var(--accent-blue)]/12 font-medium text-[var(--accent-blue)]' : 'text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)] hover:text-[var(--text-primary)]')}>
                    <Icon className="h-4 w-4 shrink-0" />{item.label}
                  </button>;
                })}
              </div>}
            </div>
          );
        })}
      </div>
      {activeItem && <div className="hidden shrink-0 items-center gap-2 border-l border-[var(--border-primary)] pl-3 text-xs text-[var(--text-secondary)] sm:flex" aria-live="polite"><span>{activeGroup?.label}</span><span aria-hidden="true">/</span><span className="font-medium text-[var(--text-primary)]">{activeItem.label}</span></div>}
    </nav>
  );
}
