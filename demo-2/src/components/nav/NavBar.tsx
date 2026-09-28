"use client";

import {
  LayoutDashboard,
  TrendingUp,
  Users,
  ShieldAlert,
  FileSearch,
  Network,
  FlaskConical,
  Brain,
  Settings,
  MonitorPlay,
  Cpu,
  Network as GraphIcon,
  FileSearch as PassiveIcon,
} from 'lucide-react';
import { useUIStore } from '@/store/uiStore';
import { cn } from '@/utils/classnames';

const NAV_ITEMS: { view: string; label: string; icon: any }[] = [
  { view: 'command-center', label: 'Command Center', icon: LayoutDashboard },
  { view: 'mitigation-cache', label: 'Mitigation Cache', icon: Cpu },
  { view: 'presentation', label: 'Executive Demo', icon: MonitorPlay },
  { view: 'attack', label: 'Attack Forecast', icon: TrendingUp },
  { view: 'threat-actors', label: 'Threat Actors', icon: Users },
  { view: 'deception', label: 'Deception', icon: ShieldAlert },
  { view: 'forensics', label: 'Forensics', icon: FileSearch },
  { view: 'infrastructure', label: 'Infrastructure', icon: Network },
  { view: 'ai-intelligence', label: 'AI Intelligence', icon: Brain },
  { view: 'model-lab', label: 'Model Lab', icon: FlaskConical },
  { view: 'graph-analysis', label: 'Graph Analysis', icon: GraphIcon },
  { view: 'passive-analysis', label: 'Passive Analysis', icon: PassiveIcon },
  { view: 'settings', label: 'Settings', icon: Settings },
];

export function NavBar({ demoMode = false }: { demoMode?: boolean }) {
  const { activeView, setActiveView } = useUIStore();
  // Demo-2 intentionally retains the complete operations workspace. Each
  // screen is backed by the isolated Demo-2 API, never by the main console.
  const items = NAV_ITEMS;

  return (
    <nav aria-label="Workspace navigation" className="console-shell-chrome shrink-0 flex items-center gap-1 px-3 py-1.5 bg-[var(--bg-secondary)] border-b border-[var(--border-primary)] overflow-x-auto">
      {items.map((item) => {
        const active = activeView === item.view;
        const Icon = item.icon;
        return (
          <button
            key={item.view}
            onClick={() => setActiveView(item.view as any)}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'flex items-center gap-2 px-3 py-2 rounded-lg text-sm whitespace-nowrap transition-colors',
              active
                ? 'bg-[var(--accent-blue)]/15 text-[var(--accent-blue)] font-medium'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]'
            )}
          >
            <Icon className="w-4 h-4" />
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}
