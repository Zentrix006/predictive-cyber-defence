"use client";

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { Menu, Sun, Moon, Bell, Shield, AlertTriangle, Activity, Settings, ChevronLeft, X, LogIn, LogOut, LockKeyhole, Trash2 } from 'lucide-react';
import { cn } from '@/utils/classnames';
import { useUIStore } from '@/store/uiStore';
import { AccessDialog } from '@/components/auth/AccessDialog';
import { clearConsoleSession, ConsoleSession, getConsoleSession } from '@/lib/api';
import { demoApiBase } from '@/lib/demo-api';

interface HeaderProps {
  sidebarOpen: boolean;
  onToggleSidebar: () => void;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  activeIncident: any;
  connectionStatus: 'connecting' | 'connected' | 'unavailable' | 'unauthorized';
  /** Demo-2 uses its isolated range API; never open the main-console sign-in flow there. */
  demoMode?: boolean;
}

export function Header({ sidebarOpen, onToggleSidebar, theme, onToggleTheme, activeIncident, connectionStatus, demoMode = false }: HeaderProps) {
  const { notifications, addNotification, removeNotification } = useUIStore();
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [accessOpen, setAccessOpen] = useState(false);
  const [session, setSession] = useState<ConsoleSession | null>(null);
  const [rangeSummary, setRangeSummary] = useState<any>(null);
  const [cleanupBusy, setCleanupBusy] = useState(false);
  const notificationRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const refresh = () => setSession(getConsoleSession());
    refresh();
    window.addEventListener('pcd:session-changed', refresh);
    return () => window.removeEventListener('pcd:session-changed', refresh);
  }, []);
  useEffect(() => {
    if (!notificationOpen) return;
    const dismiss = (event: PointerEvent) => {
      if (!notificationRef.current?.contains(event.target as Node)) setNotificationOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setNotificationOpen(false);
        notificationRef.current?.querySelector<HTMLButtonElement>('button')?.focus();
      }
    };
    document.addEventListener('pointerdown', dismiss);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('pointerdown', dismiss);
      document.removeEventListener('keydown', escape);
    };
  }, [notificationOpen]);

  const connectionLabel = {
    connecting: 'Connecting to API',
    connected: 'API connected',
    unavailable: 'API unavailable',
    unauthorized: 'Sign-in required',
  }[connectionStatus];

  useEffect(() => {
    if (!demoMode) return;
    let cancelled = false;
    const load = async () => {
      try {
        const response = await fetch(`${demoApiBase()}/command/overview`);
        if (!response.ok) throw new Error('range unavailable');
        const data = await response.json();
        if (!cancelled) setRangeSummary(data);
      } catch {
        if (!cancelled) setRangeSummary(null);
      }
    };
    load();
    const id = window.setInterval(load, 5000);
    const refresh = () => load();
    window.addEventListener('pcd:session-changed', refresh);
    return () => {
      cancelled = true;
      window.clearInterval(id);
      window.removeEventListener('pcd:session-changed', refresh);
    };
  }, [demoMode]);

  const debrisCount = demoMode && rangeSummary ? (
    Number(rangeSummary.threats || 0) +
    Number(rangeSummary.contained || 0) +
    Number(rangeSummary.decoys || 0) +
    Number(rangeSummary.trapped || 0) +
    Number((rangeSummary.maintenance || []).length || 0)
  ) : 0;
  const cleanupAvailable = debrisCount > 0;
  const cleanupTitle = cleanupAvailable
    ? 'Clear attacker debris and preserve evidence'
    : 'No completed attack debris to clear';

  const clearDebris = async () => {
    if (!cleanupAvailable || cleanupBusy) return;
    setCleanupBusy(true);
    try {
      const response = await fetch(`${demoApiBase()}/admin/clear-debris`, { method: 'POST' });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body?.detail || 'Could not clear demo debris');
      }
      addNotification({
        type: 'success',
        message: 'Attack debris cleared. Evidence and LAN registrations are preserved.',
      });
      window.dispatchEvent(new Event('pcd:session-changed'));
    } catch (error: any) {
      addNotification({
        type: 'error',
        message: error?.message || 'Debris cleanup failed',
      });
    } finally {
      setCleanupBusy(false);
    }
  };

  const notifIcon = {
    error: <AlertTriangle className="w-3.5 h-3.5 text-[var(--accent-red)]" />,
    warning: <AlertTriangle className="w-3.5 h-3.5 text-[var(--accent-yellow)]" />,
    success: <Activity className="w-3.5 h-3.5 text-[var(--accent-green)]" />,
    info: <Bell className="w-3.5 h-3.5 text-[var(--accent-blue)]" />,
  };

  return (
    <header className={cn(
      "console-shell-chrome h-16 bg-[var(--bg-secondary)] border-b border-[var(--border-primary)] flex items-center justify-between gap-2 px-2 sm:px-4",
      "z-10 shrink-0"
    )}>
      {/* Left */}
      <div className="flex min-w-0 items-center gap-2 sm:gap-4">
        <button
          onClick={onToggleSidebar}
          className="p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors"
          aria-label={sidebarOpen ? "Close sidebar" : "Open sidebar"}
          aria-expanded={sidebarOpen}
          aria-controls="incident-sidebar"
        >
          {sidebarOpen ? <ChevronLeft className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>

        <div className="flex items-center gap-2 min-w-0">
          <span className="grid place-items-center w-8 h-8 rounded-lg bg-[var(--accent-blue)]/15 border border-[var(--accent-blue)]/30">
            <Shield className="w-4 h-4 text-[var(--accent-blue)]" />
          </span>
          <div className="min-w-0">
            <span className="block text-sm sm:text-lg font-bold text-[var(--text-primary)] truncate">Predictive Cyber Defence</span>
            <span role="status" className="flex items-center gap-1.5 text-[10px] tracking-wide text-[var(--text-secondary)]">
              <span aria-hidden="true" className={cn('w-1.5 h-1.5 rounded-full shrink-0', connectionStatus === 'connected' ? 'bg-[var(--accent-green)]' : connectionStatus === 'connecting' ? 'bg-[var(--text-muted)]' : 'bg-[var(--accent-yellow)]')} /> {connectionLabel}
            </span>
          </div>
        </div>
        
        {activeIncident && (
          <div className="hidden 2xl:flex min-w-0 max-w-xs items-center gap-2 px-3 py-1 bg-[var(--accent-red)]/20 rounded-lg border border-[var(--accent-red)]">
            <Activity className="w-4 h-4 text-[var(--accent-red)] animate-pulse" />
            <span className="truncate text-sm font-medium text-[var(--accent-red)]" title={activeIncident.title}>
              INCIDENT: {activeIncident.title}
            </span>
          </div>
        )}
      </div>
      
      {/* Right */}
      <div className="flex shrink-0 items-center gap-0 sm:gap-2">
        {!demoMode && <>
          <button onClick={() => setAccessOpen(true)} className={cn('flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs transition-colors', session?.roles.includes('admin') ? 'bg-[var(--accent-blue)]/15 text-[var(--accent-blue)]' : 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]')} title={session ? 'Manage console access' : 'Sign in'} aria-label={session?.roles.includes('admin') ? 'Manage administrator access' : session ? 'Manage view-only guest access' : 'Sign in'}>
            {session?.roles.includes('admin') ? <LockKeyhole className="h-3.5 w-3.5" /> : <LogIn className="h-3.5 w-3.5" />}<span className="hidden sm:inline">{session?.roles.includes('admin') ? 'Administrator' : session ? 'View-only guest' : 'Sign in'}</span>
          </button>
          {session && <button onClick={() => { clearConsoleSession(); setSession(null); }} className="rounded-lg p-2 text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]" title="Sign out" aria-label="Sign out"><LogOut className="h-4 w-4" /></button>}
        </>}
        {demoMode && <div className="inline-flex items-center gap-1">
          <span className="hidden sm:inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent-green)]/30 bg-[var(--accent-green)]/10 px-2.5 py-1.5 text-xs text-[var(--accent-green)]" title="Controlled Demo-2 range">
            <LockKeyhole className="h-3.5 w-3.5" /> Isolated range
          </span>
          <button
            type="button"
            onClick={clearDebris}
            disabled={!cleanupAvailable || cleanupBusy}
            title={cleanupTitle}
            aria-label="Clear post-attack debris"
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs transition-colors',
              cleanupAvailable
                ? 'border-[var(--accent-yellow)]/40 bg-[var(--accent-yellow)]/10 text-[var(--accent-yellow)] hover:bg-[var(--accent-yellow)]/15'
                : 'cursor-not-allowed border-[var(--border-primary)] bg-[var(--bg-tertiary)] text-[var(--text-muted)] opacity-60'
            )}
          >
            <Trash2 className={cn('h-3.5 w-3.5', cleanupBusy && 'animate-pulse')} />
            <span className="hidden md:inline">{cleanupBusy ? 'Clearing...' : 'Clear debris'}</span>
          </button>
        </div>}
        {/* Notifications */}
        <div className="relative" ref={notificationRef}>
          <button
            onClick={() => setNotificationOpen(!notificationOpen)}
            className="p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors relative"
            aria-label="Notifications"
            aria-expanded={notificationOpen}
            aria-controls="console-notifications"
          >
            <Bell className="w-5 h-5" />
            {notifications.length > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-[var(--accent-red)] text-white text-[10px] rounded-full flex items-center justify-center">
                {notifications.length > 99 ? '99+' : notifications.length}
              </span>
            )}
          </button>

          {notificationOpen && (
            <div id="console-notifications" aria-label="Notifications" className="fixed right-2 top-16 sm:absolute sm:right-0 sm:top-auto mt-2 w-80 max-w-[calc(100vw-1rem)] max-h-[min(24rem,70dvh)] overflow-auto bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-xl shadow-xl z-50 animate-fade-in">
              <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--border-primary)]">
                <span className="text-sm font-semibold text-[var(--text-primary)]">Notifications</span>
              </div>
              {notifications.length === 0 ? (
                <div className="p-4 text-sm text-[var(--text-muted)]">No notifications</div>
              ) : (
                <div className="p-1.5 space-y-1">
                  {[...notifications].reverse().map((n: any) => (
                    <div key={n.id} className="flex items-start gap-2 p-2 rounded-md hover:bg-[var(--bg-tertiary)]">
                      {notifIcon[(n.type as keyof typeof notifIcon)] || notifIcon.info}
                      <span className="text-xs text-[var(--text-primary)] flex-1">{n.message}</span>
                      <button
                        onClick={() => removeNotification(n.id)}
                        className="text-[var(--text-muted)] hover:text-[var(--text-primary)] shrink-0"
                        aria-label="Dismiss"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        
        {/* Theme Toggle */}
        <button
          onClick={onToggleTheme}
          className="p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors"
          aria-label={theme === 'dark' ? "Switch to light mode" : "Switch to dark mode"}
        >
          {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
        </button>
        
        {/* Settings */}
        <button
          onClick={() => useUIStore.getState().setActiveView('settings')}
          className="hidden sm:block p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors"
          aria-label="Settings"
        >
          <Settings className="w-5 h-5" />
        </button>
        <Link
          href="/lan-demo"
          className="hidden lg:inline-flex items-center gap-1.5 rounded-lg border border-[var(--accent-blue)]/25 bg-[var(--accent-blue)]/10 px-3 py-2 text-xs font-medium text-[var(--accent-blue)] hover:bg-[var(--accent-blue)]/15"
        >
          LAN demo
        </Link>
      </div>
      {!demoMode && <AccessDialog open={accessOpen} onClose={() => setAccessOpen(false)} session={session} onSession={setSession} />}
    </header>
  );
}
