"use client";

import { FormEvent, useEffect, useRef, useState } from 'react';
import { KeyRound, ShieldCheck, UserRound, X } from 'lucide-react';
import api, { ConsoleSession, setConsoleSession } from '@/lib/api';

type LoginResponse = { access_token: string; username: string; roles: string[]; elevated: boolean; expires_in: number };

export function AccessDialog({ open, onClose, session, onSession }: {
  open: boolean; onClose: () => void; session: ConsoleSession | null; onSession: (value: ConsoleSession | null) => void;
}) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    setError(null);
    const dialog = dialogRef.current;
    (dialog?.querySelector<HTMLElement>('input[type="password"]') ?? dialog?.querySelector<HTMLElement>('button'))?.focus();
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); closeRef.current(); }
      if (event.key !== 'Tab') return;
      const controls = dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), [tabindex="0"]');
      if (!controls?.length) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', keyboard);
    return () => {
      document.removeEventListener('keydown', keyboard);
      setPassword('');
      previous?.focus();
    };
  }, [open]);

  if (!open) return null;

  const save = (response: LoginResponse) => {
    const next: ConsoleSession = { username: response.username, roles: response.roles, elevated: response.elevated, expires_in: response.expires_in };
    setConsoleSession(response.access_token, next);
    onSession(next);
    setPassword('');
    setError(null);
  };

  const loginAdmin = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError(null);
    try { save(await api.post<LoginResponse>('/auth/login', { username: 'dev', password })); onClose(); } catch (err: any) { setError(err?.message || 'Sign in failed'); } finally { setBusy(false); }
  };
  const guest = async () => {
    setBusy(true); setError(null);
    try { save(await api.post<LoginResponse>('/auth/guest')); onClose(); } catch (err: any) { setError(err?.message || 'Guest access failed'); } finally { setBusy(false); }
  };
  return (
    <div ref={dialogRef} className="console-shell-chrome fixed inset-0 z-[70] grid place-items-center overflow-y-auto bg-black/65 p-4" role="dialog" aria-modal="true" aria-labelledby="console-access-title" aria-describedby="console-access-description">
      <div className="my-auto w-full max-w-md rounded-2xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-[var(--border-primary)] p-5">
          <div className="flex gap-3">
            <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-[var(--accent-blue)]/15 text-[var(--accent-blue)]"><ShieldCheck className="h-5 w-5" /></span>
            <div>
              <h2 id="console-access-title" className="font-semibold text-[var(--text-primary)]">Console access</h2>
              <p id="console-access-description" className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">Use an administrator account for console controls. Guests can view dashboards and evidence.</p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close console access" className="shrink-0 rounded-lg p-2 text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]"><X className="h-5 w-5" /></button>
        </div>
        <div className="p-5">
          {session?.roles.includes('admin') ? (
            <div role="status" className="rounded-lg border border-[var(--accent-green)]/30 bg-[var(--accent-green)]/10 p-4 text-sm text-[var(--accent-green)]">Signed in as {session.username}. Administrator controls are available.</div>
          ) : (
            <>
              {session && <p className="mb-4 rounded-lg bg-[var(--bg-tertiary)] p-3 text-sm text-[var(--text-secondary)]">You are using a view-only guest session.</p>}
              <form onSubmit={loginAdmin} className="space-y-3" aria-busy={busy}>
                <label className="block text-sm text-[var(--text-secondary)]">Administrator ID
                  <input value="dev" readOnly autoComplete="username" name="username" className="mt-1.5 w-full rounded-lg border border-[var(--border-primary)] bg-[var(--bg-tertiary)] px-3 py-2 text-[var(--text-secondary)]" />
                </label>
                <label className="block text-sm text-[var(--text-secondary)]">Password
                  <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" name="password" required disabled={busy} aria-invalid={Boolean(error)} aria-describedby={error ? 'console-access-error' : undefined} className="mt-1.5 w-full rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)] px-3 py-2 text-[var(--text-primary)]" />
                </label>
                <button disabled={busy} className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-700 px-3 py-2 text-sm font-medium text-white hover:bg-sky-800 disabled:opacity-60"><KeyRound className="h-4 w-4" />{busy ? 'Signing in…' : 'Sign in as administrator'}</button>
              </form>
              <div className="my-4 flex items-center gap-3 text-xs text-[var(--text-secondary)]"><span className="h-px flex-1 bg-[var(--border-primary)]" />or<span className="h-px flex-1 bg-[var(--border-primary)]" /></div>
              <button onClick={guest} disabled={busy} className="flex w-full items-center justify-center gap-2 rounded-lg border border-[var(--border-primary)] px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] disabled:opacity-60"><UserRound className="h-4 w-4" />Continue as view-only guest</button>
            </>
          )}
          {error && <p id="console-access-error" role="alert" className="mt-3 text-xs text-[var(--accent-red)]">{error}</p>}
        </div>
      </div>
    </div>
  );
}
