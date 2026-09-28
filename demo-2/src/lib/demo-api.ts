export type DemoRole = 'attacker' | 'observer' | 'server' | 'host' | 'client' | 'other';

export function demoApiBase(): string {
  if (typeof window !== 'undefined') return `http://${window.location.hostname}:8100/api/demo`;
  return process.env.NEXT_PUBLIC_DEMO_API_URL || 'http://localhost:8100/api/demo';
}

export async function demoRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${demoApiBase()}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* retain status */ }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export type DemoSession = { participant_id: string; role: DemoRole; token: string; asset_id?: string | null; hostname?: string };
const SESSION_KEY = 'demo2.range.session';

export function getDemoSession(): DemoSession | null {
  if (typeof window === 'undefined') return null;
  try { const raw = sessionStorage.getItem(SESSION_KEY); return raw ? JSON.parse(raw) : null; } catch { return null; }
}

export function saveDemoSession(session: DemoSession) { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); }
