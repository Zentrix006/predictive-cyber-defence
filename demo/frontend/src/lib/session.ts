import type { Role } from "./api";

const K = "demo:session";

export type Session = {
  participant_id: string;
  role: Role;
  token: string;
  asset_id?: string | null;
  page_endpoint?: string | null;
  hostname?: string;
  device_type?: string;
};

export function getSession(): Session | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(K);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

export function saveSession(s: Session) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(K, JSON.stringify(s));
}

export function clearSession() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(K);
}