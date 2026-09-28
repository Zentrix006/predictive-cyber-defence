// Same-origin calls are proxied to the backend by next.config.js. This keeps
// LAN clients from accidentally calling *their own* localhost:8000.
const API = process.env.NEXT_PUBLIC_API_URL || '/api/v1';
const TOKEN_KEY = 'pcd.access_token';
const SESSION_KEY = 'pcd.session';

export interface ConsoleSession {
  username: string;
  roles: string[];
  elevated: boolean;
  expires_in?: number;
}

export function authHeaders(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const token = window.sessionStorage.getItem(TOKEN_KEY);
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function getConsoleSession(): ConsoleSession | null {
  if (typeof window === 'undefined') return null;
  try {
    const stored = window.sessionStorage.getItem(SESSION_KEY);
    return stored ? JSON.parse(stored) as ConsoleSession : null;
  } catch {
    return null;
  }
}

export function setConsoleSession(token: string, session: ConsoleSession): void {
  window.sessionStorage.setItem(TOKEN_KEY, token);
  window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  window.dispatchEvent(new Event('pcd:session-changed'));
}

export function clearConsoleSession(): void {
  if (typeof window === 'undefined') return;
  window.sessionStorage.removeItem(TOKEN_KEY);
  window.sessionStorage.removeItem(SESSION_KEY);
  window.dispatchEvent(new Event('pcd:session-changed'));
}


/** Convert API collection responses to a safe array. Some endpoints return a
 * named envelope (for example `{ events: [...] }`), while others return arrays. */
export function toArray<T>(payload: unknown, key?: string): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (payload && typeof payload === 'object') {
    const record = payload as Record<string, unknown>;
    if (key && Array.isArray(record[key])) return record[key] as T[];
    for (const fallback of ['items', 'data', 'results']) {
      if (Array.isArray(record[fallback])) return record[fallback] as T[];
    }
  }
  return [];
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(options?.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail || body);
    } catch {
      // keep statusText
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
};

export interface ThreatActor {
  id: string;
  display_id: string;
  incident_id: string | null;
  current_asset_name: string | null;
  current_stage: string | null;
  predicted_stage: string | null;
  predicted_target_name: string | null;
  predicted_target_id: string | null;
  confidence: number;
  risk_score: number;
  response_state: string;
  source_observations: any[];
  correlated_sources: string[];
  first_seen: string;
  last_seen: string;
}

export interface ForecastStep {
  offset: number;
  stage: string;
  probability: number;
  confidence: number;
  eta_seconds: number;
  target_asset_id: string | null;
  target_asset_name: string | null;
}

export interface BeliefBranch {
  branch: number;
  confidence: number;
  target_name: string | null;
  stage: string | null;
  risk: number;
}

export interface Belief {
  branches: BeliefBranch[];
  consensus_target: string | null;
  consensus_stage: string | null;
  consensus_confidence: number;
  consensus_agreement: number;
  worst_case: { terminal_stage?: string; branch?: number; peak_infil_risk?: number } | string | null;
  chain_of_thought?: string[];
}

export interface ForecastDetail {
  incident_id: string;
  model_version: string;
  generated_at: string;
  current_state: string;
  current_stage: string;
  current_confidence: number;
  predicted_stages: string[];
  predicted_targets: any[];
  probabilities: Record<string, number>[];
  forecast_horizon: number;
  estimated_time: number[];
  confidence: number[];
  risk: number[];
  risk_level: string;
  steps: ForecastStep[];
  belief: Belief | null;
  recommended_action: string;
  recommended_actions: any[];
  explanation: any | null;
}

export interface SimulationStatus {
  active: boolean;
  scenario: string | null;
  incident_id: string | null;
  started_at: string | null;
  marker: string | null;
}

export interface HoneypotInstance {
  id: string;
  name: string;
  honeypot_type: string;
  os: string | null;
  status: string;
  ip_address: string | null;
  ports: number[];
  services: string[];
  interactions_count: number;
  detection_count: number;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  summary: string;
}

export interface NetworkState {
  asset_count: number;
  services: any[];
  users: any[];
  auth_events: any[];
  vulnerabilities: any[];
  suspicious_assets: any[];
  distressed_assets: any[];
  timestamp: string;
}

export default api;
