// Public API base the browser uses. Prefer the host the page was served from
// (so phones on the LAN resolve the same machine), falling back to an explicit
// env override, then localhost for pure local development.
const API = typeof window !== "undefined"
  ? `http://${window.location.hostname}:8100/api/demo`
  : process.env.NEXT_PUBLIC_DEMO_API_URL || "http://localhost:8100/api/demo";

export class DemoError extends Error {
  status: number;
  constructor(status: number, msg: string) {
    super(msg);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new DemoError(res.status, detail);
  }
  return (await res.json()) as T;
}

const q = (obj: Record<string, string | number | boolean | undefined>) => {
  const sp = new URLSearchParams();
  Object.entries(obj).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  });
  const s = sp.toString();
  return s ? `?${s}` : "";
};

export type Role = "attacker" | "host" | "server" | "client" | "other" | "observer";

export type DeviceContext = {
  category?: string;
  platform?: string;
  browser?: string;
  language?: string;
  timestamp?: string;
};

export type JoinResp = {
  participant_id: string;
  role: Role;
  token: string;
  device_context: DeviceContext;
  asset_id?: string | null;
  page_endpoint?: string | null;
  hostname?: string;
  device_type?: string;
};

export type AssetInfo = {
  id: string;
  hostname: string;
  name?: string;
  role: string;
  status: string;
  service?: string;
  ip?: string;
  asset_type?: string;
  isolated?: boolean;
  trap?: boolean;
};

export type DeviceService = {
  domain: string;
  serving: boolean;
  fallback: string | null;
  status: "serving" | "down" | "na";
};

export type MaintenanceInfo = {
  asset: string;
  name?: string;
  job: string;
  since?: string;
  recoverable: boolean;
  degraded?: boolean;
  checks?: { check: string; label: string; verdict: string; at?: string }[];
  data_loss?: {
    severity?: string;
    estimated_records_at_risk?: number;
    data_classes?: string[];
    exposure_window_seconds?: number;
    attribution_signals?: number;
    note?: string;
    records_estimated?: number;
    exposure_minutes?: number;
  };
};

export type AssetState = {
  id: string;
  hostname: string;
  status: string;
  role: string;
  service?: string | DeviceService;
  asset_type?: string;
  ip?: string;
  zone?: string;
  registered?: boolean;
  page_endpoint?: string;
  predicted_target?: boolean;
  contained?: boolean;
  trapped?: boolean;
  maintenance?: MaintenanceInfo | null;
  deception_active?: boolean;
  stage?: string | null;
  actor?: string | null;
  last_seen?: string | null;
};

export type Forecast = {
  incident_id?: string;
  model: string;
  current_stage: string;
  predicted_stages: string[];
  predicted_target?: string;
  confidence: number;
  risk_score: number;
  risk_level: string;
  lead_time?: number;
  belief: { branches: { branch: number; confidence: number; target?: string; stage?: string; risk: number }[]; consensus?: string; agreement?: number; chain_of_thought?: string[] };
  explanation?: { natural_language?: string; top_factors?: { feature: string; contribution: number }[] };
};

export type ServiceStatus = {
  domain: string;
  replicas: number;
  serving: number;
  serving_ids: string[];
  fallback: string | null;
  status: "serving" | "down" | "na";
  client_load?: Record<string, number>;
  client_edges?: Record<string, string>;
  continuity?: {
    real: number;
    real_serving: number;
    honeypot: number;
  };
  backups?: {
    count: number;
    recent: { asset: string; snapshot: string }[];
  };
  restores?: number;
};

export type Overview = {
  simulation: boolean;
  mode: string;
  threats: number;
  contained: number;
  decoys: number;
  trapped: number;
  maintenance: MaintenanceInfo[];
  healthy: number;
  assets: number;
  online_assets: number;
  participants: number;
  participants_total: number;
  attackers: number;
  attackers_total: number;
  incident: {
    id?: string | null;
    status?: string | null;
    stage?: string | null;
    level?: number;
    origin?: string | null;
    predicted_target?: string | null;
    predicted_target_id?: string | null;
    deception?: boolean;
    decoy?: string | null;
    actor?: string | null;
    pivot_count?: number;
    trapped?: boolean;
    prediction?: Forecast | null;
  } | null;
  incidents: {
    id: string;
    status: string;
    stage: string;
    level: number;
    origin: string | null;
    predicted_target: string | null;
    predicted_target_id: string | null;
    deception: boolean;
    decoy: string | null;
    actor: string | null;
    pivot_count: number;
    trapped: boolean;
    prediction: Forecast | null;
  }[];
  actors: {
    actor: string;
    incident_id: string;
    origin: string | null;
    stage: string;
    level: number;
    predicted_target: string | null;
    predicted_target_id: string | null;
    deception: boolean;
    decoy: string | null;
    status: string;
    pivot_count: number;
    trapped: boolean;
    risk_level?: string;
    risk_score?: number;
    confidence?: number;
    converging?: boolean;
    prediction?: Forecast | null;
  }[];
  convergence: {
    target: string;
    actors: string[];
    incidents: string[];
    risk_score: number;
    risk_level: string;
  }[];
  service: ServiceStatus;
  prediction: Forecast | null;
  evidence_count: number;
};

export type TopologyNode = {
  id: string;
  label: string;
  type: "asset" | "infra" | "attacker" | "forecast";
  asset_type?: string;
  role?: string;
  status?: string;
  ip?: string;
  criticality?: string;
  zone?: string;
  bait?: boolean;
  ring_of?: string;
  capture_of?: string;
  presented_as?: string;
  forecast_of?: string;
  serving?: boolean;
  recovering?: boolean;
  last_restore_at?: string;
  meta?: { incident?: string; monitoring?: boolean; pivot?: number };
};

export type TopologyEdge = {
  source: string;
  target: string;
  kind?: string;
  flow?: number;
  actor_id?: string;
  confidence?: number;
};

export type ActorBrief = {
  actor: string;
  incident_id: string;
  origin: string | null;
  origin_name?: string | null;
  origin_status?: string | null;
  stage: string;
  status: string;
  trapped: boolean;
  deception_active?: boolean;
  monitoring?: boolean;
  predicted_target_id?: string | null;
  predicted_target?: string | null;
  pivot_count: number;
  confidence?: number | null;
  risk_score?: number | null;
  risk_level?: string | null;
};

export type ContainerBrief = {
  asset_id: string;
  name?: string | null;
  actor: string;
  incident_id: string;
  contained: boolean;
};

export type DeceptionBrief = {
  decoy_id: string;
  decoy_name: string;
  incident_id: string;
  actor: string;
  predicted_target_id?: string | null;
  predicted_target?: string | null;
  status: string;
  stage: string;
  explanation?: unknown;
};

export type AssetBrief = {
  id: string;
  name: string;
  role: string;
  asset_type: string;
  status: string;
  zone?: string;
  ip?: string;
  criticality?: string;
  registered: boolean;
  decoy: boolean;
  service?: string;
};

export type ConvGroup = {
  target: string;
  target_name?: string | null;
  incident_ids: string[];
  actors: {
    actor: string;
    incident_id: string;
    stage: string;
    confidence?: number | null;
    risk_score?: number | null;
    risk_level?: string | null;
  }[];
  count: number;
  aggregate_risk_score?: number | null;
  aggregate_risk_level?: string | null;
  correlation_id?: string | null;
};

export type Topology = {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  predictions?: Forecast[];
  actors?: ActorBrief[];
  containment?: ContainerBrief[];
  deception?: DeceptionBrief[];
  assets?: AssetBrief[];
  infrastructure?: TopologyNode[];
  services?: ServiceStatus;
  convergence?: ConvGroup[];
};

export type Health = {
  db: boolean;
  model: boolean;
  model_version: string;
  feature_dim: number;
  sse: boolean;
  simulation: boolean;
  ts: string;
};

export type AiObservability = {
  generated_at: string;
  model: { ready: boolean; version?: string; feature_dim: number; kind: string; serving_checkpoint: string };
  range: { real_devices: number; live_telemetry_events: number; simulation: boolean; scanner: string };
  training: {
    demo_records: number;
    candidate?: any;
    promotion: string;
    status?: {
      status?: string;
      phase?: string;
      progress_percent?: number;
      eta_minutes?: number | null;
      resolved_device?: string | null;
      device_preference?: string;
      message?: string;
      error?: string | null;
      plan?: any;
      steps?: { phase: string; label: string; percent: number; eta_minutes: number }[];
    };
    plan?: {
      status?: string;
      phase?: string;
      progress_percent?: number;
      eta_minutes?: number | null;
      device_strategy?: { preferred?: string; fallback_order?: string[]; cuda_available?: boolean; cpu_available?: boolean; description?: string };
      records?: number;
      schema_requirements?: { name: string; required_fields: string[]; sources: string[] }[];
      expected_improvement?: string[];
      current_metrics?: { model_version?: string; stage_accuracy?: number | null; infiltration_accuracy?: number | null; macro_f1?: number | null; validation_loss?: number | null };
      steps?: { phase: string; label: string; percent: number; eta_minutes: number }[];
    };
  };
  schema_intake: { status: string; started_at?: string; completed_at?: string; sources: any[]; errors: any[]; manifest?: any };
  knowledge_flow: { label: string; detail: string }[];
};

export type DemoTimelineItem = {
  event_id: string;
  kind: string;
  timestamp: string;
  incident_id?: string;
  simulation: boolean;
  source: string;
  payload: Record<string, unknown>;
};

export type ParticipantScore = {
  participant_id: string;
  role: string;
  browser?: string | null;
  platform?: string | null;
  asset_id?: string | null;
  asset_role?: string | null;
  asset_status?: string | null;
  online: boolean;
  engaged: boolean;
  score: number;
  level: string;
  chips: string[];
  last_seen?: string | null;
  joined: string;
};

export type ParticipantBoard = {
  participants: ParticipantScore[];
  live: number;
  max_score: number;
};

export const demoApi = {
  join: (role: Role) => request<JoinResp>(`/join${q({ role })}`, { method: "POST" }),
  config: () => request<{ name: string; mode: string; simulation: boolean; roles: Role[]; join_url: string; public_base_url?: string }>("/config"),
  attackerOptions: (token: string) => request<{ targets: AssetInfo[] }>(`/attacker/options${q({ token })}`),
  attackerStart: (token: string, target: string) =>
    request<any>(`/attacker/start${q({ token, target })}`, { method: "POST" }),
  attackerAnswer: (token: string, incident_id: string, answer: string) =>
    request<any>(`/attacker/answer${q({ token, incident_id, answer })}`, { method: "POST" }),
  attackerState: (token: string) => request<any>(`/attacker/state${q({ token })}`),
  attackerPivotOptions: (token: string) =>
    request<any>(`/attacker/pivot-options${q({ token })}`),
  attackerPivot: (token: string, incident_id: string, target: string) =>
    request<any>(`/attacker/pivot${q({ token, incident_id, target })}`, { method: "POST" }),
  threatActors: () => request<any>("/threat/actors"),
  threatActor: (actorId: string) => request<any>(`/threat/actors/${actorId}`),
  threatTrajectory: (actorId: string) => request<any>(`/threat/trajectories/${actorId}`),
  decoyQuestions: (token: string) => request<{ questions: { question: string }[] }>(`/decoy/questions${q({ token })}`),
  decoyInteract: (token: string, incident_id: string, answers: unknown[], context?: Record<string, string | number | null | undefined>) =>
    request<any>(`/decoy/interact${q({ token, incident_id })}`, {
      method: "POST",
      body: JSON.stringify({ answers, context }),
    }),
  assets: () => request<AssetInfo[]>("/assets"),
  assetState: (id: string) => request<AssetState>(`/asset/${encodeURIComponent(id)}/state`),
  deviceRegister: (body: Record<string, string | undefined>) =>
    request<any>("/device/register", { method: "POST", body: JSON.stringify(body) }),
  heartbeat: (body: Record<string, string | undefined>) =>
    request<any>("/heartbeat", { method: "POST", body: JSON.stringify(body) }),
  overview: () => request<Overview>("/command/overview"),
  topology: () => request<Topology>("/command/topology"),
  health: () => request<Health>("/command/health"),
  timeline: (limit = 60) => request<DemoTimelineItem[]>(`/command/timeline${q({ limit })}`),
  participants: () => request<ParticipantBoard>("/command/participants"),
  forecast: () => request<{ incident: any; prediction: Forecast | null }>("/command/forecast"),
  threats: () => request<{ actors: any[]; converging: any[] }>("/command/threats"),
  ai: () => request<AiObservability>("/ai/observability"),
  evidence: (incident_id?: string) =>
    request<any[]>(`/forensics/evidence${incident_id ? q({ incident_id }) : ""}`),
  admin: {
    health: (pin: string) => request<any>(`/admin/health`, { headers: { "x-demo-admin-pin": pin } }),
    start: (pin: string) => request<any>("/admin/start", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    reset: (pin: string, clear = false) =>
      request<any>(`/admin/reset${q({ clear_logs: clear })}`, { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    deception: (pin: string) =>
      request<any>("/admin/deception", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    rollback: (pin: string) => request<any>("/admin/rollback", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    restore: (pin: string, assetId: string, force = false) =>
      request<any>(`/admin/restore${q({ asset_id: assetId, force })}`, { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    maintenanceDiagnose: (pin: string, assetId: string) =>
      request<any>(`/admin/maintenance/${encodeURIComponent(assetId)}/diagnose`, { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    maintenanceRelease: (pin: string, assetId: string) =>
      request<any>(`/admin/maintenance/${encodeURIComponent(assetId)}/release`, { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    exportTraining: (pin: string) =>
      request<any>("/admin/export-training", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    scanSchemas: (pin: string) =>
      request<any>("/admin/ai/schema-scan", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    prepareTraining: (pin: string) =>
      request<any>("/admin/ai/prepare-training", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    trainAI: (pin: string) =>
      request<any>("/admin/ai/train", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    clear: (pin: string) => request<any>("/admin/clear", { method: "POST", headers: { "x-demo-admin-pin": pin } }),
    participants: (pin: string) => request<any[]>("/admin/participants", { headers: { "x-demo-admin-pin": pin } }),
    devices: (pin: string, opts?: { include_offline?: boolean; include_decoys?: boolean }) => {
      const q = new URLSearchParams();
      if (opts?.include_offline) q.set("include_offline", "true");
      if (opts?.include_decoys) q.set("include_decoys", "true");
      const qs = q.toString();
      return request<{ devices: any[]; online?: number; offline_total?: number; include_offline?: boolean }>(
        `/admin/devices${qs ? `?${qs}` : ""}`,
        { headers: { "x-demo-admin-pin": pin } },
      );
    },
  },
};
