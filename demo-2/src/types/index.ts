/**
 * Shared TypeScript types for frontend
 */

// Asset Types
export enum AssetStatus {
  NORMAL = 'normal',
  SUSPICIOUS = 'suspicious',
  COMPROMISED = 'compromised',
  CONTAINED = 'contained',
  DECEPTION = 'deception',
  OFFLINE = 'offline',
}

export enum AssetType {
  SERVER = 'server',
  WORKSTATION = 'workstation',
  ROUTER = 'router',
  SWITCH = 'switch',
  FIREWALL = 'firewall',
  IOT_DEVICE = 'iot_device',
  HONEYPOT = 'honeypot',
  DATABASE = 'database',
  WEB_SERVER = 'web_server',
  DOMAIN_CONTROLLER = 'domain_controller',
  UNKNOWN = 'unknown',
}

export enum ZoneType {
  INTERNET = 'internet',
  DMZ = 'dmz',
  SERVER_ZONE = 'server_zone',
  USER_ZONE = 'user_zone',
  IOT_ZONE = 'iot_zone',
  MANAGEMENT = 'management',
  QUARANTINE = 'quarantine',
  HONEYNET = 'honeynet',
}

export enum CriticalityLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum IsolationLevel {
  NONE = 'none',
  QUARANTINE_VLAN = 'quarantine_vlan',
  FULL_ISOLATION = 'full_isolation',
  NETWORK_SEGMENT = 'network_segment',
}

export interface NetworkInterface {
  name: string;
  ip_addresses: string[];
  mac_address?: string;
  vlan?: number;
  speed_mbps?: number;
}

export interface TopologyNode {
  id: string;
  label: string;
  asset_id: string;
  asset_type: AssetType;
  zone: ZoneType;
  status: AssetStatus;
  threatScore: number;
  containmentLevel?: string;
  criticality: CriticalityLevel;
  position?: { x: number; y: number };
  metadata: Record<string, any>;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  protocol?: string;
  port?: number;
  bytes_transferred: number;
  packet_count: number;
  is_predicted: boolean;
  prediction_probability?: number;
  first_seen: string;
  last_seen: string;
}

export interface PredictionEdge {
  id: string;
  source: string;
  target: string;
  probability: number;
  predicted_stage: string;
  eta_seconds: number;
  created_at: string;
}

export interface NetworkTopology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  prediction_edges: PredictionEdge[];
  timestamp: string;
  incident_id?: string;
}

// Incident Types
export enum IncidentStatus {
  OPEN = 'open',
  INVESTIGATING = 'investigating',
  CONTAINED = 'contained',
  ERADICATING = 'eradicating',
  RECOVERING = 'recovering',
  CLOSED = 'closed',
}

export enum IncidentSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum AttackStage {
  RECONNAISSANCE = 'reconnaissance',
  INITIAL_ACCESS = 'initial_access',
  EXECUTION = 'execution',
  PERSISTENCE = 'persistence',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  DEFENSE_EVASION = 'defense_evasion',
  CREDENTIAL_ACCESS = 'credential_access',
  DISCOVERY = 'discovery',
  LATERAL_MOVEMENT = 'lateral_movement',
  COLLECTION = 'collection',
  COMMAND_AND_CONTROL = 'command_and_control',
  EXFILTRATION = 'exfiltration',
  IMPACT = 'impact',
}

export interface TimelineEvent {
  id: string;
  incident_id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description?: string;
  severity: IncidentSeverity;
  source: string;
  asset_ids: string[];
  metadata: Record<string, any>;
  prediction_id?: string;
}

export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  source: string;
  source_reference?: string;
  detected_at: string;
  assigned_to?: string;
  current_stage?: AttackStage;
  threat_score: number;
  closed_at?: string;
  closure_reason?: string;
  tags: string[];
  metadata: Record<string, any>;
  assets_involved: string[];
  created_at: string;
  updated_at: string;
}

// Prediction Types
export interface ForecastWindow {
  window_offset: number;
  stage: AttackStage;
  probability: number;
  target_asset_id?: string;
  target_asset_name?: string;
  eta_seconds: number;
  confidence: number;
}

export interface PredictedTarget {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  probability: number;
  reasoning: string[];
}

export interface FactorContribution {
  factor: string;
  contribution: number;
  description: string;
}

export interface Explanation {
  feature_importance: Record<string, number>;
  top_factors: FactorContribution[];
  natural_language: string;
  attention_visualization?: Record<string, any>;
}

export interface ModelDecision {
  action: string;
  action_type: string;
  risk_reduction_pct: number;
  jepa_surprisal: number;
  is_novel_behavior: boolean;
  decision_confidence: number;
  target_stage: string;
  branches_evaluated: number;
  worst_case_branch?: {
    terminal_stage?: string;
    branch_index?: number;
    risk_score?: number;
  };
  rollback_armed: boolean;
  vendor_diff: string;
  divert_target?: string;
  source_node?: string;
  target_node?: string;
}

export interface AttackForecast {
  incident_id: string;
  current_stage: AttackStage;
  current_confidence: number;
  timeline: ForecastWindow[];
  predicted_targets: PredictedTarget[];
  explanation: Explanation;
  generated_at: string;
  model_version: string;
  model_decision?: ModelDecision;
  thinking?: Record<string, any>;
  novelty?: any;
  recommended_action?: string;
  recommended_actions?: any[];
}

// Deception Types
export enum HoneypotType {
  WEB = 'web',
  SSH = 'ssh',
  DATABASE = 'database',
  SMB = 'smb',
  FTP = 'ftp',
  IOT = 'iot',
  CUSTOM = 'custom',
}

export enum DeploymentStatus {
  PENDING = 'pending',
  DEPLOYING = 'deploying',
  ACTIVE = 'active',
  TEARING_DOWN = 'tearing_down',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export interface HoneypotTemplate {
  id: string;
  name: string;
  honeypot_type: HoneypotType;
  description: string;
  docker_image: string;
  ports: number[];
  environment: Record<string, string>;
  volumes: string[];
  resource_limits: Record<string, any>;
  decoy_files: string[];
  credentials: Record<string, string>[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DeceptionDeployment {
  id: string;
  incident_id: string;
  name: string;
  honeypot_types: HoneypotType[];
  target_assets: string[];
  predicted_stage: string;
  status: DeploymentStatus;
  container_ids: string[];
  network_config: Record<string, any>;
  deployed_at?: string;
  torn_down_at?: string;
  interactions_count: number;
}

export interface HoneypotInteraction {
  id: string;
  deployment_id: string;
  honeypot_type: HoneypotType;
  container_id: string;
  timestamp: string;
  source_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  action: string;
  details: Record<string, any>;
  severity: string;
  mitre_techniques: string[];
}

// Forensics Types
export enum EvidenceType {
  PCAP = 'pcap',
  LOG = 'log',
  FILE_EVENT = 'file_event',
  MEMORY_DUMP = 'memory_dump',
  DISK_IMAGE = 'disk_image',
  CONFIG_SNAPSHOT = 'config_snapshot',
  NETWORK_FLOW = 'network_flow',
  HONEYPOT_INTERACTION = 'honeypot_interaction',
}

export enum FileEventAction {
  DISCOVERED = 'discovered',
  READ = 'read',
  MODIFIED = 'modified',
  COPIED = 'copied',
  DELETED = 'deleted',
  EXFILTRATED = 'exfiltrated',
  ENCRYPTED = 'encrypted',
}

export interface Evidence {
  id: string;
  incident_id: string;
  evidence_type: EvidenceType;
  name: string;
  description?: string;
  source_asset_id?: string;
  size_bytes: number;
  sha256_hash: string;
  collection_method: string;
  collected_at: string;
  storage_path: string;
  is_verified: boolean;
}

export interface FileEvent {
  id: string;
  incident_id: string;
  asset_id: string;
  file_path: string;
  file_hash?: string;
  action: FileEventAction;
  timestamp: string;
  process_name?: string;
  process_id?: number;
  user?: string;
  metadata: Record<string, any>;
  was_read: boolean;
  was_modified: boolean;
  was_copied: boolean;
  was_deleted: boolean;
  was_exfiltrated: boolean;
  exfiltration_destination?: string;
}

export interface ConfigSnapshot {
  id: string;
  incident_id: string;
  label: string;
  description: string;
  snapshot_type: string;
  configuration: Record<string, any>;
  sha256_hash: string;
  created_at: string;
  applied_at?: string;
}

// WebSocket Types
export enum WSEventType {
  ASSET_STATUS_CHANGED = 'asset_status_changed',
  CONNECTION_ADDED = 'connection_added',
  CONNECTION_REMOVED = 'connection_removed',
  TOPOLOGY_UPDATED = 'topology_updated',
  PREDICTION_GENERATED = 'prediction_generated',
  FORECAST_UPDATED = 'forecast_updated',
  STAGE_TRANSITION = 'stage_transition',
  INCIDENT_CREATED = 'incident_created',
  INCIDENT_UPDATED = 'incident_updated',
  INCIDENT_CLOSED = 'incident_closed',
  HONEYPOT_DEPLOYED = 'honeypot_deployed',
  HONEYPOT_INTERACTION = 'honeypot_interaction',
  HONEYPOT_REMOVED = 'honeypot_removed',
  HOST_ISOLATED = 'host_isolated',
  HOST_RESTORED = 'host_restored',
  TRAFFIC_BLOCKED = 'traffic_blocked',
  SNAPSHOT_CREATED = 'snapshot_created',
  CONFIG_APPLIED = 'config_applied',
  EVIDENCE_COLLECTED = 'evidence_collected',
  TIMELINE_UPDATED = 'timeline_updated',
}

export interface WSEvent {
  event: WSEventType;
  timestamp: string;
  incident_id?: string;
  payload: any;
}