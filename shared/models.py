"""
Shared Pydantic models for backend-frontend communication.
Single source of truth for all data contracts.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# ENUMS
# ============================================================================

class AssetStatus(str, Enum):
    NORMAL = "normal"           # 🟢 Green
    SUSPICIOUS = "suspicious"   # 🟡 Yellow
    COMPROMISED = "compromised" # 🔴 Red
    CONTAINED = "contained"     # 🔵 Blue
    DECEPTION = "deception"     # 🟣 Purple
    OFFLINE = "offline"         # ⚫ Black


class AssetType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    IOT_DEVICE = "iot_device"
    HONEYPOT = "honeypot"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    DOMAIN_CONTROLLER = "domain_controller"
    UNKNOWN = "unknown"


class ZoneType(str, Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    SERVER_ZONE = "server_zone"
    USER_ZONE = "user_zone"
    IOT_ZONE = "iot_zone"
    MANAGEMENT = "management"
    QUARANTINE = "quarantine"
    HONEYNET = "honeynet"


class CriticalityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackStage(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    CONTAIN = "contain"
    DECEIVE = "deceive"
    MONITOR = "monitor"
    BLOCK = "block"
    ALERT = "alert"
    ISOLATE_NETWORK = "isolate_network"
    CAPTURE_PCAP = "capture_pcap"
    COLLECT_LOGS = "collect_logs"
    SNAPSHOT_CONFIG = "snapshot_config"


class IsolationLevel(str, Enum):
    NONE = "none"
    QUARANTINE_VLAN = "quarantine_vlan"
    FULL_ISOLATION = "full_isolation"
    NETWORK_SEGMENT = "network_segment"


class HoneypotType(str, Enum):
    WEB = "web"
    SSH = "ssh"
    DATABASE = "database"
    SMB = "smb"
    FTP = "ftp"
    IOT = "iot"
    CUSTOM = "custom"


class DeploymentStatus(str, Enum):
    PENDING = "pending"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    TEARING_DOWN = "tearing_down"
    COMPLETED = "completed"
    FAILED = "failed"


class EvidenceType(str, Enum):
    PCAP = "pcap"
    LOG = "log"
    FILE_EVENT = "file_event"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    CONFIG_SNAPSHOT = "config_snapshot"
    NETWORK_FLOW = "network_flow"
    HONEYPOT_INTERACTION = "honeypot_interaction"


class FileEventAction(str, Enum):
    DISCOVERED = "discovered"
    READ = "read"
    MODIFIED = "modified"
    COPIED = "copied"
    DELETED = "deleted"
    EXFILTRATED = "exfiltrated"
    ENCRYPTED = "encrypted"


# ============================================================================
# BASE MODELS
# ============================================================================

class TimestampedModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IDModel(BaseModel):
    id: UUID = Field(default_factory=uuid4)


# ============================================================================
# NETWORK TOPOLOGY MODELS
# ============================================================================

class NetworkInterface(BaseModel):
    name: str
    ip_addresses: list[str] = Field(default_factory=list)
    mac_address: str | None = None
    vlan: int | None = None
    speed_mbps: int | None = None


class AssetBase(BaseModel):
    hostname: str
    ip_address: str
    asset_type: AssetType
    zone: ZoneType
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    os: str | None = None
    os_version: str | None = None
    interfaces: list[NetworkInterface] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Asset(AssetBase, IDModel, TimestampedModel):
    status: AssetStatus = AssetStatus.NORMAL
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    last_seen: datetime | None = None
    incident_id: UUID | None = None
    containment_level: IsolationLevel = IsolationLevel.NONE
    deception_deployment_id: UUID | None = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    asset_type: AssetType | None = None
    zone: ZoneType | None = None
    criticality: CriticalityLevel | None = None
    os: str | None = None
    os_version: str | None = None
    tags: list[str] | None = None
    metadata: dict[str, Any] | None = None


class TopologyNode(BaseModel):
    id: str
    label: str
    asset_id: UUID
    asset_type: AssetType
    zone: ZoneType
    status: AssetStatus
    threat_score: float
    criticality: CriticalityLevel
    position: dict[str, float] | None = None  # x, y
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    id: str
    source: str
    target: str
    protocol: str | None = None
    port: int | None = None
    bytes_transferred: int = 0
    packet_count: int = 0
    is_predicted: bool = False
    prediction_probability: float | None = None
    first_seen: datetime
    last_seen: datetime


class NetworkTopology(BaseModel):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    timestamp: datetime
    incident_id: UUID | None = None


class PredictionEdge(BaseModel):
    id: str
    source: str
    target: str
    probability: float
    predicted_stage: AttackStage
    eta_seconds: float
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# NETWORK STATE MODELS (for World Model)
# ============================================================================

class HostState(BaseModel):
    asset_id: UUID
    hostname: str
    ip: str
    active_connections: int
    suspicious_flows: int
    blocked_flows: int
    auth_failures: int
    process_count: int
    cpu_usage: float
    memory_usage: float
    disk_io: float
    network_io: float


class ConnectionState(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: str  # ESTABLISHED, SYN_SENT, etc.
    bytes: int
    packets: int
    duration: float
    flags: str


class TrafficStatistics(BaseModel):
    total_flows: int
    total_bytes: int
    total_packets: int
    unique_src_ips: int
    unique_dst_ips: int
    unique_ports: int
    tcp_syn_rate: float
    udp_rate: float
    icmp_rate: float
    avg_flow_duration: float
    entropy_src_port: float
    entropy_dst_port: float


class NetworkState(BaseModel):
    timestamp: datetime
    window_start: datetime
    window_end: datetime
    window_size_seconds: int
    hosts: dict[str, HostState]
    connections: list[ConnectionState]
    traffic_stats: TrafficStatistics
    feature_vector: list[float]  # Flattened for ML


# ============================================================================
# WORLD MODEL / PREDICTION MODELS
# ============================================================================

class PredictedState(BaseModel):
    window_offset: int  # 1, 2, 3, 4
    timestamp: datetime
    feature_vector: list[float]
    host_predictions: dict[str, dict]  # Predicted host states
    confidence: float


class TransitionPrediction(BaseModel):
    current_state: NetworkState
    predicted_next_state: PredictedState
    transition_probability: float
    attention_weights: dict[str, float] | None = None


class ForecastWindow(BaseModel):
    window_offset: int
    stage: AttackStage
    probability: float
    target_asset_id: UUID | None = None
    target_asset_name: str | None = None
    eta_seconds: float
    confidence: float


class PredictedTarget(BaseModel):
    asset_id: UUID
    asset_name: str
    asset_type: AssetType
    probability: float
    reasoning: list[str]


class Explanation(BaseModel):
    feature_importance: dict[str, float]  # feature_name -> importance
    top_factors: list[FactorContribution]
    natural_language: str
    attention_visualization: dict[str, Any] | None = None


class FactorContribution(BaseModel):
    factor: str
    contribution: float  # 0-1
    description: str


class AttackForecast(BaseModel):
    incident_id: UUID
    current_stage: AttackStage
    current_confidence: float
    timeline: list[ForecastWindow]
    predicted_targets: list[PredictedTarget]
    explanation: Explanation
    generated_at: datetime
    model_version: str


# ============================================================================
# INCIDENT MODELS
# ============================================================================

class IncidentBase(BaseModel):
    title: str
    description: str | None = None
    severity: IncidentSeverity
    source: str  # "auto", "manual", "alert"
    source_reference: str | None = None  # Alert ID, etc.
    tags: list[str] = Field(default_factory=list)


class Incident(IncidentBase, IDModel, TimestampedModel):
    status: IncidentStatus = IncidentStatus.OPEN
    detected_at: datetime
    assigned_to: UUID | None = None
    assets_involved: list[UUID] = Field(default_factory=list)
    current_stage: AttackStage | None = None
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    closed_at: datetime | None = None
    closure_reason: str | None = None


class IncidentCreate(IncidentBase):
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    assets_involved: list[UUID] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    assigned_to: UUID | None = None
    current_stage: AttackStage | None = None
    threat_score: float | None = None
    tags: list[str] | None = None


class TimelineEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    timestamp: datetime
    event_type: str
    title: str
    description: str | None = None
    severity: IncidentSeverity
    source: str
    asset_ids: list[UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    prediction_id: UUID | None = None


# ============================================================================
# DECISION / RESPONSE MODELS
# ============================================================================

class ResponseAction(BaseModel):
    action_type: ActionType
    target_asset_id: UUID | None = None
    target_zone: ZoneType | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=1, le=10)
    requires_approval: bool = False
    auto_execute: bool = True


class Decision(BaseModel):
    incident_id: UUID
    risk_score: float = Field(ge=0.0, le=1.0)
    actions: list[ResponseAction]
    reasoning: str
    requires_approval: bool
    created_at: datetime = Field(default_factory=datetime.utcnow)
    decided_by: str  # "auto", "analyst", "admin"
    analyst_id: UUID | None = None


class ContainmentResult(BaseModel):
    asset_id: UUID
    action: ActionType
    success: bool
    previous_status: AssetStatus
    new_status: AssetStatus
    isolation_level: IsolationLevel
    applied_rules: list[str] = Field(default_factory=list)
    error: str | None = None
    executed_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# DECEPTION MODELS
# ============================================================================

class HoneypotTemplate(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    honeypot_type: HoneypotType
    description: str
    docker_image: str
    ports: list[int]
    environment: dict[str, str] = Field(default_factory=dict)
    volumes: list[str] = Field(default_factory=list)
    resource_limits: dict[str, Any] = Field(default_factory=dict)
    decoy_files: list[str] = Field(default_factory=list)
    credentials: list[dict[str, str]] = Field(default_factory=list)
    is_active: bool = True


class DeceptionDeployment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    name: str
    honeypot_types: list[HoneypotType]
    target_assets: list[UUID]
    predicted_stage: AttackStage
    status: DeploymentStatus = DeploymentStatus.PENDING
    container_ids: list[str] = Field(default_factory=list)
    network_config: dict[str, Any] = Field(default_factory=dict)
    deployed_at: datetime | None = None
    torn_down_at: datetime | None = None
    interactions_count: int = 0


class HoneypotInteraction(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    deployment_id: UUID
    honeypot_type: HoneypotType
    container_id: str
    timestamp: datetime
    source_ip: str
    source_port: int
    destination_port: int
    protocol: str
    action: str  # connection, auth_attempt, command, file_access, etc.
    details: dict[str, Any] = Field(default_factory=dict)
    severity: IncidentSeverity = IncidentSeverity.LOW
    mitre_techniques: list[str] = Field(default_factory=list)


# ============================================================================
# FORENSICS MODELS
# ============================================================================

class EvidenceBase(BaseModel):
    incident_id: UUID
    evidence_type: EvidenceType
    name: str
    description: str | None = None
    source_asset_id: UUID | None = None
    size_bytes: int
    sha256_hash: str
    collection_method: str
    collected_by: UUID | None = None


class Evidence(EvidenceBase, IDModel, TimestampedModel):
    storage_path: str
    is_verified: bool = False
    verified_at: datetime | None = None
    verified_by: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PCAPFile(Evidence):
    packet_count: int
    start_time: datetime
    end_time: datetime
    filters_applied: list[str] = Field(default_factory=list)


class LogFile(Evidence):
    log_source: str
    log_format: str
    line_count: int
    time_range_start: datetime
    time_range_end: datetime


class FileEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    asset_id: UUID
    file_path: str
    file_hash: str | None = None
    action: FileEventAction
    timestamp: datetime
    process_name: str | None = None
    process_id: int | None = None
    user: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Tracking fields
    was_read: bool = False
    was_modified: bool = False
    was_copied: bool = False
    was_deleted: bool = False
    was_exfiltrated: bool = False
    exfiltration_destination: str | None = None


class ConfigSnapshot(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    label: str
    description: str
    snapshot_type: str  # "pre_incident", "containment", "deception", "post_incident"
    configuration: dict[str, Any]  # Serialized network config
    sha256_hash: str
    created_by: UUID | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    applied_at: datetime | None = None


class ConfigDiff(BaseModel):
    from_snapshot_id: UUID
    to_snapshot_id: UUID
    added: dict[str, Any]
    removed: dict[str, Any]
    modified: dict[str, Any]


# ============================================================================
# WEBSOCKET EVENT MODELS
# ============================================================================

class WSEventType(str, Enum):
    # Topology
    ASSET_STATUS_CHANGED = "asset_status_changed"
    CONNECTION_ADDED = "connection_added"
    CONNECTION_REMOVED = "connection_removed"
    TOPOLOGY_UPDATED = "topology_updated"
    
    # Prediction
    PREDICTION_GENERATED = "prediction_generated"
    FORECAST_UPDATED = "forecast_updated"
    STAGE_TRANSITION = "stage_transition"
    
    # Incident
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_CLOSED = "incident_closed"
    
    # Deception
    HONEYPOT_DEPLOYED = "honeypot_deployed"
    HONEYPOT_INTERACTION = "honeypot_interaction"
    HONEYPOT_REMOVED = "honeypot_removed"
    
    # Containment
    HOST_ISOLATED = "host_isolated"
    HOST_RESTORED = "host_restored"
    TRAFFIC_BLOCKED = "traffic_blocked"
    
    # Config
    SNAPSHOT_CREATED = "snapshot_created"
    CONFIG_APPLIED = "config_applied"
    
    # Forensics
    EVIDENCE_COLLECTED = "evidence_collected"
    TIMELINE_UPDATED = "timeline_updated"


class WSEvent(BaseModel):
    event: WSEventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    incident_id: UUID | None = None
    payload: dict[str, Any]


class AssetStatusChangedPayload(BaseModel):
    asset_id: UUID
    asset_name: str
    old_status: AssetStatus
    new_status: AssetStatus
    threat_score: float


class PredictionGeneratedPayload(BaseModel):
    forecast: AttackForecast


class HoneypotInteractionPayload(BaseModel):
    deployment_id: UUID
    interaction: HoneypotInteraction


class HostIsolatedPayload(BaseModel):
    asset_id: UUID
    asset_name: str
    isolation_level: IsolationLevel
    previous_status: AssetStatus


# ============================================================================
# API REQUEST/RESPONSE MODELS
# ============================================================================

class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


class APIResponse(BaseModel):
    success: bool = True
    data: Any | None = None
    error: str | None = None
    message: str | None = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    detail: str | None = None
    code: str | None = None


# ============================================================================
# FILTER MODELS
# ============================================================================

class AssetFilters(BaseModel):
    status: list[AssetStatus] | None = None
    asset_type: list[AssetType] | None = None
    zone: list[ZoneType] | None = None
    criticality: list[CriticalityLevel] | None = None
    search: str | None = None
    incident_id: UUID | None = None


class IncidentFilters(BaseModel):
    status: list[IncidentStatus] | None = None
    severity: list[IncidentSeverity] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    assigned_to: UUID | None = None
    search: str | None = None


class EvidenceFilters(BaseModel):
    evidence_type: list[EvidenceType] | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    source_asset_id: UUID | None = None