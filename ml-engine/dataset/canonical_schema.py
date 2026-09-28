import datetime
from typing import Optional, List, Dict, Any, Set, Literal
import math
from pydantic import BaseModel, Field, model_validator

SCHEMA_VERSION = "canonical-telemetry-v1"

class TransportMetrics(BaseModel):
    """Typed packet/flow measurements; absent telemetry stays null."""
    syn_count: Optional[int] = Field(default=None, ge=0)
    ack_count: Optional[int] = Field(default=None, ge=0)
    fin_count: Optional[int] = Field(default=None, ge=0)
    rst_count: Optional[int] = Field(default=None, ge=0)
    psh_count: Optional[int] = Field(default=None, ge=0)
    iat_mean_seconds: Optional[float] = Field(default=None, ge=0)
    iat_variance_seconds: Optional[float] = Field(default=None, ge=0)
    iat_p95_seconds: Optional[float] = Field(default=None, ge=0)
    ttl_mean: Optional[float] = Field(default=None, ge=0, le=255)
    ttl_variance: Optional[float] = Field(default=None, ge=0)
    tcp_window_mean: Optional[float] = Field(default=None, ge=0)
    payload_bytes_mean: Optional[float] = Field(default=None, ge=0)
    retransmission_count: Optional[int] = Field(default=None, ge=0)
    fragment_count: Optional[int] = Field(default=None, ge=0)
    unique_destination_ports: Optional[int] = Field(default=None, ge=0)
    sequential_scan_score: Optional[float] = Field(default=None, ge=0, le=1)
    random_scan_score: Optional[float] = Field(default=None, ge=0, le=1)
    bidirectional_bytes_ratio: Optional[float] = Field(default=None, ge=0)
    bidirectional_packets_ratio: Optional[float] = Field(default=None, ge=0)
    flow_duration_seconds: Optional[float] = Field(default=None, ge=0)

class CanonicalEvent(BaseModel):
    schema_version: str = SCHEMA_VERSION
    event_id: str
    timestamp_utc: datetime.datetime
    capture_id: str
    campaign_id: str
    site_id: str
    sensor_id: str
    source_type: str
    source_file_hash: str
    event_kind: str = "flow"
    direction: Optional[Literal["ingress", "egress", "internal", "unknown"]] = None
    
    # Identity (Unknown fields must remain null)
    src_device_id: Optional[str] = None
    dst_device_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    
    # Network details
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    vlan_id: Optional[int] = None
    interface_id: Optional[str] = None
    segment_id: Optional[str] = None
    flow_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # Metrics
    packet_count: Optional[int] = None
    byte_count: Optional[int] = None
    tcp_udp_icmp_features: Dict[str, Any] = Field(default_factory=dict)
    packet_level_statistics: Dict[str, Any] = Field(default_factory=dict)
    typed_metrics: TransportMetrics = Field(default_factory=TransportMetrics)
    observed_mask: Dict[str, bool] = Field(default_factory=dict)
    
    # Labels
    label: str
    mitre_stage: Optional[str] = None
    label_provenance: str
    label_confidence: float = Field(ge=0.0, le=1.0)
    label_is_partial: bool = False
    label_is_unknown: bool = False
    
    @model_validator(mode='after')
    def validate_identity(self) -> 'CanonicalEvent':
        # Ensure we do not replace unknown identity with fabricated hosts.
        # But we MUST have at least some identity trace for graph building eventually.
        # We allow nulls here, but the Dataset level validator will check for graph usability.
        return self


class DeviceRecord(BaseModel):
    schema_version: str = SCHEMA_VERSION
    device_id: str
    ip_history: List[str] = Field(default_factory=list)
    mac_history: List[str] = Field(default_factory=list)
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    role: Optional[str] = None
    operating_system: Optional[str] = None
    vlan: Optional[int] = None
    zone: Optional[str] = None
    criticality: Optional[str] = None
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    identity_status: Literal["verified", "corroborated", "inferred", "unknown"] = "unknown"
    identity_evidence: List[str] = Field(default_factory=list)


class TopologyEdge(BaseModel):
    schema_version: str = SCHEMA_VERSION
    source_device: str
    destination_device: str
    relationship_type: str
    local_interface: Optional[str] = None
    remote_interface: Optional[str] = None
    vlan_trunk_info: Optional[str] = None
    evidence_source: str
    evidence_sources: List[str] = Field(default_factory=list)
    observation_count: int = Field(default=1, ge=1)
    relationship_direction: Literal["directed", "undirected"] = "directed"
    contradiction: bool = False
    confidence: float = Field(ge=0.0, le=1.0)
    first_confirmed: datetime.datetime
    last_confirmed: datetime.datetime
    
    @model_validator(mode='after')
    def validate_evidence(self) -> 'TopologyEdge':
        valid_evidence = {"LLDP", "CDP", "FDB", "ROUTING", "AUTH_CONFIG", "FLOW_CORROBORATION"}
        if not any(ev in self.evidence_source.upper() for ev in valid_evidence):
            raise ValueError(f"Topology edge must be supported by valid evidence. Got: {self.evidence_source}")
        return self


class ConfigSnapshot(BaseModel):
    schema_version: str = SCHEMA_VERSION
    device_id: str
    vendor_platform: str
    config_hash: str
    state_info: Dict[str, Any]
    collection_time: datetime.datetime
    redacted_config_ref: str
    provenance: str


class CampaignManifest(BaseModel):
    schema_version: str = SCHEMA_VERSION
    campaign_id: str
    site_id: str
    partition: str  # train, development, calibration, test-known, test-novel
    captures_included: List[str]
    capture_hashes: Dict[str, str] = Field(default_factory=dict)
    artifact_hashes: Dict[str, str]
    telemetry_types: List[str] = Field(default_factory=list)
    attack_families: List[str]
    stages_present: List[str]
    event_file: str
    device_file: str
    topology_file: str
    label_policy_version: str = "labels-v1"
    
    @model_validator(mode='after')
    def validate_partition_and_telemetry(self) -> 'CampaignManifest':
        valid_partitions = {"train", "development", "calibration", "test-known", "test-novel"}
        if self.partition not in valid_partitions:
            raise ValueError(f"Invalid partition: {self.partition}")
            
        required_telemetry = {"PCAP", "flow", "identity", "topology", "configuration", "labels"}
        if not required_telemetry.issubset(set(self.telemetry_types)):
            missing = required_telemetry - set(self.telemetry_types)
            raise ValueError(f"Campaign {self.campaign_id} missing required telemetry types: {missing}")
            
        for cap in self.captures_included:
            digest = self.capture_hashes.get(cap)
            if digest is None:
                raise ValueError(f"Capture {cap} is missing a recorded SHA-256 hash.")
            if len(digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
                raise ValueError(f"Capture {cap} requires a valid SHA-256 digest.")
        for artifact in ("event_file", "device_file", "topology_file"):
            digest = self.artifact_hashes.get(artifact)
            if digest is None or len(digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
                raise ValueError(f"{artifact} requires a valid SHA-256 digest in artifact_hashes.")
                
        return self
