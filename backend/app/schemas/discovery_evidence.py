"""
Discovery Evidence and Device Identity Schemas (Phase 1)
Validation, response serialization, and operator verification models.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class DiscoveryObservationCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    source: str = Field(..., description="Discovery source protocol: arp, dhcp, mdns, snmp, lldp, cdp, ssh, netflow")
    collector: str = Field(..., description="Collector identity or interface: eth0, probe-dmz, snmp-poller")
    device_id: Optional[UUID] = None
    raw_evidence_ref: Optional[str] = None
    normalized_fields: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    auth_method: Optional[str] = None
    operator_id: Optional[str] = None
    timestamp: Optional[datetime] = None


class DiscoveryObservationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: UUID
    device_id: Optional[UUID] = None
    source: str
    timestamp: datetime
    collector: str
    raw_evidence_ref: Optional[str] = None
    normalized_fields: Dict[str, Any] = Field(default_factory=dict)
    confidence: float
    auth_method: Optional[str] = None
    operator_id: Optional[str] = None


class DeviceIdentityCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    primary_ip: Optional[str] = None
    primary_mac: Optional[str] = None
    ips: List[str] = Field(default_factory=list)
    macs: List[str] = Field(default_factory=list)
    hostname: Optional[str] = None
    dhcp_name: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    os_version: Optional[str] = None
    device_role: str = "unknown"
    management_interface: Optional[str] = None
    vlan_memberships: List[int] = Field(default_factory=list)
    site_zone: str = "unknown"
    criticality: str = "medium"
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    status: str = "provisional"
    secret_vault_ref: Optional[str] = None
    notes: Optional[str] = None


class DeviceIdentityUpdate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    device_role: Optional[str] = None
    vlan_memberships: Optional[List[int]] = None
    site_zone: Optional[str] = None
    criticality: Optional[str] = None
    secret_vault_ref: Optional[str] = None
    notes: Optional[str] = None


class DeviceVerificationAction(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    action: str = Field(..., description="Action to take: approve, reject, merge")
    target_device_id: Optional[UUID] = Field(None, description="For merge action: ID of primary device to merge into")
    verified_by: str = Field("operator", description="Operator identity approving verification")
    vendor_override: Optional[str] = None
    role_override: Optional[str] = None
    notes: Optional[str] = None


class DeviceIdentityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: UUID
    primary_ip: Optional[str] = None
    primary_mac: Optional[str] = None
    ips: List[str] = Field(default_factory=list)
    macs: List[str] = Field(default_factory=list)
    hostname: Optional[str] = None
    dhcp_name: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    os_version: Optional[str] = None
    device_role: str
    management_interface: Optional[str] = None
    vlan_memberships: List[int] = Field(default_factory=list)
    site_zone: str
    criticality: str
    confidence: float
    status: str
    secret_vault_ref: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None
    notes: Optional[str] = None


class DeviceSnapshotCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    device_id: UUID
    interfaces: List[Dict[str, Any]] = Field(default_factory=list)
    link_state: Dict[str, Any] = Field(default_factory=dict)
    vlans_and_trunks: Dict[str, Any] = Field(default_factory=dict)
    routing_table: List[Dict[str, Any]] = Field(default_factory=list)
    neighbours: List[Dict[str, Any]] = Field(default_factory=list)
    acl_metadata: List[Dict[str, Any]] = Field(default_factory=list)
    enabled_services: List[str] = Field(default_factory=list)
    configuration_hash: str
    source_observation_ids: List[str] = Field(default_factory=list)


class DeviceSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: UUID
    device_id: UUID
    interfaces: List[Dict[str, Any]] = Field(default_factory=list)
    link_state: Dict[str, Any] = Field(default_factory=dict)
    vlans_and_trunks: Dict[str, Any] = Field(default_factory=dict)
    routing_table: List[Dict[str, Any]] = Field(default_factory=list)
    neighbours: List[Dict[str, Any]] = Field(default_factory=list)
    acl_metadata: List[Dict[str, Any]] = Field(default_factory=list)
    enabled_services: List[str] = Field(default_factory=list)
    configuration_hash: str
    collected_at: datetime
    source_observation_ids: List[str] = Field(default_factory=list)


class TopologyEdgeCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    source_device_id: UUID
    destination_device_id: UUID
    relationship_type: str = "switched"
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    evidence_source: str = "lldp"
    confidence: float = Field(0.5, ge=0.0, le=1.0)


class TopologyEdgeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: UUID
    source_device_id: UUID
    destination_device_id: UUID
    relationship_type: str
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    evidence_source: str
    confidence: float
    status: str
    first_seen: datetime
    last_confirmed: datetime


class VendorTelemetryIngestRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    vendor: str = Field(..., description="Target vendor: cisco, juniper, arista")
    command_type: str = Field(..., description="CLI command: show_version, show_neighbors, show_vlan, show_route")
    raw_cli_output: str = Field(..., description="Raw text output from device CLI execution")
    target_ip: Optional[str] = None
    target_mac: Optional[str] = None
    operator_id: str = "operator"


class VerificationQueueItem(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    device: DeviceIdentityResponse
    observation_count: int
    sources: List[str]
    is_discrepant: bool = False
    discrepancy_reasons: List[str] = Field(default_factory=list)
    recommended_action: str = "requires_review"

