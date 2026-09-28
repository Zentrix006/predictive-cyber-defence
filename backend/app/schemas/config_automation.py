"""
Configuration Automation & Rollback Watchdog Schemas (Phase 5).
Pydantic V2 validation models with protected_namespaces disabled.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class ConfigPlanRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    platform: str = Field(..., description="Target platform: cisco_ios_xe, cisco_nxos, juniper_junos, arista_eos, linux_nftables")
    action_type: str = Field(..., description="Action: QUARANTINE, RATE_LIMIT, DECEPTION_DIVERT, ACL_DROP, ISOLATE_HOST")
    target_ip: str = Field(..., description="Target host or interface IP")
    target_device_id: Optional[UUID] = None
    interface: Optional[str] = None
    quarantine_vlan: Optional[int] = None
    rate_kbps: Optional[int] = 1000
    honeypot_ip: Optional[str] = "10.0.9.10"
    operator_id: str = "operator"
    vault_ref: Optional[str] = None


class ConfigPlanResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    plan_id: str
    platform: str
    vendor: str
    action_type: str
    target_ip: str
    operations: List[str]
    reverse_rollback_operations: List[str]
    verification_commands: List[str]
    syntax_diff: str
    pre_snapshot_sha256: str
    is_safe: bool
    safety_violations: List[str] = Field(default_factory=list)
    requires_human_approval: bool


class CanaryExecutionRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    plan_id: str
    target_ip: str
    platform: str
    operations: List[str]
    reverse_rollback_operations: List[str]
    timeout_seconds: int = Field(60, ge=1, le=300, description="Rollback watchdog timer duration (default 60s)")
    operator_id: str = "operator"
    simulate_health_failure: bool = Field(False, description="For testing: trigger health degradation to test rollback")


class CanaryExecutionResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    task_id: str
    plan_id: str
    status: str  # ARMED, CONFIRMED, ROLLED_BACK
    target_ip: str
    timeout_seconds: int
    watchdog_armed_at: datetime
    watchdog_expires_at: datetime
    pre_snapshot_sha256: str
    executed_operations: List[str]
    rollback_ready: bool


class WatchdogStatusResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    task_id: str
    plan_id: str
    status: str  # ARMED, CONFIRMED, ROLLED_BACK, EXPIRED
    target_ip: str
    remaining_seconds: float
    health_status: str  # HEALTHY, DEGRADED, ROLLED_BACK
    operator_id: str
    created_at: datetime
    confirmed_at: Optional[datetime] = None
    rolled_back_at: Optional[datetime] = None
