"""
Unit and Integration Tests for Safe Configuration Automation & 60-Second Rollback Watchdog (Phase 5).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import pytest

from app.schemas.config_automation import (
    ConfigPlanRequest,
    CanaryExecutionRequest,
)
from app.services.config_automation import (
    VaultSecretResolver,
    SafetyPolicyGuard,
    ConfigPlanningEngine,
    RollbackWatchdogEngine,
    PROTECTED_MANAGEMENT_IPS,
    PROTECTED_INTERFACES,
)
from app.api.v1.endpoints.config_automation import (
    compile_config_plan,
    execute_canary_change,
    confirm_canary_success,
    trigger_manual_rollback,
    list_active_watchdogs,
    get_watchdog_status,
)


def test_vault_secret_resolution():
    """Verify zero cleartext credentials: vault URI resolution and validation."""
    # 1. Valid vault URI
    res = VaultSecretResolver.resolve_credential_ref("vault://secret/network/cisco-switch-01")
    assert res["status"] == "resolved_via_mock_vault"
    assert res["vault_path"] == "secret/network/cisco-switch-01"

    # 2. None / empty reference defaults to key agent
    res_default = VaultSecretResolver.resolve_credential_ref(None)
    assert res_default["auth_type"] == "key_agent"

    # 3. Invalid reference format rejected
    with pytest.raises(ValueError, match="Invalid vault reference format"):
        VaultSecretResolver.resolve_credential_ref("plain_text_password_or_token")


def test_safety_policy_guard():
    """Verify pre-flight safety policies block critical management isolation."""
    # 1. Blocking protected Wi-Fi & Docker & local gateway IPs
    for ip in ["172.22.192.1", "127.0.0.1", "172.18.0.1", "10.0.0.1"]:
        is_safe, violations = SafetyPolicyGuard.inspect_safety(
            target_ip=ip,
            interface=None,
            action_type="ACL_DROP",
        )
        assert not is_safe
        assert any("protected management/gateway address" in v for v in violations)

    # 2. Blocking quarantine on protected management interfaces
    for iface in ["mgmt0", "eth0", "wlan0", "lo"]:
        is_safe, violations = SafetyPolicyGuard.inspect_safety(
            target_ip="10.10.10.50",
            interface=iface,
            action_type="QUARANTINE",
        )
        assert not is_safe
        assert any("critical management/uplink port" in v for v in violations)

    # 3. Blocking subnet broadcast / zero IP
    is_safe, violations = SafetyPolicyGuard.inspect_safety("192.168.1.255", None, "ACL_DROP")
    assert not is_safe
    assert any("subnet boundary" in v for v in violations)

    # 4. Legitimate endpoint on standard access port is safe
    is_safe, violations = SafetyPolicyGuard.inspect_safety("10.0.50.45", "GigabitEthernet1/0/24", "ACL_DROP")
    assert is_safe
    assert len(violations) == 0


def test_multi_vendor_plan_compilation():
    """Verify deterministic command synthesis, rollback commands, and syntax diffs."""
    # 1. Cisco IOS-XE Quarantine Plan
    req_cisco = ConfigPlanRequest(
        platform="cisco_ios_xe",
        target_ip="10.10.20.55",
        interface="GigabitEthernet0/5",
        action_type="QUARANTINE",
        quarantine_vlan=666,
    )
    plan_cisco = ConfigPlanningEngine.build_plan(req_cisco)
    assert plan_cisco.vendor == "Cisco"
    assert plan_cisco.is_safe is True
    assert any("switchport access vlan 666" in op for op in plan_cisco.operations)
    assert any("switchport access vlan 1" in op for op in plan_cisco.reverse_rollback_operations)
    assert "--- running-config" in plan_cisco.syntax_diff
    assert len(plan_cisco.pre_snapshot_sha256) == 64

    # 2. Juniper Junos Rate Limit Plan
    req_juniper = ConfigPlanRequest(
        platform="juniper_junos",
        target_ip="10.10.20.56",
        action_type="RATE_LIMIT",
        rate_kbps=5000,
    )
    plan_juniper = ConfigPlanningEngine.build_plan(req_juniper)
    assert plan_juniper.vendor == "Juniper"
    assert plan_juniper.is_safe is True
    assert any("bandwidth-limit 5000k" in op for op in plan_juniper.operations)
    assert any("delete firewall policer" in op for op in plan_juniper.reverse_rollback_operations)

    # 3. Arista EOS ACL Drop Plan
    req_arista = ConfigPlanRequest(
        platform="arista_eos",
        target_ip="10.10.20.57",
        action_type="ACL_DROP",
    )
    plan_arista = ConfigPlanningEngine.build_plan(req_arista)
    assert plan_arista.vendor == "Arista"
    assert plan_arista.is_safe is True
    assert any("deny ip host 10.10.20.57 any" in op for op in plan_arista.operations)
    assert any("no ip access-list" in op for op in plan_arista.reverse_rollback_operations)

    # 4. Linux Nftables Deception Divert Plan
    req_linux = ConfigPlanRequest(
        platform="linux_nftables",
        target_ip="10.10.20.58",
        action_type="DECEPTION_DIVERT",
        honeypot_ip="10.0.99.99",
    )
    plan_linux = ConfigPlanningEngine.build_plan(req_linux)
    assert plan_linux.vendor == "Linux"
    assert plan_linux.is_safe is True
    assert any("dnat to 10.0.99.99" in op for op in plan_linux.operations)


@pytest.mark.asyncio
async def test_rollback_watchdog_arm_and_confirm():
    """Verify watchdog arming, timer window, and operator confirmation disarming."""
    exec_req = CanaryExecutionRequest(
        plan_id="plan_test_01",
        target_ip="10.200.1.5",
        platform="cisco_ios_xe",
        operations=["interface GigabitEthernet0/1", "shutdown"],
        reverse_rollback_operations=["interface GigabitEthernet0/1", "no shutdown"],
        timeout_seconds=60,
        operator_id="soc_analyst_lead",
    )

    # 1. Arm Watchdog
    armed = await RollbackWatchdogEngine.arm_canary_watchdog(exec_req)
    assert armed.status == "ARMED"
    assert armed.rollback_ready is True
    assert armed.timeout_seconds == 60

    # 2. Query status
    status = RollbackWatchdogEngine.get_status(armed.task_id)
    assert status is not None
    assert status.status == "ARMED"
    assert status.remaining_seconds > 0

    # 3. Confirm watchdog before expiration
    confirmed = await RollbackWatchdogEngine.confirm_watchdog(armed.task_id, operator_id="soc_analyst_lead")
    assert confirmed.status == "CONFIRMED"
    assert confirmed.health_status == "HEALTHY"
    assert confirmed.confirmed_at is not None

    # Status persists as CONFIRMED
    status_after = RollbackWatchdogEngine.get_status(armed.task_id)
    assert status_after.status == "CONFIRMED"


@pytest.mark.asyncio
async def test_rollback_watchdog_manual_rollback():
    """Verify operator manual rollback trigger executes instantaneously."""
    exec_req = CanaryExecutionRequest(
        plan_id="plan_test_02",
        target_ip="10.200.1.6",
        platform="juniper_junos",
        operations=["set firewall filter DROP_BAD term 1 then discard"],
        reverse_rollback_operations=["delete firewall filter DROP_BAD"],
        timeout_seconds=60,
    )

    armed = await RollbackWatchdogEngine.arm_canary_watchdog(exec_req)
    assert armed.status == "ARMED"

    # Operator triggers emergency rollback
    rolled_back = await RollbackWatchdogEngine.trigger_rollback(armed.task_id, reason="anomaly_detected")
    assert rolled_back.status == "ROLLED_BACK"
    assert rolled_back.health_status == "DEGRADED"
    assert rolled_back.rolled_back_at is not None


@pytest.mark.asyncio
async def test_rollback_watchdog_simulated_health_failure():
    """Verify sub-second automatic rollback when canary health drops."""
    exec_req = CanaryExecutionRequest(
        plan_id="plan_test_03",
        target_ip="10.200.1.7",
        platform="arista_eos",
        operations=["ip access-list TEST", "10 deny any"],
        reverse_rollback_operations=["no ip access-list TEST"],
        timeout_seconds=30,
        simulate_health_failure=True,
    )

    armed = await RollbackWatchdogEngine.arm_canary_watchdog(exec_req)
    assert armed.status == "ARMED"

    # Wait 1.2s for simulated failure trigger
    await asyncio.sleep(1.2)

    status = RollbackWatchdogEngine.get_status(armed.task_id)
    assert status is not None
    assert status.status == "ROLLED_BACK"
    assert status.health_status == "DEGRADED"


@pytest.mark.asyncio
async def test_rollback_watchdog_timeout_expiration():
    """Verify automatic rollback occurs if operator does not confirm within timeout."""
    exec_req = CanaryExecutionRequest(
        plan_id="plan_test_04",
        target_ip="10.200.1.8",
        platform="linux_nftables",
        operations=["nft add rule inet filter input drop"],
        reverse_rollback_operations=["nft delete rule inet filter input handle 99"],
        timeout_seconds=1,  # 1-second timeout for testing
        simulate_health_failure=False,
    )

    armed = await RollbackWatchdogEngine.arm_canary_watchdog(exec_req)
    assert armed.status == "ARMED"

    # Sleep 1.3s to allow 1s timeout to expire
    await asyncio.sleep(1.3)

    status = RollbackWatchdogEngine.get_status(armed.task_id)
    assert status is not None
    assert status.status == "ROLLED_BACK"


@pytest.mark.asyncio
async def test_config_automation_api_endpoints():
    """Verify end-to-end FastAPI endpoint routing and response models."""
    mock_user = {"sub": "test_operator", "role": "admin"}

    # 1. Compile Plan
    plan_req = ConfigPlanRequest(
        platform="cisco_ios_xe",
        target_ip="10.55.1.1",
        interface="GigabitEthernet0/2",
        action_type="RATE_LIMIT",
        rate_kbps=2000,
        vault_ref="vault://secret/net/switch-core",
    )
    plan = await compile_config_plan(plan_req, current_user=mock_user)
    assert plan.plan_id.startswith("plan_cisco_ios_xe")
    assert plan.is_safe is True

    # 2. Execute Canary
    exec_req = CanaryExecutionRequest(
        plan_id=plan.plan_id,
        target_ip=plan.target_ip,
        platform=plan.platform,
        operations=plan.operations,
        reverse_rollback_operations=plan.reverse_rollback_operations,
        timeout_seconds=45,
    )
    armed = await execute_canary_change(exec_req, current_user=mock_user)
    assert armed.status == "ARMED"
    assert armed.target_ip == "10.55.1.1"

    # 3. List Watchdogs
    watchdogs = await list_active_watchdogs(current_user=mock_user)
    assert any(w.task_id == armed.task_id for w in watchdogs)

    # 4. Get Status
    single_wd = await get_watchdog_status(armed.task_id, current_user=mock_user)
    assert single_wd.task_id == armed.task_id

    # 5. Confirm Canary
    confirmed = await confirm_canary_success(armed.task_id, current_user=mock_user)
    assert confirmed.status == "CONFIRMED"
    assert confirmed.operator_id == "test_operator"
