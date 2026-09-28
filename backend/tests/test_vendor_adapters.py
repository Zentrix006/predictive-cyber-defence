"""Unit tests for multi-vendor network configuration compilers and zero-loss rollback."""
import pytest

from app.services.vendor_adapters import (
    compile_vendor_plan,
    execute_vendor_plan_with_health_check,
    CiscoIosXeCompiler,
    JuniperJunosCompiler,
    LinuxNftablesCompiler,
    OpenFlowSdnCompiler,
)


def test_cisco_ios_xe_compiler():
    # 1. ACL drop
    ops, rb, ver = CiscoIosXeCompiler.compile_acl_drop("10.0.1.50")
    assert any("deny ip host 10.0.1.50 any" in op for op in ops)
    assert any("no ip access-list" in r for r in rb)
    assert any("show ip access-lists" in v for v in ver)

    # 2. Rate limiting policer
    ops_r, rb_r, _ = CiscoIosXeCompiler.compile_rate_limit("10.0.1.50", rate_kbps=500)
    assert any("police 500000" in op for op in ops_r)

    # 3. Deception divert
    ops_d, rb_d, _ = CiscoIosXeCompiler.compile_deception_divert("10.0.1.50", "10.0.9.10")
    assert any("set ip next-hop 10.0.9.10" in op for op in ops_d)


def test_juniper_junos_compiler():
    ops, rb, ver = JuniperJunosCompiler.compile_acl_drop("10.0.2.20")
    assert any("set firewall family inet filter" in op for op in ops)
    assert any("then discard" in op for op in ops)
    assert any("delete firewall family inet filter" in r for r in rb)


def test_linux_nftables_compiler():
    # 1. Drop rule
    ops, rb, ver = LinuxNftablesCompiler.compile_acl_drop("10.0.3.15")
    assert any("nft add rule inet filter input ip saddr 10.0.3.15 drop" in op for op in ops)
    assert any("nft delete rule" in r for r in rb)

    # 2. Rate limiting
    ops_lim, _, _ = LinuxNftablesCompiler.compile_rate_limit("10.0.3.15", rate_per_sec=25)
    assert any("limit rate over 25/second drop" in op for op in ops_lim)

    # 3. Deception DNAT
    ops_dnat, _, _ = LinuxNftablesCompiler.compile_deception_divert("10.0.3.15", "10.0.9.12")
    assert any("dnat to 10.0.9.12" in op for op in ops_dnat)


def test_openflow_sdn_compiler():
    ops, rb, ver = OpenFlowSdnCompiler.compile_acl_drop("10.0.4.10")
    assert any("ovs-ofctl add-flow" in op and "actions=drop" in op for op in ops)
    assert any("ovs-ofctl del-flows" in r for r in rb)


def test_compile_vendor_plan_critical_safeguards():
    # Destructive action on critical asset -> guarded
    crit_plan = compile_vendor_plan(
        platform="cisco_ios_xe",
        action_type="ISOLATE",
        target_ip="10.0.2.20",
        asset_criticality="critical",
    )
    assert crit_plan.is_critical_guarded
    assert crit_plan.requires_human_approval
    assert crit_plan.pre_snapshot_sha256 != ""
    assert "proposed-config" in crit_plan.syntax_diff

    # Non-critical asset -> autonomous allowed
    std_plan = compile_vendor_plan(
        platform="linux_nftables",
        action_type="RATE_LIMIT",
        target_ip="10.0.5.40",
        asset_criticality="medium",
    )
    assert not std_plan.is_critical_guarded
    assert not std_plan.requires_human_approval


def test_automated_health_check_rollback():
    plan = compile_vendor_plan(
        platform="linux_nftables",
        action_type="CONTAIN",
        target_ip="10.0.5.40",
    )

    # Case 1: Healthy probe -> VERIFIED
    res_ok = execute_vendor_plan_with_health_check(plan, synthetic_health_ok=True)
    assert res_ok["status"] == "VERIFIED"
    assert res_ok["zero_loss_guarantee_met"] is True
    assert not any("[ROLLBACK]" in op for op in res_ok["executed_operations"])

    # Case 2: Degraded probe -> Instant Sub-Second Rollback (Zero Outage)
    res_fail = execute_vendor_plan_with_health_check(plan, synthetic_health_ok=False)
    assert res_fail["status"] == "ROLLED_BACK"
    assert res_fail["zero_loss_guarantee_met"] is True
    assert res_fail["outage_seconds"] == 0.00
    assert any("[ROLLBACK]" in op for op in res_fail["executed_operations"])
