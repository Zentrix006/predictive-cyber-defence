from app.services.device_command_plan import build_intent_plan, list_profiles


def test_profiles_include_supported_platforms():
    ids = {profile["id"] for profile in list_profiles()}
    assert {"cisco_ios_xe", "juniper_junos", "arista_eos"}.issubset(ids)


def test_intent_plan_is_structured_dry_run_with_rollback():
    plan = build_intent_plan(
        platform="cisco_ios_xe",
        intent="quarantine_interface",
        parameters={"interface": "Gi1/0/24", "quarantine_vlan": "999", "asset_id": "asset-123"},
    )
    assert plan["mode"] == "dry_run"
    assert plan["execution_guard"] == "requires_adapter_and_policy_authorization"
    assert any("switchport access vlan 999" in item for item in plan["operations"])
    assert plan["rollback"]


def test_intent_plan_rejects_command_injection_tokens():
    try:
        build_intent_plan(
            platform="cisco_ios_xe",
            intent="quarantine_interface",
            parameters={"interface": "Gi1/0/24\nreload", "quarantine_vlan": "999", "asset_id": "a"},
        )
    except ValueError as exc:
        assert "interface" in str(exc)
    else:
        raise AssertionError("unsafe command token was accepted")
