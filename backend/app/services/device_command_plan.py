"""Intent-to-command planning for supported network devices.

The world model selects an intent and parameters. This module renders only
validated, versioned templates; it never executes arbitrary model output.
"""
from __future__ import annotations

from typing import Any, Dict


DEVICE_PROFILES: Dict[str, Dict[str, Any]] = {
    "cisco_ios_xe": {
        "vendor": "Cisco",
        "platform": "IOS-XE",
        "transports": ["ssh", "netconf", "restconf"],
        "capabilities": ["quarantine_interface", "interface_description", "verify_vlan"],
    },
    "cisco_nxos": {
        "vendor": "Cisco",
        "platform": "NX-OS",
        "transports": ["ssh", "netconf"],
        "capabilities": ["quarantine_interface", "interface_description", "verify_vlan"],
    },
    "juniper_junos": {
        "vendor": "Juniper",
        "platform": "Junos",
        "transports": ["ssh", "netconf"],
        "capabilities": ["quarantine_interface", "interface_description", "verify_vlan"],
    },
    "arista_eos": {
        "vendor": "Arista",
        "platform": "EOS",
        "transports": ["ssh", "eapi", "netconf"],
        "capabilities": ["quarantine_interface", "interface_description", "verify_vlan"],
    },
}


def list_profiles() -> list[dict[str, Any]]:
    return [{"id": key, **value} for key, value in DEVICE_PROFILES.items()]


def _require_text(body: Dict[str, Any], name: str) -> str:
    value = str(body.get(name, "")).strip()
    if not value or any(token in value for token in ("\n", "\r", ";", "|", "&&")):
        raise ValueError(f"{name} must be a single safe token")
    return value


def build_intent_plan(*, platform: str, intent: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    profile = DEVICE_PROFILES.get(platform)
    if profile is None:
        raise ValueError(f"unsupported device profile: {platform}")
    if intent not in profile["capabilities"]:
        raise ValueError(f"intent {intent!r} is not supported by {platform}")

    interface = _require_text(parameters, "interface")
    vlan = _require_text(parameters, "quarantine_vlan")
    asset_id = _require_text(parameters, "asset_id")
    description = f"QUARANTINE {asset_id}"

    if platform in {"cisco_ios_xe", "cisco_nxos", "arista_eos"}:
        operations = [
            f"interface {interface}",
            f" description {description}",
            " switchport mode access",
            f" switchport access vlan {vlan}",
        ]
        verification = [
            f"show interface {interface} switchport",
            f"show vlan id {vlan}",
        ]
    else:
        operations = [
            f"set interfaces {interface} description \"{description}\"",
            f"set interfaces {interface} unit 0 family ethernet-switching vlan members {vlan}",
        ]
        verification = [
            f"show interfaces {interface} terse",
            f"show vlans {vlan}",
        ]

    return {
        "plan_version": "1.0",
        "platform": platform,
        "vendor": profile["vendor"],
        "intent": intent,
        "parameters": {"interface": interface, "quarantine_vlan": vlan, "asset_id": asset_id},
        "mode": "dry_run",
        "risk": "high",
        "preconditions": [
            "device_identity_verified",
            "management_channel_healthy",
            "interface_exists",
            "interface_is_not_uplink_or_trunk",
            "quarantine_vlan_exists",
            "protected_asset_policy_allows_change",
        ],
        "operations": operations,
        "verification": verification,
        "rollback": [
            "restore_pre_change_configuration_snapshot",
            f"verify_interface_state:{interface}",
        ],
        "execution_guard": "requires_adapter_and_policy_authorization",
    }
