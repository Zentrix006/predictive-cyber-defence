"""
Deception Selection

Scores pre-staged honeypots against a prediction to pick the best deception asset.
The world model never activates a honeypot directly - it recommends, the policy
engine authorizes, and the deception controller activates.
"""
from typing import List, Optional

# How well each MITRE stage maps to a honeypot type (proxy for deception value)
STAGE_HONEYPOT_AFFINITY = {
    "reconnaissance": ["web", "ssh"],
    "initial_access": ["web", "ssh", "ftp"],
    "execution": ["ssh", "web"],
    "persistence": ["ssh"],
    "privilege_escalation": ["ssh"],
    "defense_evasion": ["web"],
    "credential_access": ["ssh", "database", "smb"],
    "discovery": ["web", "database"],
    "lateral_movement": ["smb", "ssh", "database"],
    "collection": ["database", "smb"],
    "command_and_control": ["iot", "web"],
    "exfiltration": ["database", "ftp"],
    "impact": ["database", "web"],
    "unknown": ["web"],
}

# expected honeypot OS for a given target OS
OS_MATCH = {
    "linux": ["linux"],
    "windows": ["windows"],
    "win": ["windows"],
    "windows_server": ["windows"],
    "unix": ["linux"],
}


def score_honeypot(
    instance,
    predicted_stage: str,
    target_type: str = "",
    target_os: str = "",
    target_services: Optional[List[str]] = None,
    topology_proximity: float = 0.5,
) -> dict:
    """
    Score a single honeypot instance 0..1 for how suitable it is for a prediction.

    Factors: stage affinity, target type match, OS match, service overlap,
    topology proximity and availability.
    """
    hp_type = instance.honeypot_type.value if hasattr(instance.honeypot_type, "value") else instance.honeypot_type
    os_name = (instance.os or "").lower()
    target_os = (target_os or "").lower()
    target_services = [s.lower() for s in (target_services or [])]
    instance_services = [s.lower() for s in getattr(instance, "services", None) or []]

    score = 0.0
    score += 0.35 * (1.0 if hp_type in STAGE_HONEYPOT_AFFINITY.get(predicted_stage, []) else 0.2)

    if target_type:
        type_match = 1.0 if ("db" in hp_type and "database" in target_type) else (
            1.0 if "web" in hp_type and "web" in target_type else (
                1.0 if "iot" in hp_type and "iot" in target_type else
                (0.8 if hp_type in ["ssh", "smb"] and "server" in target_type else 0.3)
            )
        )
        score += 0.15 * type_match

    if target_os:
        expected = OS_MATCH.get(target_os, [])
        score += 0.15 * (1.0 if os_name in expected else 0.2)
    else:
        score += 0.08

    if instance_services and target_services:
        overlap = len(set(instance_services) & set(target_services))
        score += 0.15 * min(1.0, overlap / max(1, len(target_services)))
    elif target_services:
        score += 0.05

    score += 0.15 * max(0.0, min(1.0, float(topology_proximity)))

    # availability
    status = instance.status.value if hasattr(instance.status, "value") else instance.status
    available = status in ("dormant",)  # only dormant honeypots are deployable
    availability = 1.0 if available else 0.0
    score += 0.05 * availability

    score = min(1.0, round(score, 4))
    return {
        "honeypot_id": str(instance.id),
        "name": instance.name,
        "type": hp_type,
        "os": os_name,
        "status": status,
        "score": score,
        "available": available,
    }


def select_honeypots(
    instances,
    predicted_stage: str,
    target_type: str = "",
    target_os: str = "",
    target_services: Optional[List[str]] = None,
    topology_proximity: float = 0.5,
    limit: int = 3,
) -> List[dict]:
    """Rank honeypots for a prediction from best to worst."""
    ranked = sorted(
        (
            score_honeypot(
                i,
                predicted_stage=predicted_stage,
                target_type=target_type,
                target_os=target_os,
                target_services=target_services,
                topology_proximity=topology_proximity,
            )
            for i in instances
        ),
        key=lambda s: s["score"],
        reverse=True,
    )
    return ranked[:limit]