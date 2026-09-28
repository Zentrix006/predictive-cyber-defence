"""
Demo risk + policy engine.
Deterministic risk scoring combined with model confidence, and policy decisions
that drive containment + deception. Pure functions (no DB).
"""

STAGE_RISK = {
    "reconnaissance": 15,
    "initial_access": 35,
    "execution": 45,
    "persistence": 50,
    "privilege_escalation": 55,
    "defense_evasion": 50,
    "discovery": 55,
    "lateral_movement": 70,
    "collection": 80,
    "exfiltration": 88,
    "impact": 95,
}


def compute_risk(stage: str, confidence: float, level: int = 1,
                 criticality: str = "high") -> dict:
    base = STAGE_RISK.get(stage, 20)
    stage_factor = 1.0 + 0.04 * max(0, level - 1)
    conf_factor = 0.7 + 0.3 * min(1.0, confidence)
    crit_factor = {"low": 0.8, "medium": 0.9, "high": 1.0, "critical": 1.15}.get(criticality, 1.0)
    score = round(min(99.0, base * conf_factor * crit_factor * stage_factor), 1)
    level_name = "low" if score < 40 else ("medium" if score < 60 else ("high" if score < 80 else "critical"))
    return {"risk_score": score, "risk_level": level_name}


def policy_decision(stage: str, risk: dict, predicted: bool = False) -> dict:
    """Produce a deterministic response policy."""
    action = "MONITOR"
    reason = "Risk within normal operating envelope."
    needs_approval = risk["risk_level"] in ("high", "critical")
    if risk["risk_level"] == "critical":
        action = "CONTAIN_AND_DECEIVE"
        reason = "Critical risk — isolate origin asset and stage decoy at predicted target."
    elif risk["risk_level"] == "high":
        action = "CONTAIN_AND_DECEIVE"
        reason = "High risk — contain origin and steer simulation toward decoy."
    elif risk["risk_level"] == "medium":
        action = "ISOLATE"
        reason = "Medium risk — restrict network access for origin asset."
    return {
        "action": action,
        "reason": reason,
        "requires_human_approval": needs_approval,
        "stage": stage,
        "risk": risk,
    }


def select_decoy_target(candidates: list) -> str:
    """Prefer the demoted decoy DB node when available."""
    for c in candidates or []:
        if "decoy" in str(c).lower() or "decoy" in c.get("asset_type", "").lower():
            return c["id"]
    for c in candidates or []:
        if c.get("role") in ("database", "server"):
            return c["id"]
    return candidates[0]["id"] if candidates else "DB-DECOY-01"


def fusion_risk(risk_scores: list) -> dict:
    """Multi-actor convergence fusion.

    Several trajectories converging on one asset compound its risk: treat each
    actor's risk score as an independent breach probability and combine them as
    1 - product(1 - p). Returns a dict with the fused score (capped at 99) and a
    risk level label.
    """
    combined = 1.0
    for s in (risk_scores or [0.0]):
        p = min(0.99, max(0.0, float(s) / 100.0))
        combined *= (1.0 - p)
    score = round(min(99.0, (1.0 - combined) * 100.0), 1)
    level = "low" if score < 40 else ("medium" if score < 60 else
                                      ("high" if score < 80 else "critical"))
    return {"risk_score": score, "risk_level": level}