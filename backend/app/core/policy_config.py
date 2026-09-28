"""
Central policy configuration.

All risk thresholds and policy rules live here so they are configurable in one
place instead of being hardcoded across the codebase.
"""
import enum


class PolicyAction(str, enum.Enum):
    OBSERVE = "observe"
    MONITOR = "monitor"
    PREPARE_DECEPTION = "prepare_deception"
    CONTAIN = "contain"
    CONTAIN_AND_DECEIVE = "contain_and_deceive"
    ESCALATE = "escalate"


# Risk bands (inclusive min, inclusive max, human label)
RISK_LEVEL_BANDS = [
    (0, 30, "low"),
    (31, 60, "medium"),
    (61, 80, "high"),
    (81, 100, "critical"),
]


# Ordered rule list. The first rule whose conditions are all satisfied wins.
# Fields supported per rule:
#   id, min_risk (0-100), min_confidence (0-1),
#   predicted_target_critical: bool (matched when predicted target is critical),
#   asset_criticality_not: list of criticality labels that block the rule,
#   deception_available: bool (matched when deception resources are available),
#   action: PolicyAction value, human: requires human approval, note: rationale
POLICY_RULES = [
    {
        "id": "esc-critical",
        "min_risk": 90,
        "min_confidence": 0.0,
        "action": PolicyAction.ESCALATE,
        "human": True,
        "note": "Risk >= 90 always escalates to a human decision.",
    },
    {
        "id": "deceive-critical-target",
        "min_risk": 85,
        "min_confidence": 0.85,
        "predicted_target_critical": True,
        "action": PolicyAction.CONTAIN_AND_DECEIVE,
        "human": True,
        "note": "High risk on a critical predicted target -> contain + deception with human approval.",
    },
    {
        "id": "selective-containment",
        "min_risk": 80,
        "min_confidence": 0.85,
        "asset_criticality_not": ["critical"],
        "action": PolicyAction.CONTAIN,
        "human": False,
        "note": "Risk >= 80 with confidence >= 0.85 on a non-critical asset -> selective containment.",
    },
    {
        "id": "contain-and-deceive",
        "min_risk": 70,
        "min_confidence": 0.75,
        "deception_available": True,
        "action": PolicyAction.CONTAIN_AND_DECEIVE,
        "human": False,
        "note": "Sustained high risk with deception available -> contain and deceive.",
    },
    {
        "id": "prepare-deception",
        "min_risk": 50,
        "min_confidence": 0.6,
        "action": PolicyAction.PREPARE_DECEPTION,
        "human": False,
        "note": "Risk >= 50 -> stage deception while monitoring.",
    },
    {
        "id": "monitor",
        "min_risk": 30,
        "min_confidence": 0.0,
        "action": PolicyAction.MONITOR,
        "human": False,
        "note": "Elevated risk -> increase monitoring.",
    },
    {
        "id": "observe",
        "min_risk": 0,
        "min_confidence": 0.0,
        "action": PolicyAction.OBSERVE,
        "human": False,
        "note": "Low risk -> normal observation.",
    },
]


def risk_level_for_score(score: float) -> str:
    score = max(0.0, min(100.0, score))
    for lo, hi, label in RISK_LEVEL_BANDS:
        if lo <= score <= hi:
            return label
    return "low"