"""
Deterministic Policy Engine

The AI (world model / DQN) RECOMMENDS. The policy engine AUTHORIZES. Rules are
configured centrally in app/core/policy_config.py.
"""
from typing import Optional

from app.core.policy_config import POLICY_RULES, PolicyAction
from app.services.risk_engine import risk_level_for


class PolicyDecision:
    """Plain data holder returned by the policy engine."""

    def __init__(
        self,
        action: PolicyAction,
        rule_id: str,
        rationale: str,
        requires_human_approval: bool,
        risk_score: float,
        risk_level: str,
        confidence: float,
    ):
        self.action = action
        self.rule_id = rule_id
        self.rationale = rationale
        self.requires_human_approval = requires_human_approval
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.confidence = confidence

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "rule_id": self.rule_id,
            "rationale": self.rationale,
            "requires_human_approval": self.requires_human_approval,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
        }


def evaluate_policy(
    risk_score: float,
    confidence: float,
    asset_criticality: str = "medium",
    predicted_target_critical: bool = False,
    deception_available: bool = False,
    novelty_score: float = 0.0,
) -> PolicyDecision:
    """Evaluate deterministic policy rules with zero-loss safeguards for novel threats."""
    risk_score = max(0.0, min(100.0, float(risk_score)))
    confidence = max(0.0, min(1.0, float(confidence)))
    novelty_score = max(0.0, min(1.0, float(novelty_score)))

    # Zero-Day / Novelty policy override:
    if novelty_score >= 0.70:
        if asset_criticality.lower() == "critical":
            return PolicyDecision(
                action=PolicyAction.PREPARE_DECEPTION,
                rule_id="novel-threat-critical-asset",
                rationale="Novel high-uncertainty anomaly on critical infrastructure -> staging deception and non-disruptive capture to preserve uptime.",
                requires_human_approval=True,
                risk_score=round(max(risk_score, 75.0), 2),
                risk_level=risk_level_for(max(risk_score, 75.0)),
                confidence=round(confidence, 3),
            )
        else:
            return PolicyDecision(
                action=PolicyAction.CONTAIN,
                rule_id="novel-threat-standard-asset",
                rationale="Novel high-uncertainty anomaly on non-critical asset -> selective containment to isolate blast radius.",
                requires_human_approval=False,
                risk_score=round(max(risk_score, 70.0), 2),
                risk_level=risk_level_for(max(risk_score, 70.0)),
                confidence=round(confidence, 3),
            )

    for rule in POLICY_RULES:
        if risk_score < rule["min_risk"]:
            continue
        if confidence < rule["min_confidence"]:
            continue
        if rule.get("predicted_target_critical") and not predicted_target_critical:
            continue
        excluded = rule.get("asset_criticality_not", [])
        if asset_criticality.lower() in excluded:
            continue
        if rule.get("deception_available") and not deception_available:
            continue
        return PolicyDecision(
            action=rule["action"],
            rule_id=rule["id"],
            rationale=rule["note"],
            requires_human_approval=rule["human"],
            risk_score=round(risk_score, 2),
            risk_level=risk_level_for(risk_score),
            confidence=round(confidence, 3),
        )

    # Fallback (should not be reached - observe rule covers risk >= 0)
    return PolicyDecision(
        action=PolicyAction.OBSERVE,
        rule_id="observe",
        rationale="Low risk -> normal observation.",
        requires_human_approval=False,
        risk_score=round(risk_score, 2),
        risk_level=risk_level_for(risk_score),
        confidence=round(confidence, 3),
    )