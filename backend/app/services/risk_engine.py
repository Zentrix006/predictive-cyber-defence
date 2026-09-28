"""
Deterministic Risk Engine

Risk = Threat Probability x Asset Criticality x Exposure x Predicted Impact

The engine does NOT rely on raw model confidence alone. It combines the model's
forecasted threat probability with deterministic asset/exposure factors and a
convergence multiplier for multiple attack paths targeting the same asset.
"""
from typing import Optional

from app.core.policy_config import risk_level_for_score

CRITICALITY_WEIGHTS = {
    "low": 0.3,
    "medium": 0.6,
    "high": 0.8,
    "critical": 1.0,
}

# Contribution weights for each risk factor (must sum to 1.0)
PROBABILITY_W = 0.45
CRITICALITY_W = 0.20
EXPOSURE_W = 0.10
IMPACT_W = 0.10
CONFIDENCE_W = 0.15


def risk_level_for(score: float) -> str:
    return risk_level_for_score(score)


def compute_risk(
    threat_probability: float = 0.5,
    confidence: float = 0.5,
    asset_criticality: str = "medium",
    exposure: float = 0.5,
    predicted_impact: float = 0.5,
    converging_paths: int = 1,
    active_actors: int = 1,
) -> dict:
    """
    Compute a deterministic 0-100 risk score.

    threat_probability / exposure / predicted_impact are expected in [0, 1].
    confidence is the model's forecast confidence in [0, 1].
    """
    tp = max(0.0, min(1.0, float(threat_probability)))
    cf = max(0.0, min(1.0, float(confidence)))
    ex = max(0.0, min(1.0, float(exposure)))
    im = max(0.0, min(1.0, float(predicted_impact)))
    crit = CRITICALITY_WEIGHTS.get(asset_criticality, 0.6)

    base = 100.0 * (
        PROBABILITY_W * tp
        + CONFIDENCE_W * cf
        + CRITICALITY_W * crit
        + EXPOSURE_W * ex
        + IMPACT_W * im
    )

    actors = max(1, int(active_actors))
    paths = max(1, int(converging_paths))
    convergence_multiplier = 1.0 + 0.10 * (actors - 1) + 0.15 * (paths - 1)
    score = max(0.0, min(100.0, base * convergence_multiplier))

    return {
        "risk_score": round(score, 2),
        "risk_level": risk_level_for(score),
        "probability_component": round(PROBABILITY_W * tp * 100, 2),
        "criticality_component": round(CRITICALITY_W * crit * 100, 2),
        "exposure_component": round(EXPOSURE_W * ex * 100, 2),
        "impact_component": round(IMPACT_W * im * 100, 2),
        "convergence_multiplier": round(convergence_multiplier, 3),
        "converging_paths": paths,
    }


def asset_exposure(asset) -> float:
    """Deterministic exposure estimate from an Asset ORM object."""
    # Assets on the internet / DMZ / with high-value roles are more exposed.
    zone = getattr(asset, "zone", None)
    zone_exposure = {
        "internet": 1.0,
        "dmz": 0.85,
        "server_zone": 0.6,
        "management": 0.5,
        "user_zone": 0.4,
        "iot_zone": 0.3,
        "quarantine": 0.1,
        "honeynet": 0.05,
    }
    base = zone_exposure.get(zone.value if hasattr(zone, "value") else zone, 0.5)
    ports = 0
    services = getattr(asset, "services", None)
    if services:
        # Accessing the relationship can trigger async IO; stay lazy-safe.
        try:
            services = list(services)
        except Exception:
            services = []
        ports = sum(1 for s in services if getattr(s, "status", "running") != "stopped")
    base = min(1.0, base + 0.03 * ports)
    return base


def predicted_impact(asset) -> float:
    """Deterministic impact estimate from asset criticality."""
    criticality = getattr(asset, "criticality", None)
    value = criticality.value if hasattr(criticality, "value") else criticality
    return CRITICALITY_WEIGHTS.get(value, 0.6)


def asset_risk(asset, threat_probability: float, confidence: float, converging_paths: int = 1, active_actors: int = 1) -> dict:
    """Convenience: compute risk for an asset row."""
    return compute_risk(
        threat_probability=threat_probability,
        confidence=confidence,
        asset_criticality=(
            asset.criticality.value if hasattr(asset.criticality, "value") else asset.criticality
        ),
        exposure=asset_exposure(asset),
        predicted_impact=predicted_impact(asset),
        converging_paths=converging_paths,
        active_actors=active_actors,
    )