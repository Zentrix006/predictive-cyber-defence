"""
Multi-Source Confidence Fusion Engine & Discrepancy Detection (Phase 3)
Calculates Bayesian belief accumulation across independent discovery protocols,
cross-corroborates hardware and network attributes, and flags discrepancies for operator review.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class DiscoveredSignal:
    source: str
    confidence: float
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    role: Optional[str] = None
    raw_evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FusionResult:
    fused_confidence: float
    canonical_vendor: Optional[str]
    canonical_model: Optional[str]
    canonical_role: str
    canonical_hostname: Optional[str]
    is_discrepant: bool
    discrepancy_reasons: List[str]
    contributing_sources: List[str]
    recommended_action: str  # "auto_promote", "requires_review", "flagged_discrepancy"


# Known OUI vendors for cross-checking hardware signals
OUI_DATABASE: Dict[str, str] = {
    "00:0c:29": "vmware",
    "00:50:56": "vmware",
    "08:00:27": "virtualbox",
    "b8:27:eb": "raspberry_pi",
    "dc:a6:32": "raspberry_pi",
    "e4:5f:01": "raspberry_pi",
    "00:01:42": "cisco",
    "00:0c:85": "cisco",
    "00:1e:c2": "cisco",
    "00:24:97": "cisco",
    "00:1c:73": "arista",
    "00:10:db": "juniper",
    "00:05:85": "juniper",
    "00:26:bb": "dell",
    "54:a0:50": "dell",
    "08:3e:8e": "hp",
    "3c:d9:2b": "hp",
    "34:12:98": "apple",
    "a4:83:e7": "apple",
    "6c:03:b5": "ubiquiti",
    "28:c2:dd": "intel",
    "00:15:5d": "microsoft_hyperv",
}


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(cleaned) < 6:
        return None
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def lookup_oui(mac: Optional[str]) -> Optional[str]:
    norm = normalize_mac(mac)
    if not norm:
        return None
    prefix = norm[:8]
    return OUI_DATABASE.get(prefix)


class ConfidenceFusionEngine:
    """
    Independent Bayesian belief fusion across observation streams.
    """

    @classmethod
    def fuse_signals(cls, signals: List[DiscoveredSignal]) -> FusionResult:
        if not signals:
            return FusionResult(
                fused_confidence=0.50,
                canonical_vendor=None,
                canonical_model=None,
                canonical_role="unknown",
                canonical_hostname=None,
                is_discrepant=False,
                discrepancy_reasons=[],
                contributing_sources=[],
                recommended_action="requires_review",
            )

        contributing_sources: List[str] = []
        confidences: List[float] = []
        hostnames: List[Tuple[str, float]] = []
        vendors: List[Tuple[str, float]] = []
        models: List[Tuple[str, float]] = []
        roles: List[Tuple[str, float]] = []
        macs: Set[str] = set()

        for s in signals:
            src = s.source.lower().strip()
            contributing_sources.append(src)
            confidences.append(max(0.10, min(0.98, s.confidence)))
            if s.hostname:
                hostnames.append((s.hostname.strip(), s.confidence))
            if s.vendor:
                vendors.append((s.vendor.strip().lower(), s.confidence))
            if s.model:
                models.append((s.model.strip(), s.confidence))
            if s.role and s.role != "unknown":
                roles.append((s.role.strip().lower(), s.confidence))
            if s.mac:
                m_norm = normalize_mac(s.mac)
                if m_norm:
                    macs.add(m_norm)

        # 1. Bayesian Independent Accumulation: C_fused = 1 - Prod(1 - c_i)
        prod = 1.0
        for c in confidences:
            prod *= (1.0 - c)
        raw_fused = 1.0 - prod

        # 2. Cross-corroboration & Discrepancy Analysis
        discrepancy_reasons: List[str] = []
        is_discrepant = False

        # Vendor cross-validation with OUI
        oui_vendor = None
        for m in macs:
            oui_hit = lookup_oui(m)
            if oui_hit:
                oui_vendor = oui_hit
                break

        distinct_vendors = {v[0] for v in vendors}
        if oui_vendor:
            # Check for conflict
            for v_name in distinct_vendors:
                if v_name != oui_vendor and not (v_name in oui_vendor or oui_vendor in v_name):
                    discrepancy_reasons.append(
                        f"Hardware OUI vendor '{oui_vendor}' contradicts protocol reported vendor '{v_name}'"
                    )
                    is_discrepant = True

        if len(distinct_vendors) > 1:
            discrepancy_reasons.append(
                f"Conflicting vendors reported across protocols: {', '.join(sorted(distinct_vendors))}"
            )
            is_discrepant = True

        # Role consistency check
        distinct_roles = {r[0] for r in roles}
        if "switch" in distinct_roles and "workstation" in distinct_roles:
            discrepancy_reasons.append("Conflicting device roles detected: switch vs workstation")
            is_discrepant = True

        # 3. Resolve canonical values by highest confidence weight
        canonical_vendor = cls._resolve_weighted_winner(vendors) or oui_vendor
        canonical_model = cls._resolve_weighted_winner(models)
        canonical_hostname = cls._resolve_weighted_winner(hostnames)
        canonical_role = cls._resolve_weighted_winner(roles) or "unknown"

        # 4. Confidence adjustments
        final_conf = raw_fused
        if is_discrepant:
            # Significant penalty for conflicting facts
            final_conf = max(0.20, min(0.49, final_conf * 0.5))
            rec_action = "flagged_discrepancy"
        elif len(set(contributing_sources)) >= 3 and final_conf >= 0.85:
            # Boost for triple-independent agreement (e.g. ARP + DHCP + LLDP/SNMP)
            final_conf = min(0.99, final_conf + 0.05)
            rec_action = "auto_promote"
        elif final_conf >= 0.75:
            rec_action = "auto_promote"
        else:
            rec_action = "requires_review"

        return FusionResult(
            fused_confidence=round(final_conf, 4),
            canonical_vendor=canonical_vendor,
            canonical_model=canonical_model,
            canonical_role=canonical_role,
            canonical_hostname=canonical_hostname,
            is_discrepant=is_discrepant,
            discrepancy_reasons=discrepancy_reasons,
            contributing_sources=sorted(list(set(contributing_sources))),
            recommended_action=rec_action,
        )

    @staticmethod
    def _resolve_weighted_winner(candidates: List[Tuple[str, float]]) -> Optional[str]:
        if not candidates:
            return None
        scores: Dict[str, float] = {}
        for val, weight in candidates:
            scores[val] = scores.get(val, 0.0) + weight
        return max(scores.items(), key=lambda x: x[1])[0]
