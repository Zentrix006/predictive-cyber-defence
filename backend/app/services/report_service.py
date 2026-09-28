"""
Incident Report Service

Assembles a complete, structured incident report (JSON + Markdown) covering
summary, actors, predictions (with lead time where available), decisions,
actions, deception, evidence, file audit, configuration changes and timeline.
"""
from typing import Dict, List
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.incident import Incident
from app.models.asset import Asset
from app.models.threat import ThreatActor
from app.models.prediction import Prediction, ForecastWindow, PredictedTarget
from app.models.response import PolicyDecision, ResponseAction
from app.models.deception import DeceptionDeployment, HoneypotInteraction
from app.models.forensics import Evidence, FileEvent
from app.models.config_snapshot import ConfigSnapshot


async def build_report(db: AsyncSession, incident_id: UUID, include_timeline: bool = True) -> Dict:
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id).options(
            selectinload(Incident.assets),
            selectinload(Incident.timeline_events),
            selectinload(Incident.threat_actors),
            selectinload(Incident.response_actions),
            selectinload(Incident.policy_decisions),
            selectinload(Incident.deception_deployments),
            selectinload(Incident.evidence),
            selectinload(Incident.config_snapshots),
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise LookupError("Incident not found")

    pred_rows = await db.execute(
        select(Prediction).where(Prediction.incident_id == incident_id).order_by(Prediction.generated_at.desc())
    )
    predictions = list(pred_rows.scalars().all())
    pred_windows = {}
    pred_targets = {}
    for p in predictions:
        w = await db.execute(select(ForecastWindow).where(ForecastWindow.prediction_id == p.id))
        pred_windows[str(p.id)] = [row for row in w.scalars().all()]
        t = await db.execute(select(PredictedTarget).where(PredictedTarget.prediction_id == p.id))
        pred_targets[str(p.id)] = [row for row in t.scalars().all()]

    file_events = await db.execute(select(FileEvent).where(FileEvent.incident_id == incident_id))
    file_events_list = list(file_events.scalars().all())

    interaction_rows = await db.execute(select(HoneypotInteraction))
    interactions_map: Dict[str, List] = {}
    for d in incident.deception_deployments:
        interactions_map[str(d.id)] = [
            i for i in interaction_rows.scalars().all() if str(i.deployment_id) == str(d.id)
        ]

    # Lead-time estimate from the newest prediction's generation time to now
    lead_time_seconds = None
    if predictions:
        latest = predictions[0]
        eta = latest.timeline[0].get("eta_seconds") if latest.timeline else None
        if eta is not None:
            lead_time_seconds = eta

    report: Dict = {
        "incident_id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
        "current_stage": incident.current_stage.value if incident.current_stage else None,
        "threat_score": incident.threat_score,
        "source": incident.source,
        "metadata": incident.metadata_,
        "summary": f"{len(incident.threat_actors)} threat actor(s), "
                   f"{len(incident.assets)} affected asset(s), "
                   f"{len(predictions)} prediction(s), "
                   f"{len(incident.response_actions)} response action(s), "
                   f"{len(incident.evidence)} evidence item(s).",
        "lead_time_estimate_seconds": lead_time_seconds,
    }

    report["assets"] = [
        {
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
            "status": a.status.value if hasattr(a.status, "value") else str(a.status),
            "criticality": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
            "threat_score": a.threat_score,
            "zone": a.zone.value if hasattr(a.zone, "value") else str(a.zone),
        }
        for a in incident.assets
    ]

    report["threat_actors"] = [
        {
            "display_id": a.display_id,
            "current_asset": a.current_asset_name,
            "current_stage": a.current_stage.value if a.current_stage else None,
            "predicted_stage": a.predicted_stage.value if a.predicted_stage else None,
            "predicted_target": a.predicted_target_name,
            "confidence": a.confidence,
            "risk_score": a.risk_score,
            "response_state": a.response_state.value if hasattr(a.response_state, "value") else str(a.response_state),
            "sources": a.correlated_sources,
            "first_seen": a.first_seen.isoformat(),
            "last_seen": a.last_seen.isoformat(),
        }
        for a in incident.threat_actors
    ]

    report["predictions"] = [
        {
            "model_version": p.model_version,
            "generated_at": p.generated_at.isoformat(),
            "current_stage": p.current_stage.value if hasattr(p.current_stage, "value") else str(p.current_stage),
            "current_confidence": p.current_confidence,
            "horizon": p.horizon,
            "timeline": p.timeline,
            "predicted_targets": p.predicted_targets,
            "windows": [
                {
                    "offset": w.window_offset,
                    "stage": w.stage.value if hasattr(w.stage, "value") else str(w.stage),
                    "probability": w.probability,
                    "target": w.target_asset_name,
                    "eta_seconds": w.eta_seconds,
                }
                for w in pred_windows.get(str(p.id), [])
            ],
        }
        for p in predictions[:5]
    ]

    report["policy_decisions"] = [
        {
            "timestamp": d.timestamp.isoformat(),
            "risk_score": d.risk_score,
            "risk_level": d.risk_level,
            "confidence": d.confidence,
            "recommended_action": d.recommended_action.value if hasattr(d.recommended_action, "value") else str(d.recommended_action),
            "rationale": d.rationale,
            "rule_id": d.rule_id,
            "requires_human_approval": d.requires_human_approval,
            "approved": d.approved,
        }
        for d in incident.policy_decisions
    ]

    report["response_actions"] = [
        {
            "action_type": a.action_type.value if hasattr(a.action_type, "value") else str(a.action_type),
            "status": a.status.value if hasattr(a.status, "value") else str(a.status),
            "requested_by": a.requested_by,
            "approved_by": a.approved_by,
            "requires_human_approval": a.requires_human_approval,
            "asset_ids": [str(x) for x in a.asset_ids],
            "before_snapshot_id": str(a.before_snapshot_id) if a.before_snapshot_id else None,
            "after_snapshot_id": str(a.after_snapshot_id) if a.after_snapshot_id else None,
            "simulation": a.simulation,
            "result": a.result,
        }
        for a in incident.response_actions
    ]

    report["deception"] = [
        {
            "name": d.name,
            "honeypot_types": [t.value if hasattr(t, "value") else str(t) for t in d.honeypot_types],
            "predicted_stage": d.predicted_stage,
            "status": d.status.value if hasattr(d.status, "value") else str(d.status),
            "interactions_count": d.interactions_count,
            "interactions": [
                {
                    "source_ip": i.source_ip,
                    "action": i.action,
                    "timestamp": i.timestamp.isoformat(),
                    "details": i.details,
                }
                for i in interactions_map.get(str(d.id), [])
            ],
        }
        for d in incident.deception_deployments
    ]

    report["evidence"] = [
        {
            "evidence_type": e.evidence_type.value if hasattr(e.evidence_type, "value") else str(e.evidence_type),
            "name": e.name,
            "sha256_hash": e.sha256_hash,
            "size_bytes": e.size_bytes,
            "is_verified": e.is_verified,
            "collected_by": str(e.collected_by) if e.collected_by else None,
            "storage_path": e.storage_path,
        }
        for e in incident.evidence
    ]

    report["file_audit"] = [
        {
            "file_path": f.file_path,
            "action": f.action.value if hasattr(f.action, "value") else str(f.action),
            "timestamp": f.timestamp.isoformat(),
            "user": f.user,
            "was_exfiltrated": f.was_exfiltrated,
            "exfiltration_destination": f.exfiltration_destination,
        }
        for f in file_events_list
    ]

    report["config_snapshots"] = [
        {
            "label": s.label,
            "snapshot_type": s.snapshot_type,
            "sha256_hash": s.sha256_hash,
            "applied_at": s.applied_at.isoformat() if s.applied_at else None,
        }
        for s in incident.config_snapshots
    ]

    if include_timeline:
        report["timeline"] = [
            {
                "timestamp": t.timestamp.isoformat(),
                "event_type": t.event_type,
                "title": t.title,
                "description": t.description,
                "severity": t.severity.value if hasattr(t.severity, "value") else str(t.severity),
                "source": t.source,
            }
            for t in sorted(incident.timeline_events, key=lambda x: x.timestamp)
        ]

    report["mitre_mapping"] = {
        "framework": "MITRE ATT&CK",
        "stages_observed": sorted(
            {a.current_stage.value for a in incident.threat_actors if a.current_stage}
        ),
    }
    report["model_version"] = predictions[0].model_version if predictions else "flow-wm-v3.0.0"
    report["chain_of_custody"] = [
        {"evidence": e.name, "sha256": e.sha256_hash, "verified": e.is_verified}
        for e in incident.evidence
    ]
    return report


def report_to_markdown(report: Dict) -> str:
    """Render the report dict as a Markdown document."""
    md = [
        f"# Incident Report — {report.get('title', '')}",
        "",
        f"**Incident ID:** `{report.get('incident_id')}`  ",
        f"**Severity:** {report.get('severity')}  ",
        f"**Status:** {report.get('status')}  ",
        f"**Detected:** {report.get('detected_at')}  ",
        f"**Model:** {report.get('model_version')}",
        "",
        "## Summary",
        report.get("summary", ""),
        "",
        "## Affected Assets",
        "",
        "| Hostname | IP | Type | Status | Criticality | Risk |",
        "|---|---|---|---|---|---|",
    ]
    for a in report.get("assets", []):
        md.append(f"| {a['hostname']} | {a['ip_address']} | {a['asset_type']} | {a['status']} | {a['criticality']} | {a['threat_score']} |")

    if report.get("lead_time_estimate_seconds") is not None:
        md += ["", f"## Lead Time", f"The first predicted transition was estimated **{report['lead_time_estimate_seconds']} seconds** ahead of the observed step."]

    md += ["", "## Threat Actors"]
    for a in report.get("threat_actors", []):
        md.append(f"- **{a['display_id']}**: {a['current_asset']} → {a['predicted_target']} ({a['predicted_stage']}), risk {a['risk_score']}, confidence {a['confidence']}")

    md += ["", "## Predictions (latest)"]
    for p in report.get("predictions", [])[:3]:
        md.append(f"- `{p['generated_at']}` current stage **{p['current_stage']}** (confidence {p['current_confidence']}), horizon {p['horizon']}")
        for w in p.get("windows", []):
            md.append(f"  - T+{w['offset']}: **{w['stage']}** prob {w['probability']} target {w['target']} ETA {w['eta_seconds']}s")

    md += ["", "## Response Actions & Decisions"]
    for d in report.get("policy_decisions", []):
        md.append(f"- Policy `{d['rule_id']}` → **{d['recommended_action']}** (risk {d['risk_score']} {d['risk_level']}, human approval: {d['requires_human_approval']}): {d['rationale']}")
    for a in report.get("response_actions", []):
        md.append(f"- Action **{a['action_type']}** [{a['status']}] by {a['requested_by']}" + (f", approved by {a['approved_by']}" if a['approved_by'] else "") + (", SIMULATED" if a["simulation"] else ""))

    if report.get("deception"):
        md += ["", "## Deception", ""]
        for d in report["deception"]:
            md.append(f"- **{d['name']}** ({', '.join(d['honeypot_types'])}) [{d['status']}] — {d['interactions_count']} interactions")
            for i in d["interactions"][:5]:
                md.append(f"  - {i['source_ip']} {i['action']} @ {i['timestamp']}")

    if report.get("evidence"):
        md += ["", "## Evidence & Chain of Custody", "",
               "| Name | Type | SHA-256 | Verified |", "|---|---|---|---|"]
        for e in report["evidence"]:
            md.append(f"| {e['name']} | {e['evidence_type']} | `{e['sha256_hash'][:16]}…` | {e['is_verified']} |")

    if report.get("file_audit"):
        md += ["", "## File Audit", "",
               "| File | Action | User | Time | Exfiltrated |", "|---|---|---|---|---|"]
        for f in report["file_audit"]:
            md.append(f"| {f['file_path']} | {f['action']} | {f['user']} | {f['timestamp']} | {f['was_exfiltrated']} |")

    if report.get("config_snapshots"):
        md += ["", "## Configuration Snapshots", ""]
        for s in report["config_snapshots"]:
            md.append(f"- **{s['label']}** ({s['snapshot_type']}) `{s['sha256_hash'][:16]}…`")

    if report.get("timeline"):
        md += ["", "## Incident Timeline", ""]
        for t in report["timeline"]:
            md.append(f"- `{t['timestamp']}` **{t['title']}** — {t['description'] or ''}")

    md += ["", "## MITRE ATT&CK Mapping", "",
           f"Stages observed: {', '.join(report.get('mitre_mapping', {}).get('stages_observed', [])) or '—'}"]
    return "\n".join(md)