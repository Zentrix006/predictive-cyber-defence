"""Curated public schema intake for the demo AI dashboard.

This service never changes serving model weights. Schemas describe data
contracts; they are fetched only when a presenter asks, reduced to metadata,
and placed in a reviewable retraining manifest alongside range telemetry.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from app.core.config import settings

SOURCES = {
    "STIX 2 core": "https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/schemas/common/core.json",
    "STIX network traffic": "https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/schemas/observables/network-traffic.json",
}
_lock = threading.Lock()
_state = {"status": "idle", "started_at": None, "completed_at": None, "sources": [], "errors": [], "manifest": None}


def _path(name: str) -> Path:
    return Path(settings.TRAINING_EXPORT_PATH).parent / name


def _save() -> None:
    _path("demo_schema_intake.json").write_text(json.dumps(_state, indent=2), encoding="utf-8")


def status() -> dict:
    with _lock:
        return json.loads(json.dumps(_state))


def scan_schemas() -> dict:
    """Fetch a small allow-listed set of JSON schemas with bounded I/O."""
    with _lock:
        if _state["status"] == "running":
            return json.loads(json.dumps(_state))
        _state.update(status="running", started_at=datetime.now(timezone.utc).isoformat(), completed_at=None, sources=[], errors=[])
        _save()
    accepted, errors = [], []
    for label, url in SOURCES.items():
        try:
            req = Request(url, headers={"User-Agent": "Predictive-Cyber-Range/1.0 schema-intake"})
            with urlopen(req, timeout=10) as response:
                raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise ValueError("schema exceeds 1 MB intake limit")
            doc = json.loads(raw.decode("utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("schema root is not an object")
            properties = doc.get("properties", {})
            accepted.append({
                "name": label, "url": url, "id": doc.get("$id"), "title": doc.get("title") or label,
                "property_count": len(properties) if isinstance(properties, dict) else 0,
                "sample_fields": sorted(list(properties))[:12] if isinstance(properties, dict) else [],
                "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            })
        except Exception as exc:  # intake keeps partial success visible to presenter
            errors.append({"name": label, "url": url, "error": str(exc)[:180]})
    with _lock:
        _state.update(status="completed" if accepted else "failed", completed_at=datetime.now(timezone.utc).isoformat(), sources=accepted, errors=errors)
        _save()
        return json.loads(json.dumps(_state))


def prepare_training_manifest(demo_records: int) -> dict:
    """Create a reviewable candidate manifest; never promote or retrain automatically."""
    with _lock:
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "review_required",
            "serving_model_unchanged": True,
            "demo_telemetry_records": demo_records,
            "schema_contracts": _state["sources"],
            "schema_scan_status": _state["status"],
            "next_step": "Review source provenance and labels, then launch an isolated candidate training job.",
        }
        _path("demo_training_candidate_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        _state["manifest"] = manifest
        _save()
        return manifest
