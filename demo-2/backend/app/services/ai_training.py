"""
Demo AI training coordination.

This module does not mutate the serving checkpoint directly. It builds a
reviewable candidate plan, tracks coarse progress for the dashboard, and can
launch an isolated retrain job that uses `--device auto` so the trainer falls
back from CUDA to CPU when a GPU is unavailable.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from app.core.config import settings

_STATUS_PATH = Path(settings.ML_ENGINE_PATH) / "data" / "checkpoints_v3_1_candidate" / "training_status.json"
_TRAIN_SCRIPT = Path(settings.ML_ENGINE_PATH) / "scripts" / "train_real.py"

_STATE: Dict[str, Any] = {
    "status": "idle",
    "phase": "idle",
    "progress_percent": 0,
    "eta_minutes": None,
    "started_at": None,
    "completed_at": None,
    "device_preference": "auto",
    "resolved_device": None,
    "records": 0,
    "schema_requirements": [],
    "expected_improvement": [],
    "steps": [],
    "message": "Ready to train a candidate checkpoint.",
    "last_output": "",
    "plan": None,
    "error": None,
}

_TASK: Optional[asyncio.Task] = None
_EPOCH_RE = re.compile(r"Epoch\s+(\d+)/(\d+)")


def _save_state() -> None:
    _STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATUS_PATH.write_text(json.dumps(_STATE, indent=2), encoding="utf-8")


def status() -> Dict[str, Any]:
    return deepcopy(_STATE)


def schema_requirements() -> list[dict[str, Any]]:
    return [
        {
            "name": "Flow-level telemetry",
            "required_fields": [
                "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
                "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
                "sload", "dload", "ct_srv_src", "ct_dst_ltm",
                "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
                "ct_src_ltm", "ct_srv_dst",
            ],
            "sources": ["UNSW-NB15", "CIC-IDS2017", "CTU-13", "NetFlow/IPFIX", "CSV exports"],
        },
        {
            "name": "Packet-level telemetry",
            "required_fields": [
                "sttl", "dttl", "swin", "dwin", "tcprtt", "synack", "ackdat",
                "smean", "dmean", "trans_depth", "response_body_len",
            ],
            "sources": ["PCAP", "PCAPNG", "Scapy/PyShark parsing"],
        },
        {
            "name": "Label + provenance",
            "required_fields": [
                "attack_cat", "label", "timestamps", "dataset_name", "source_meta",
            ],
            "sources": ["MITRE stage mapping", "incident timeline annotations", "dataset metadata"],
        },
    ]


def _device_strategy() -> dict[str, Any]:
    has_cuda = False
    has_cpu = True
    try:
        import torch

        has_cuda = torch.cuda.is_available()
    except Exception:
        has_cuda = False
    return {
        "preferred": "cuda" if has_cuda else "cpu",
        "fallback_order": ["cuda", "cpu"],
        "resolved_on_launch": "auto",
        "cuda_available": has_cuda,
        "cpu_available": has_cpu,
        "description": "Trainer runs with --device auto, which selects CUDA first and falls back to CPU when needed.",
    }


def build_training_plan(records: int, *, current_metrics: Optional[dict[str, Any]] = None, schema_scan: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    current_metrics = current_metrics or {}
    schema_scan = schema_scan or {}
    eta_minutes = max(20, int(records / 500) + 18)
    steps = [
        {"phase": "export", "label": "Export demo telemetry", "percent": 12, "eta_minutes": max(1, eta_minutes // 6)},
        {"phase": "schema", "label": "Review schema contracts", "percent": 24, "eta_minutes": max(1, eta_minutes // 6)},
        {"phase": "launch", "label": "Launch candidate training", "percent": 40, "eta_minutes": max(1, eta_minutes // 8)},
        {"phase": "train", "label": "Train world model", "percent": 78, "eta_minutes": max(1, eta_minutes - 6)},
        {"phase": "eval", "label": "Evaluate and compare", "percent": 92, "eta_minutes": 4},
        {"phase": "package", "label": "Package candidate checkpoint", "percent": 100, "eta_minutes": 1},
    ]
    return {
        "status": _STATE["status"],
        "phase": _STATE["phase"],
        "progress_percent": _STATE["progress_percent"],
        "eta_minutes": _STATE["eta_minutes"] if _STATE["status"] == "running" else eta_minutes,
        "device_strategy": _device_strategy(),
        "records": records,
        "schema_requirements": schema_requirements(),
        "schema_scan": {
            "status": schema_scan.get("status"),
            "sources": len(schema_scan.get("sources", []) or []),
            "errors": len(schema_scan.get("errors", []) or []),
        },
        "expected_improvement": [
            "Better rare-stage recall by retraining on the newly exported telemetry and the reviewed public schema contracts.",
            "Better calibration and lead-time estimates by preserving temporal ordering and validating against the candidate gate.",
            "Better runtime portability because the trainer uses CUDA when present and CPU when a GPU is unavailable.",
            "Better operational safety because the serving checkpoint stays active until the candidate is explicitly promoted.",
        ],
        "current_metrics": {
            "model_version": current_metrics.get("model_version"),
            "stage_accuracy": current_metrics.get("stage_accuracy"),
            "infiltration_accuracy": current_metrics.get("infiltration_accuracy"),
            "macro_f1": current_metrics.get("macro_f1") or current_metrics.get("attack_macro_f1"),
            "validation_loss": current_metrics.get("val_loss"),
        },
        "steps": steps,
    }


async def _run_training(plan: dict[str, Any], command: list[str]) -> None:
    global _STATE, _TASK
    try:
        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        env.setdefault("ML_DEVICE", "auto")
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(Path(settings.ML_ENGINE_PATH)),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        total_epochs = int(plan.get("epochs", 8))
        start = datetime.now(timezone.utc)
        _STATE.update(
            status="running",
            phase="train",
            progress_percent=40,
            started_at=start.isoformat(),
            completed_at=None,
            error=None,
            message="Training candidate checkpoint.",
            last_output="",
        )
        _save_state()

        assert process.stdout is not None
        async for raw in process.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            _STATE["last_output"] = line[-600:]
            match = _EPOCH_RE.search(line)
            if match:
                current = int(match.group(1))
                total = max(1, int(match.group(2)))
                total_epochs = total
                progress = 40 + int((current / total) * 40)
                elapsed_minutes = max(0.1, (datetime.now(timezone.utc) - start).total_seconds() / 60)
                eta_minutes = max(1, int(elapsed_minutes * max(0, (total - current))))
                _STATE.update(
                    phase="train",
                    progress_percent=min(80, progress),
                    eta_minutes=eta_minutes,
                    message=f"Epoch {current}/{total} in progress.",
                )
                _save_state()

        code = await process.wait()
        if code == 0:
            _STATE.update(
                status="completed",
                phase="package",
                progress_percent=100,
                eta_minutes=0,
                completed_at=datetime.now(timezone.utc).isoformat(),
                message="Candidate training completed successfully.",
                error=None,
            )
        else:
            _STATE.update(
                status="failed",
                phase="failed",
                progress_percent=min(100, _STATE.get("progress_percent", 0)),
                completed_at=datetime.now(timezone.utc).isoformat(),
                message="Candidate training failed.",
                error=f"train_real.py exited with code {code}",
            )
        _save_state()
    except Exception as exc:
        _STATE.update(
            status="failed",
            phase="failed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            message="Candidate training failed before completion.",
            error=str(exc),
        )
        _save_state()
    finally:
        _TASK = None


def start_training(plan: dict[str, Any]) -> dict[str, Any]:
    """Schedule the candidate training run.

    The caller is responsible for exporting telemetry and preparing the review
    manifest before invoking this. If a run is already active, the current
    status is returned unchanged.
    """
    global _TASK
    if _STATE.get("status") == "running" and _TASK and not _TASK.done():
        return status()

    epochs = int(plan.get("epochs", 8))
    max_rows = int(plan.get("max_rows", 30000))
    out_dir = Path(settings.ML_ENGINE_PATH) / "data" / "checkpoints_v3_1_candidate"
    command = [
        sys.executable,
        str(_TRAIN_SCRIPT),
        "--epochs", str(epochs),
        "--max-rows", str(max_rows),
        "--device", "auto",
        "--batch-size", "256",
        "--synthetic-frac", "0.15",
        "--unknown-weight", "0.35",
        "--consistency-weight", "0.4",
        "--rl-weight", "0.7",
        "--warmup-steps", "120",
        "--resume", str(Path(settings.ML_ENGINE_PATH) / "data" / "checkpoints" / "flow_world_model.pt"),
        "--out-dir", str(out_dir),
    ]
    _STATE.update(
        status="queued",
        phase="queue",
        progress_percent=0,
        eta_minutes=plan.get("eta_minutes"),
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=None,
        device_preference="auto",
        resolved_device=None,
        records=int(plan.get("records", 0)),
        schema_requirements=schema_requirements(),
        expected_improvement=plan.get("expected_improvement", []),
        steps=plan.get("steps", []),
        message="Training queued. CUDA will be used when available; CPU is the fallback.",
        last_output="",
        plan=plan,
        error=None,
        epochs=epochs,
        max_rows=max_rows,
        command=command,
    )
    _save_state()
    _TASK = asyncio.create_task(_run_training(plan | {"epochs": epochs}, command))
    return status()
