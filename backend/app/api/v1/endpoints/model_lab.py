"""
Model Lab API — world model metrics, evaluation, baselines, ablations.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

# ml-engine is mounted / available beside backend in compose; also support local path
# (same injection as analyze.py so model_lab is not coupled to import order)
_CANDIDATES = [
    Path("/ml-engine"),
    Path(__file__).resolve().parents[5] / "ml-engine",
]
for _p in _CANDIDATES:
    if (_p / "inference").exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
        break

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_roles
from app.models.evaluation import ForecastEvaluation, ModelComparisonRun
from app.schemas.evaluation import (
    WorldModelMetrics,
    ForecastEvaluationResponse,
    ModelComparisonResponse,
)
from app.services.evaluation_service import (
    checkpoint_history_curve,
    world_model_metrics,
    compute_classification_metrics,
    run_baseline_comparison,
    run_ablation,
    save_evaluation,
    list_evaluations,
    list_comparisons,
)
from app.services.learning_feedback import append_feedback, learning_status
from inference.predictor import get_predictor

router = APIRouter()

MODEL_VERSION = "flow-wm-v3.0.0"
ML_ROOT = next((candidate for candidate in _CANDIDATES if (candidate / "data").exists()), _CANDIDATES[0])


class EvaluateRequest(BaseModel):
    y_true: List[int]
    y_pred: List[int]
    label_names: Optional[List[str]] = None


class BaselineRequest(BaseModel):
    max_rows: int = 6000


class AblationRequest(BaseModel):
    max_rows: int = 4000


class LearningFeedbackRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    kind: str = "analyst"
    novelty_id: Optional[str] = None
    label: Optional[str] = None
    mitre_stage: Optional[str] = None
    analyst_confidence: Optional[float] = None
    notes: Optional[str] = None
    evidence_refs: List[str] = []
    model_version: Optional[str] = None
    source_event_ids: List[str] = []


def _pred():
    try:
        return get_predictor()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Model checkpoint unavailable: {e}")


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _file_timestamp(path: Path) -> Optional[str]:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except OSError:
        return None


def _dataset_inventory() -> List[Dict[str, Any]]:
    """Return file-level provenance without loading untrusted training data."""
    raw = ML_ROOT / "data" / "raw"
    groups = [
        ("UNSW-NB15", [raw / "UNSW_NB15_training-set.csv", raw / "UNSW_NB15_testing-set.csv"]),
        ("NSL-KDD", [raw / "NSL_KDD_Train.csv"]),
        ("KDD99", [raw / "kddcup99" / "kddcup.data_10_percent.txt"]),
        ("CIC-IDS2017", sorted((raw / "cicids2017").glob("*.csv"))),
        ("CTU-13", sorted(raw.glob("CTU13_*.csv"))),
    ]
    inventory = []
    for name, files in groups:
        present = [file for file in files if file.exists()]
        inventory.append({
            "name": name,
            "available": bool(present),
            "files": len(present),
            "bytes": sum(file.stat().st_size for file in present),
            "updated_at": max((_file_timestamp(file) for file in present), default=None),
        })
    return inventory


def _dataset_audit() -> Dict[str, Any]:
    """Return the latest read-only provenance/support audit if available."""
    audit_path = ML_ROOT / "data" / "dataset_audit.json"
    if not audit_path.exists():
        return {
            "available": False,
            "message": "Run ml-engine/scripts/audit_datasets.py before training.",
        }
    audit = _read_json(audit_path)
    quality = audit.get("quality", {})
    return {
        "available": True,
        "generated_at": audit.get("generated_at"),
        "schema_version": audit.get("schema_version"),
        "file_count": quality.get("file_count", len(audit.get("files", []))),
        "error_count": quality.get("error_count", len(audit.get("errors", []))),
        "zero_support_stages": quality.get("zero_support_stages", []),
        "aggregate_stage_support": audit.get("aggregate_stage_support", {}),
        "warning": quality.get("warning"),
    }


@router.get("/observability", response_model=dict)
async def model_observability(current_user: dict = Depends(require_roles("admin"))):
    """Operational model card for the AI Intelligence dashboard.

    This intentionally reports bounded evidence and system behaviour rather
    than exposing hidden reasoning traces or raw training traffic.
    """
    pred = _pred()
    meta = getattr(pred, "meta", {}) or {}
    checkpoint = Path(pred.checkpoint) if getattr(pred, "checkpoint", None) else None
    history_path = checkpoint.parent / "training_history.json" if checkpoint else ML_ROOT / "data" / "checkpoints" / "training_history.json"
    history = _read_json(history_path)

    candidate_dir = ML_ROOT / "data" / "checkpoints_v3_1_candidate"
    candidate_checkpoint = candidate_dir / "flow_world_model.pt"
    candidate_history = _read_json(candidate_dir / "training_history.json")
    candidate_status = _read_json(candidate_dir / "training_status.json")
    if not candidate_status and candidate_checkpoint.exists():
        candidate_status = {
            "status": "candidate_checkpoint_available",
            "message": "Candidate weights are isolated pending held-out evaluation and promotion review.",
        }

    stage_macro = meta.get("stage_macro") or {}
    attack_macro = meta.get("attack_stage_macro") or {}
    cand_v2_dir = ML_ROOT / "data" / "temporal_candidate_v2_2"
    cand_v2_checkpoint = cand_v2_dir / "candidate.pt"
    cand_v2_status = _read_json(cand_v2_dir / "training_status.json")
    cand_v2_benchmarks = _read_json(cand_v2_dir / "baseline_comparison.json")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": {
            "ready": bool(pred.ready),
            "version": meta.get("model_version", "flow-wm-unknown"),
            "feature_dim": meta.get("feature_dim"),
            "context_window": meta.get("context_window"),
            "horizon": meta.get("horizon"),
            "branches": meta.get("n_branches", 1),
            "rl_enabled": bool(meta.get("use_rl", False)),
            "rl_actions": meta.get("rl_actions", 0),
            "checkpoint_written_at": _file_timestamp(checkpoint) if checkpoint else None,
            "checkpoint_bytes": checkpoint.stat().st_size if checkpoint and checkpoint.exists() else 0,
        },
        "quality": {
            "stage_accuracy": meta.get("stage_acc"),
            "infiltration_accuracy": meta.get("infil_acc"),
            "macro_f1": stage_macro.get("f1"),
            "attack_macro_f1": attack_macro.get("f1"),
            "validation_loss": meta.get("val_loss"),
            "validation_split": meta.get("validation_split", "legacy random split; not promotion-grade"),
            "selection_metric": meta.get("selection_metric", "validation_loss"),
        },
        "training": {
            "history": history.get("history", [])[-24:],
            "best_validation_loss": history.get("best_val", meta.get("val_loss")),
            "best_selection_score": history.get("best_selection_score"),
            "synthetic_mode": meta.get("synthetic_mode", "legacy curriculum metadata unavailable"),
            "candidate": {
                **candidate_status,
                "version": _read_json(candidate_dir / "model_card.json").get("model_version"),
                "checkpoint_written_at": _file_timestamp(candidate_checkpoint),
                "checkpoint_available": candidate_checkpoint.exists(),
                "epochs_recorded": len(candidate_history.get("history", [])),
            },
        },
        "novelty_engine": {
            "supported_signals": ["surprisal_dynamics", "free_energy_ood", "epistemic_branch_variance"],
            "novelty_threshold": 0.65,
            "zero_loss_safeguards": {
                "critical_asset_guardrail": True,
                "pre_execution_snapshots": True,
                "instant_health_rollback": True,
            },
        },
        "telemetry_v2_candidate": {
            "checkpoint_available": cand_v2_checkpoint.exists(),
            "status": cand_v2_status,
            "benchmarks": cand_v2_benchmarks.get("baselines", {}),
            "promotion_gate": cand_v2_benchmarks.get("promotion_gate_evaluation", {}),
        },
        "datasets": _dataset_inventory(),
        "dataset_audit": _dataset_audit(),
        "knowledge_flow": {
            "nodes": [
                {"id": "telemetry", "label": "Captured flow telemetry", "detail": "PCAP / flow CSV"},
                {"id": "features", "label": "35 normalized features", "detail": "flow extraction + MITRE mapping"},
                {"id": "world", "label": "Temporal world model", "detail": "observed context → K-step state forecast"},
                {"id": "belief", "label": "Belief ensemble", "detail": "multiple plausible futures + agreement"},
                {"id": "policy", "label": "Defensive policy", "detail": "risk-aware action ranking"},
            ],
            "edges": [["telemetry", "features"], ["features", "world"], ["world", "belief"], ["belief", "policy"]],
            "disclosure": "Operational summary only. The dashboard exposes evidence, confidence and branch agreement—not private chain-of-thought.",
        },
    }


@router.get("/metrics", response_model=WorldModelMetrics)
async def model_metrics(db: AsyncSession = Depends(get_db), current_user: dict = Depends(require_roles("admin"))):
    pred = _pred()
    result = world_model_metrics(pred)
    result["checkpoint_history"] = checkpoint_history_curve(pred)
    return WorldModelMetrics(**result)


@router.get("/learning/status", response_model=dict)
async def learning_state(current_user: dict = Depends(require_roles("admin"))):
    """Return append-only feedback counts and candidate-training policy."""
    return learning_status()


@router.post("/learning/feedback", response_model=dict, status_code=201)
async def learning_feedback(body: LearningFeedbackRequest, current_user: dict = Depends(require_roles("admin"))):
    """Record analyst feedback for candidate retraining.

    This endpoint never changes serving weights.  It creates an auditable
    labelled record for the offline candidate-training and promotion gate.
    """
    if body.analyst_confidence is not None and not 0 <= body.analyst_confidence <= 1:
        raise HTTPException(status_code=422, detail="analyst_confidence must be between 0 and 1")
    payload = body.model_dump()
    payload["actor"] = current_user.get("sub", "unknown")
    payload["kind"] = "novelty" if body.kind == "novelty" else "analyst"
    return append_feedback(payload, kind=payload["kind"])


@router.get("/checkpoint/history", response_model=dict)
async def checkpoint_history(current_user: dict = Depends(require_roles("admin"))):
    pred = _pred()
    return checkpoint_history_curve(pred)


@router.post("/evaluate", response_model=ForecastEvaluationResponse, status_code=201)
async def evaluate(body: EvaluateRequest, db: AsyncSession = Depends(get_db), current_user: dict = Depends(require_roles("admin"))):
    if len(body.y_true) != len(body.y_pred):
        raise HTTPException(status_code=422, detail="y_true and y_pred must have equal length")
    if not body.y_true:
        raise HTTPException(status_code=422, detail="empty samples")
    metrics = compute_classification_metrics(body.y_true, body.y_pred, labels=body.label_names)
    row = await save_evaluation(db, model_version=MODEL_VERSION, metrics=metrics)
    await db.commit()
    await db.refresh(row)
    return ForecastEvaluationResponse.model_validate(row)


@router.post("/baseline", response_model=ModelComparisonResponse)
async def baseline_comparison(body: BaselineRequest, db: AsyncSession = Depends(get_db), current_user: dict = Depends(require_roles("admin"))):
    results = await run_baseline_comparison(db, model_version=MODEL_VERSION, max_rows=body.max_rows)
    await db.commit()
    base = ModelComparisonResponse(run_type="baseline", model_version=MODEL_VERSION)
    base.baselines = results.get("baselines", [])
    base.world_model = results.get("world_model")
    base.methodology = results.get("methodology")
    base.error = results.get("error")
    return base


@router.post("/ablation", response_model=ModelComparisonResponse)
async def ablation_study(body: AblationRequest, db: AsyncSession = Depends(get_db), current_user: dict = Depends(require_roles("admin"))):
    results = await run_ablation(db, model_version=MODEL_VERSION, max_rows=body.max_rows)
    await db.commit()
    base = ModelComparisonResponse(run_type="ablation", model_version=MODEL_VERSION)
    base.systems = results.get("systems", [])
    base.methodology = results.get("methodology")
    base.error = results.get("error")
    return base


@router.get("/evaluations", response_model=List[ForecastEvaluationResponse])
async def evaluations(db: AsyncSession = Depends(get_db), current_user: dict = Depends(require_roles("admin"))):
    rows = await list_evaluations(db, limit=50)
    return [ForecastEvaluationResponse.model_validate(r) for r in rows]


@router.get("/comparisons", response_model=List[ModelComparisonResponse])
async def comparisons(db: AsyncSession = Depends(get_db), current_user: dict = Depends(require_roles("admin"))):
    rows = await list_comparisons(db, limit=50)
    out = []
    for r in rows:
        results = r.results or {}
        base = ModelComparisonResponse(run_type=r.kind, model_version=r.model_version, created_at=r.created_at,
                                       result_json=results)
        base.baselines = results.get("baselines", [])
        base.world_model = results.get("world_model")
        base.systems = results.get("systems", [])
        base.methodology = results.get("methodology")
        base.error = results.get("error")
        out.append(base)
    return out
