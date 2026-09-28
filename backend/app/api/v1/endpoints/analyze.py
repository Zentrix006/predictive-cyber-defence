"""
World-model analyse API — offline PCAP/CSV upload → K-step forecast + explainability.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, ConfigDict
from app.api.deps import get_current_user

# ml-engine is mounted / available beside backend in compose; also support local path
_CANDIDATES = [
    Path("/ml-engine"),
    Path(__file__).resolve().parents[5] / "ml-engine",
]
for _p in _CANDIDATES:
    if (_p / "inference").exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
        break

router = APIRouter()


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    infiltration_timeline: list
    predicted_stages: list
    stage_probabilities: list
    current_stage: str
    current_confidence: float
    top_features: list
    attention_summary: list
    natural_language: str
    model_version: str
    datasets_trained: list
    flagged_flow_indices: list
    num_flows: int
    feature_count: int
    flow_meta: list = Field(default_factory=list)
    pcap_summary: Optional[dict] = None
    pcap_parse: Optional[dict] = None
    thinking: Optional[dict] = None
    recommended_action: str = "monitor"
    recommended_actions: List[dict] = Field(default_factory=list)
    novelty: List[dict] = Field(default_factory=list)
    novelty_score: float = 0.0
    novelty_state: str = "within_known_distribution"
    novelty_evidence: dict = Field(default_factory=dict)


class ModelStatus(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    ready: bool
    checkpoint: Optional[str] = None
    datasets_trained: list = Field(default_factory=list)
    model_version: str = "flow-wm-v3.0.0"
    message: str = ""


def _get_predictor():
    try:
        from inference.predictor import get_predictor
        return get_predictor()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"ML engine unavailable: {e}")


@router.get("/status", response_model=ModelStatus)
async def model_status(current_user: dict = Depends(get_current_user)):
    """World model readiness (trained weights present)."""
    try:
        pred = _get_predictor()
        return ModelStatus(
            ready=pred.ready,
            checkpoint=str(pred.checkpoint) if pred.checkpoint else None,
            datasets_trained=list(pred.meta.get("datasets", [])) if pred.ready else [],
            message="ready" if pred.ready else "Train with ml-engine/scripts/train_real.py",
        )
    except HTTPException:
        return ModelStatus(ready=False, message="ML engine not on PYTHONPATH")


@router.post("/upload", response_model=AnalyzeResponse)
async def analyze_upload(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """
    Accept CSV (UNSW/CIC/NSL-KDD style) or PCAP and run world-model inference offline.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="filename required")
    name = file.filename.lower()
    if not (name.endswith(".csv") or name.endswith(".pcap") or name.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Upload a .csv, .pcap, or .pcapng file")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")

    pred = _get_predictor()
    if not pred.ready:
        raise HTTPException(
            status_code=503,
            detail="World model not trained yet. Run ml-engine/scripts/train_real.py",
        )
    try:
        result = pred.predict_upload(data, file.filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Analysis failed: {e}")
    return AnalyzeResponse(**result)
