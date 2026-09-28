"""Inference for explicitly selected telemetry-v2 research checkpoints."""
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from features.telemetry_v2 import PreprocessingArtifact
from models.flow_world_model import FlowWorldModel


class TemporalPredictor:
    def __init__(self, checkpoint: Path, device="cpu"):
        self.device = torch.device(device)
        payload = torch.load(checkpoint, map_location=self.device, weights_only=False)
        if payload.get("schema_version") != "telemetry-v2" or payload.get("forecast_branch") != "base":
            raise ValueError("Incompatible checkpoint schema or forecast branch")
        self.artifact = PreprocessingArtifact(**payload["preprocessing"])
        if self.artifact.sha256 != payload.get("preprocessing_sha256"):
            raise ValueError("Checkpoint preprocessing hash mismatch")
        if self.artifact.feature_names != payload.get("feature_names"):
            raise ValueError("Checkpoint feature order mismatch")
        self.config = payload["model_config"]
        if self.config["feature_dim"] != len(self.artifact.feature_names):
            raise ValueError("Checkpoint feature dimension mismatch")
        self.temperature = float(payload.get("stage_temperature", payload.get("temperature", 1.0)))
        self.malicious_temperature = float(payload.get("malicious_temperature", 1.0))
        self.model = FlowWorldModel(**self.config).to(self.device)
        self.model.load_state_dict(payload["model_state"], strict=True)
        self.model.eval()

    def predict(self, frame, schema_version="telemetry-v2"):
        if schema_version != self.artifact.schema_version:
            raise ValueError("Telemetry schema mismatch")
        for column in ("timestamp", "capture_id", "segment_id"):
            if column not in frame or frame[column].isna().any():
                raise ValueError(f"Missing observation identity: {column}")
        if frame.capture_id.nunique() != 1 or frame.segment_id.nunique() != 1:
            raise ValueError("Inference requires one capture and segment")
        frame = frame.copy()
        frame["timestamp"] = pd.to_datetime(frame.timestamp, utc=True, errors="raise")
        frame = frame.sort_values("timestamp")
        context = self.config["context_window"]
        if len(frame) < context:
            raise ValueError("Insufficient observed history")
        frame = frame.iloc[-context:]
        if not np.all(np.diff(frame.timestamp.astype("int64")) == 10_000_000_000):
            raise ValueError("History contains missing or duplicate 10-second windows")
        x = torch.from_numpy(self.artifact.transform(frame)).unsqueeze(0).to(self.device)
        with torch.no_grad():
            result = self.model(x)
        calibrated_stage_logits = result.stage_logits[0] / max(self.temperature, 0.01)
        calibrated_malicious_logits = result.infil_logits[0] / max(self.malicious_temperature, 0.01)
        return {"stage_probabilities": torch.softmax(calibrated_stage_logits, -1).cpu().tolist(),
                "future_malicious_activity_probability": torch.sigmoid(calibrated_malicious_logits).cpu().tolist(),
                "horizon_seconds": [(i + 1) * 10 for i in range(self.config["horizon"])],
                "preprocessing_sha256": self.artifact.sha256,
                "temperature": self.temperature,
                "malicious_temperature": self.malicious_temperature,
                "calibrated": self.temperature != 1.0 or self.malicious_temperature != 1.0,
                "research_candidate": True}
