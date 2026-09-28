"""Versioned measured telemetry: train-fitted preprocessing and indexed windows.

Inputs are time-windowed observations, not arbitrary consecutive CSV flows.
No legacy proxy columns or inferred MITRE labels are accepted here.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd
from torch.utils.data import Dataset

NUMERIC = (
    "duration_seconds", "forward_packets", "reverse_packets", "forward_bytes",
    "reverse_bytes", "iat_mean_seconds", "iat_variance_seconds2", "iat_max_seconds",
    "ttl_mean", "ttl_variance", "tcp_window_mean", "fragment_count",
    "payload_mean_bytes", "payload_variance_bytes2", "retransmissions",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
    "unique_destination_ports", "unique_destination_hosts", "bidirectional_ratio",
)
CATEGORICAL = ("protocol", "device_role", "vendor")
PARTITIONS = {"train", "development", "calibration", "test"}


@dataclass
class PreprocessingArtifact:
    schema_version: str
    median: list
    scale: list
    vocabularies: dict
    training_hashes: list

    @property
    def feature_names(self):
        names = list(NUMERIC) + [f"missing_{n}" for n in NUMERIC]
        for col in CATEGORICAL:
            names += [f"{col}={v}" for v in self.vocabularies[col]]
        return names

    @property
    def sha256(self):
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()

    @classmethod
    def fit(cls, frame, training_hashes):
        if frame.empty or set(frame["partition"]) != {"train"}:
            raise ValueError("Preprocessing must be fitted on nonempty training data only")
        values = numeric_values(frame)
        # All-missing features have an explicit mask and neutral imputation.
        median, scale = [], []
        for column in values.T:
            observed = column[np.isfinite(column)]
            median.append(float(np.median(observed)) if len(observed) else 0.0)
            spread = float(np.percentile(observed, 75) - np.percentile(observed, 25)) if len(observed) else 1.0
            scale.append(spread if spread > 1e-6 else 1.0)
        vocab = {}
        for col in CATEGORICAL:
            vals = frame[col].dropna().astype(str).unique() if col in frame else []
            vocab[col] = ["<missing>", "<unseen>"] + sorted(set(vals) - {"<missing>", "<unseen>"})
        return cls("telemetry-v2", median, scale, vocab, sorted(training_hashes))

    def transform(self, frame):
        if self.schema_version != "telemetry-v2":
            raise ValueError("Unsupported preprocessing schema")
        values = numeric_values(frame)
        missing = ~np.isfinite(values)
        filled = np.where(missing, np.asarray(self.median), values)
        parts = [np.clip((filled - self.median) / self.scale, -10, 10), missing.astype(float)]
        for col in CATEGORICAL:
            vocab = self.vocabularies[col]
            index = {value: i for i, value in enumerate(vocab)}
            vals = frame[col] if col in frame else pd.Series([None] * len(frame))
            ids = [0 if pd.isna(v) else index.get(str(v), 1) for v in vals]
            parts.append(np.eye(len(vocab), dtype=np.float32)[ids])
        return np.concatenate(parts, axis=1).astype(np.float32)


def numeric_values(frame):
    return frame.reindex(columns=NUMERIC).apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float64)


def validate_observations(frame):
    required = {"capture_id", "segment_id", "timestamp", "partition", "malicious", "stage"}
    if required - set(frame.columns):
        raise ValueError(f"Missing telemetry columns: {sorted(required - set(frame.columns))}")
    if frame.empty or frame[list(required)].isna().any().any():
        raise ValueError("Empty telemetry or missing observation identity/labels")
    if not set(frame.partition).issubset(PARTITIONS):
        raise ValueError("Invalid partition")
    if (frame.groupby("capture_id").partition.nunique() > 1).any():
        raise ValueError("Capture leakage across partitions")
    # Campaign/site boundaries are stronger than capture boundaries. If the
    # adapter provides these columns, enforce them before any window is built.
    for identity in ("campaign_id", "site_id"):
        if identity in frame and (frame.groupby(identity).partition.nunique() > 1).any():
            raise ValueError(f"{identity} leakage across partitions")
    if not frame.malicious.isin([0, 1]).all():
        raise ValueError("malicious must be an annotated binary label")
    if not frame.stage.isin(range(-1, 13)).all():
        raise ValueError("stage must be -1 (unlabelled/benign) or a supported MITRE index 0..12")
    if "label_confidence" in frame and not frame.label_confidence.between(0, 1).all():
        raise ValueError("label_confidence must be between 0 and 1")
    result = frame.copy()
    result["timestamp"] = pd.to_datetime(result.timestamp, utc=True, errors="raise")
    if result.duplicated(["capture_id", "segment_id", "timestamp"]).any():
        raise ValueError("Duplicate segment time windows")
    return result.sort_values(["capture_id", "segment_id", "timestamp"]).reset_index(drop=True)


def quality_summary(frame):
    """Return training-quality facts without altering the input frame."""
    frame = validate_observations(frame)
    numeric = frame.reindex(columns=NUMERIC).apply(pd.to_numeric, errors="coerce")
    missingness = numeric.isna().mean().to_dict()
    return {
        "rows": int(len(frame)),
        "captures": int(frame.capture_id.nunique()),
        "campaigns": int(frame.campaign_id.nunique()) if "campaign_id" in frame else None,
        "partitions": sorted(frame.partition.unique().tolist()),
        "stage_support": {str(k): int(v) for k, v in frame.loc[frame.stage >= 0, "stage"].value_counts().to_dict().items()},
        "malicious_support": {str(k): int(v) for k, v in frame.malicious.value_counts().to_dict().items()},
        "missingness": {k: round(float(v), 6) for k, v in missingness.items()},
        "label_confidence_mean": float(frame.label_confidence.mean()) if "label_confidence" in frame else 1.0,
    }


class TemporalWindows(Dataset):
    """Store observations once; overlapping sequences are sliced on demand."""

    def __init__(self, frame, artifact, partition, context=12, horizon=6, seconds=10):
        if context < 1 or horizon < 1 or seconds < 1:
            raise ValueError("Window sizes must be positive")
        frame = validate_observations(frame)
        frame = frame[frame.partition == partition].reset_index(drop=True)
        self.features = artifact.transform(frame)
        self.stage = frame.stage.to_numpy(dtype=np.int64)
        self.malicious = frame.malicious.to_numpy(dtype=np.float32)
        self.context, self.horizon = context, horizon
        self.starts = []
        for _, group in frame.groupby(["capture_id", "segment_id"], sort=False):
            indices = group.index.to_numpy()
            times = group.timestamp.astype("int64").to_numpy()
            breaks = np.flatnonzero(np.diff(times) != seconds * 1_000_000_000) + 1
            for run in np.split(indices, breaks):
                if len(run) >= context + horizon:
                    self.starts.extend(range(int(run[0]), int(run[-1]) - context - horizon + 2))

    def __len__(self):
        return len(self.starts)

    def __getitem__(self, index):
        start = self.starts[index]
        mid, end = start + self.context, start + self.context + self.horizon
        return (self.features[start:mid], self.features[mid:end],
                self.stage[mid:end], self.malicious[mid:end])
