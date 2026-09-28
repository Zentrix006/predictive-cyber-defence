import numpy as np
import pandas as pd
import pytest
import json
from argparse import Namespace
import torch

from features.telemetry_v2 import PreprocessingArtifact, TemporalWindows, validate_observations


def observations():
    return pd.DataFrame({
        "capture_id": ["train-capture"] * 24 + ["test-capture"] * 24,
        "segment_id": ["lan"] * 48,
        "timestamp": list(pd.date_range("2026-01-01", periods=24, freq="10s", tz="UTC")) * 2,
        "partition": ["train"] * 24 + ["test"] * 24,
        "malicious": [0] * 48, "stage": [-1] * 48,
        "duration_seconds": np.arange(48, dtype=float), "protocol": ["tcp"] * 48,
    })


def test_transform_independent_of_upload_neighbors_and_holdout():
    frame = observations()
    artifact = PreprocessingArtifact.fit(frame[frame.partition == "train"], ["source-hash"])
    before = artifact.sha256
    np.testing.assert_array_equal(artifact.transform(frame.iloc[[3]])[0], artifact.transform(frame)[3])
    frame.loc[frame.partition == "test", "duration_seconds"] = 1e20
    assert artifact.sha256 == before
    assert np.isfinite(artifact.transform(frame)).all()
    with pytest.raises(ValueError, match="training data only"):
        PreprocessingArtifact.fit(frame, [])


def test_unknown_categories_and_missing_are_distinct():
    frame = observations()
    artifact = PreprocessingArtifact.fit(frame[frame.partition == "train"], [])
    frame.loc[0, "protocol"] = None
    frame.loc[1, "protocol"] = "new-protocol"
    result = artifact.transform(frame)
    assert result[0, artifact.feature_names.index("protocol=<missing>")] == 1
    assert result[1, artifact.feature_names.index("protocol=<unseen>")] == 1
    assert result[0, artifact.feature_names.index("missing_ttl_mean")] == 1


def test_no_cross_capture_or_gap_windows():
    frame = observations()
    artifact = PreprocessingArtifact.fit(frame[frame.partition == "train"], [])
    dataset = TemporalWindows(frame, artifact, "train")
    assert len(dataset) == 7
    assert dataset[0][0].shape == (12, len(artifact.feature_names))
    assert dataset[0][1].shape[0] == 6
    frame.loc[12:23, "timestamp"] += pd.Timedelta(seconds=10)
    assert len(TemporalWindows(frame, artifact, "train")) == 0


def test_capture_partition_leakage_rejected():
    frame = observations()
    frame.loc[0, "partition"] = "test"
    with pytest.raises(ValueError, match="leakage"):
        validate_observations(frame)


def test_train_reload_infer_and_corrupt_artifact(tmp_path):
    from scripts.train_temporal_v2 import run
    from inference.temporal_v2 import TemporalPredictor
    parts = []
    for part in ("train", "development", "calibration", "test"):
        rows = observations().iloc[:24].copy()
        rows["capture_id"] = part
        rows["partition"] = part
        parts.append(rows)
    frame = pd.concat(parts, ignore_index=True)
    source = tmp_path / "diagnostic_only.csv"
    frame.to_csv(source, index=False)
    output = tmp_path / "candidate"
    run(Namespace(input=str(source), out_dir=str(output), seed=42,
                  device="cpu", sanity_check=False, batch_size=8, epochs=1))
    status = json.loads((output / "training_status.json").read_text())
    assert status["status"] == "completed"
    assert not status["promotion_eligible"]
    predictor = TemporalPredictor(output / "candidate.pt")
    sample = frame[frame.partition == "test"].drop(columns=["stage", "malicious", "partition"])
    prediction = predictor.predict(sample)
    assert len(prediction["future_malicious_activity_probability"]) == 6
    assert prediction["calibrated"] is False
    with pytest.raises(ValueError, match="schema mismatch"):
        predictor.predict(sample, schema_version="legacy")
    if torch.cuda.is_available():
        cuda_prediction = TemporalPredictor(output / "candidate.pt", "cuda").predict(sample)
        np.testing.assert_allclose(prediction["future_malicious_activity_probability"],
                                   cuda_prediction["future_malicious_activity_probability"], atol=1e-4)
    checkpoint = torch.load(output / "candidate.pt", weights_only=False)
    checkpoint["preprocessing"]["median"][0] += 1
    torch.save(checkpoint, output / "corrupt.pt")
    with pytest.raises(ValueError, match="hash mismatch"):
        TemporalPredictor(output / "corrupt.pt")


def test_failed_training_records_failure(tmp_path):
    from scripts.train_temporal_v2 import run
    source = tmp_path / "invalid.csv"
    observations().to_csv(source, index=False)
    output = tmp_path / "failed"
    with pytest.raises(ValueError, match="Each partition"):
        run(Namespace(input=str(source), out_dir=str(output), seed=42,
                      device="cpu", sanity_check=False, batch_size=8, epochs=1))
    assert json.loads((output / "training_status.json").read_text())["status"] == "failed"
    assert not (output / "candidate.pt").exists()


def test_cse_2018_stage_mapping_is_explicit():
    from scripts.prepare_cse_cic_2018 import stage_for
    from features.mitre_map import MITRE_STAGES
    assert stage_for("Benign") == -1
    assert MITRE_STAGES[stage_for("FTP-BruteForce")] == "credential_access"
    assert MITRE_STAGES[stage_for("Infilteration")] == "lateral_movement"
    assert MITRE_STAGES[stage_for("Bot")] == "command_and_control"
    assert MITRE_STAGES[stage_for("DDoS attacks-LOIC-HTTP")] == "impact"
