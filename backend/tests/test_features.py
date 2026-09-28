"""Feature extraction pipeline contract tests (ml-engine)."""
from __future__ import annotations

import io

import numpy as np
import pandas as pd
import pytest

from features.extract import (
    FLOW_FEATURE_COLS,
    PACKET_FEATURE_COLS,
    CATEGORICAL_COLS,
    dataframe_to_feature_matrix,
    load_cicflowmeter_csv,
    load_nsl_kdd_csv,
)
from features.mitre_map import MITRE_STAGES, attack_label_to_mitre


EXPECTED_DIM = len(FLOW_FEATURE_COLS) + len(PACKET_FEATURE_COLS) + len(CATEGORICAL_COLS)


def test_feature_matrix_shape_contract():
    df = pd.DataFrame({"dur": [1.0], "proto": ["tcp"]})
    m = dataframe_to_feature_matrix(df)
    assert m.features.shape[1] == EXPECTED_DIM == 35
    assert len(m.feature_names) == 35
    assert m.features.dtype == np.float32


@pytest.mark.parametrize(
    "label,expected",
    [
        ("1", "command_and_control"),   # CTU-13 numeric botnet traffic
        ("0", "unknown"),               # CTU-13 normal
        ("neptune", "impact"),
        ("Fuzzers", "reconnaissance"),
        ("Generic", "impact"),
        ("Backdoor", "persistence"),
        ("Worms", "lateral_movement"),
        ("portsweep", "reconnaissance"),
        ("rootkit", "persistence"),
        ("Benign", "unknown"),
        ("Bot", "command_and_control"),
    ],
)
def test_attack_label_to_mitre(label, expected):
    idx = attack_label_to_mitre(label)
    assert MITRE_STAGES[idx] == expected


def test_numeric_labels_keep_ctu_mapping():
    """Regression: numeric 0/1 labels must NOT be collapsed to 'Attack'."""
    stream = io.StringIO(
        "flow duration,total fwd packets,label\n"
        "123,2,1\n"
        "321,4,0\n"
    )
    df = load_cicflowmeter_csv(stream)
    assert set(df["attack_cat"]) == {"1", "0"}
    stages = np.array([attack_label_to_mitre(c) for c in df["attack_cat"]])
    assert MITRE_STAGES[stages[0]] == "command_and_control"
    assert MITRE_STAGES[stages[1]] == "unknown"


def test_string_labels_pass_through_cic():
    stream = io.StringIO(
        "flow duration,total fwd packets,Label\n"
        "123,2,Benign\n"
        "321,4,Bot\n"
    )
    df = load_cicflowmeter_csv(stream)
    cats = set(df["attack_cat"])
    assert "Bot" in cats and "Benign" in cats
    stages = np.array([attack_label_to_mitre(c) for c in df["attack_cat"]])
    assert MITRE_STAGES[stages[1]] == "command_and_control"


def test_nsl_kdd_stage_labels():
    stream = io.StringIO(
        "0,tcp,http,SF,181,5450,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,8,8,0.00,0.00,0.00,0.00,1.00,0.00,0.00,19,19,1.00,0.00,0.10,0.00,0.00,0.00,0.00,0.00,neptune,0\n"
        "0,tcp,private,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,15,15,1.00,1.00,0.00,0.00,0.00,0.00,0.00,255,255,1.00,0.00,0.00,0.15,0.00,0.00,0.00,0.00,normal,0\n"
    )
    m = dataframe_to_feature_matrix(load_nsl_kdd_csv(stream))
    assert m.stages is not None
    assert len(m.attack_cats) == 2
    stage_names = [MITRE_STAGES[s] for s in m.stages]
    assert stage_names[0] == "impact"   # neptune -> DoS -> impact
    assert stage_names[1] == "unknown"  # normal
    assert int(m.labels[0]) == 1


def test_labels_only_fallback_still_outputs_stages():
    df = pd.DataFrame({"dur": [1.0, 2.0], "proto": ["tcp", "udp"], "label": [1, 0]})
    m = dataframe_to_feature_matrix(df)
    assert m.stages is not None
    assert m.attack_cats == ["Attack", "Normal"]