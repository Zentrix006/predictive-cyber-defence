import uuid
from datetime import timedelta
import pytest
from app.core.security import create_access_token


def _admin_headers() -> dict[str, str]:
    token = create_access_token(
        uuid.uuid4(),
        expires_delta=timedelta(minutes=5),
        additional_claims={"roles": ["admin"], "elevated": True},
    )
    return {"Authorization": f"Bearer {token}"}


def test_canary_status_endpoint(client):
    response = client.get("/api/v1/canary/status", headers=_admin_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "current_phase" in data
    assert data["serving_model"] == "flow-wm-v3.0.0"
    assert data["candidate_model"] == "G-FLOWWM"
    assert "metrics" in data
    assert "avg_candidate_latency_ms" in data["metrics"]


def test_canary_evaluation_and_advancement_pipeline(client):
    headers = _admin_headers()
    # 1. Evaluate Canary
    eval_resp = client.post(
        "/api/v1/canary/evaluate",
        json={
            "retained_accuracy": 0.96,
            "critical_asset_protection_rate": 1.0,
            "max_candidate_latency_ms": 50.0,
        },
        headers=headers,
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert "passed_all_gates" in eval_data
    assert "ece_metric" in eval_data
    assert eval_data["gate_details"]["zero_loss_critical_protection"] is True

    # 2. Advance Canary
    adv_resp = client.post("/api/v1/canary/advance", headers=headers)
    assert adv_resp.status_code == 200
    adv_data = adv_resp.json()
    assert "new_phase" in adv_data

    # 3. Emergency Rollback
    rb_resp = client.post(
        "/api/v1/canary/rollback",
        json={"reason": "Simulated live telemetry divergence in canary test"},
        headers=headers,
    )
    assert rb_resp.status_code == 200
    rb_data = rb_resp.json()
    assert rb_data["status"] == "rolled_back"
    assert rb_data["phase"] == "ROLLED_BACK"
    assert rb_data["active_model"] == "serving_flow-wm-v3.0.0"


def test_epistemic_deception_api_pipeline(client):
    headers = _admin_headers()
    # 1. Dynamically provision a sandbox
    prov_resp = client.post(
        "/api/v1/deception/epistemic/provision",
        json={
            "attacker_ip": "10.0.4.55",
            "target_port": 445,
            "target_protocol": "TCP",
            "platform": "linux_nftables",
        },
        headers=headers,
    )
    assert prov_resp.status_code == 201
    prov_data = prov_resp.json()
    assert prov_data["status"] == "deployed"
    sandbox = prov_data["sandbox"]
    sandbox_id = sandbox["sandbox_id"]
    assert sandbox["decoy_type"] == "dionaea"
    assert "dnat to" in prov_data["diversion_rule"]

    # 2. Ingest attacker commands & dropped binary
    ingest_resp = client.post(
        "/api/v1/deception/epistemic/ingest",
        json={
            "sandbox_id": sandbox_id,
            "commands": [
                "whoami /all",
                "mimikatz.exe sekurlsa::logonpasswords exit",
            ],
            "payload_hex": "4d5a900003000000746573747061796c6f6164",
        },
        headers=headers,
    )
    assert ingest_resp.status_code == 200
    ingest_data = ingest_resp.json()
    assert ingest_data["status"] == "CAPTURED"
    assert any("T1003" in t for t in ingest_data["extracted_ttps"])
    assert ingest_data["closed_loop_learning_active"] is True
    assert ingest_data["replay_buffer_size"] >= 1

    # 3. List active epistemic sandboxes
    list_resp = client.get("/api/v1/deception/epistemic/sandboxes", headers=headers)
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["count"] >= 1
    assert any(s["sandbox_id"] == sandbox_id for s in list_data["sandboxes"])

