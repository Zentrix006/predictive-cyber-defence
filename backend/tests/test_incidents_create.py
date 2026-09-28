"""Incident creation API tests (regression for the assets_involved TypeError)."""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import delete

from tests.conftest import db_run


def _admin_headers() -> dict[str, str]:
    """Authenticate test mutations without weakening the production guard."""
    from app.core.security import create_access_token

    token = create_access_token(
        uuid.uuid4(),
        expires_delta=timedelta(minutes=5),
        additional_claims={"roles": ["admin"], "elevated": True},
    )
    return {"Authorization": f"Bearer {token}"}


def _delete_incident(incident_id) -> None:
    from app.models.incident import Incident

    async def _del(session):
        await session.execute(delete(Incident).where(Incident.id == incident_id))
        await session.commit()

    db_run(_del)


def test_create_incident_accepts_assets_involved(client):
    asset_id = str(uuid.uuid4())
    r = client.post(
        "/api/v1/incidents",
        json={"title": "httptest incident", "severity": "medium", "assets_involved": [asset_id]},
        headers=_admin_headers(),
    )
    assert r.status_code == 201
    data = r.json()
    assert data["id"]
    assert data["status"] == "open"
    assert data["severity"] == "medium"
    _delete_incident(uuid.UUID(data["id"]))


def test_create_incident_minimal_payload(client):
    r = client.post("/api/v1/incidents", json={"title": "min", "severity": "low"}, headers=_admin_headers())
    assert r.status_code == 201
    _delete_incident(uuid.UUID(r.json()["id"]))


def test_create_incident_requires_title_and_severity(client):
    r = client.post("/api/v1/incidents", json={"description": "missing fields"}, headers=_admin_headers())
    assert r.status_code == 422
    locs = {(d["loc"][1] if len(d["loc"]) > 1 else d["loc"][0]) for d in r.json()["detail"]}
    assert {"title", "severity"} <= locs
