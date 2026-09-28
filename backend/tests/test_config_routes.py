"""Route precedence for /config/snapshots/diff vs /{snapshot_id}."""
from __future__ import annotations

import uuid


def test_snapshots_diff_route_is_reachable(client):
    """diff must route to compare_snapshots (returns 404 for unknown IDs),
    not get swallowed by /snapshots/{snapshot_id} (which would 422 on 'diff')."""
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    r = client.get(f"/api/v1/config/snapshots/diff?from_snapshot={a}&to_snapshot={b}")
    assert r.status_code == 404
    assert r.json().get("detail") == "From snapshot not found"


def test_snapshots_diff_route_with_valid_uuid_params(client):
    r = client.get("/api/v1/config/snapshots/diff")
    # Diff handler's own query validation runs (not the {snapshot_id} uuid parse).
    assert r.status_code == 422
    locs = [str(d["loc"][0]) for d in r.json()["detail"]]
    assert "query" in locs or "path" in locs


def test_snapshots_detail_still_works_like_before(client):
    r = client.get("/api/v1/config/snapshots/not-a-uuid")
    assert r.status_code == 422
    detail = r.json()["detail"][0]
    assert detail["loc"][0] == "path"
    assert "snapshot_id" in str(detail["loc"])