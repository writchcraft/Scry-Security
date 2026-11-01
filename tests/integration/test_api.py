"""Authenticated API contracts over real synthetic SQLite evidence."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scry_security.api.app import create_app
from scry_security.database.database import Database
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.services.replay import replay_file

TOKEN = "synthetic-test-token-with-at-least-32-characters"


@pytest.fixture
def client(tmp_path):
    database = Database(tmp_path / "api.sqlite")
    store = Store(database)
    root = Path(__file__).resolve().parents[2]
    result = replay_file(
        root / "sample_logs/linux/suspicious/brute_force.txt",
        format="linux",
        rules=load_rules(),
        synthetic=True,
    )
    store.ingest(result.events, load_rules())
    with TestClient(create_app(store, TOKEN)) as client:
        yield client
    database.close()


def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def test_all_api_routes_require_authentication(client):
    for path in ["/api/summary", "/api/events", "/api/alerts", "/api/rules", "/api/hosts"]:
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert client.get("/", headers={"Host": "attacker.invalid"}).status_code == 400
    response = client.get("/")
    assert response.status_code == 200
    assert "Bring the evidence" in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/chart.umd.min.js").status_code == 200


def test_large_body_is_rejected_before_parsing(client):
    assert client.post("/api/incidents", content=b"x" * 65_537, headers=auth()).status_code == 413
    assert client.patch("/api/alerts/not-an-id/status", content=b"x" * 65_537).status_code == 413


def test_summary_uses_stored_data_and_synthetic_filter(client):
    summary = client.get("/api/summary?synthetic=true", headers=auth()).json()
    assert summary["total_events"] == 6
    assert summary["total_alerts"] == 2
    assert summary["statuses"] == {"new": 2}
    assert summary["synthetic_events"] == 6
    assert summary["authentication_failures"] == 5
    assert summary["hosts"] == {"linux": 1}
    assert summary["top_sources"] == [{"address": "192.0.2.10", "count": 2}]
    real = client.get("/api/summary?synthetic=false", headers=auth()).json()
    assert real["total_events"] == real["total_alerts"] == 0


def test_alert_investigation_and_filters(client):
    alerts = client.get("/api/alerts?status=new&operating_system=linux", headers=auth()).json()
    assert len(alerts) == 2
    selected = alerts[0]
    detail = client.get(f"/api/alerts/{selected['alert_id']}", headers=auth()).json()
    assert len(detail["events"]) == selected["evidence_count"]
    change = {
        "status": "investigating",
        "actor": "lab analyst",
        "note": "Reviewing source ownership",
    }
    assert (
        client.patch(
            f"/api/alerts/{selected['alert_id']}/status", headers=auth(), json=change
        ).status_code
        == 200
    )
    assert len(client.get("/api/alerts?status=investigating", headers=auth()).json()) == 1
    stale = {
        "status": "resolved",
        "actor": "another analyst",
        "note": "Stale page",
        "expected_revision": 1,
    }
    assert (
        client.patch(
            f"/api/alerts/{selected['alert_id']}/status", headers=auth(), json=stale
        ).status_code
        == 409
    )
    assert (
        client.patch(f"/api/alerts/{selected['alert_id']}/status", json=change).status_code == 401
    )
    assert client.get("/api/events?limit=1&offset=1", headers=auth()).status_code == 200
    assert client.get("/api/events?operating_system=windows", headers=auth()).json() == []
    assert client.get("/api/events?limit=1001", headers=auth()).status_code == 422
    assert client.get("/api/alerts?since=2026-01-01T00:00:00", headers=auth()).status_code == 422
    assert client.get("/api/alerts?hostname=%27%20OR%201%3D1--", headers=auth()).json() == []
