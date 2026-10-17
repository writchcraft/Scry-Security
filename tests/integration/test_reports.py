"""Saved investigation snapshots, safe exports and authenticated reporting routes."""

import csv
import io
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from scry_security.alerts.manager import AlertStatus
from scry_security.api.app import create_app
from scry_security.database.database import Database
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.reports.incident_report import build_report
from scry_security.reports.report_generator import export_report
from scry_security.services.replay import replay_file


@pytest.fixture
def store(tmp_path):
    database = Database(tmp_path / "reports.sqlite")
    store = Store(database)
    path = Path(__file__).resolve().parents[2] / "sample_logs/linux/suspicious/brute_force.txt"
    result = replay_file(path, format="linux", rules=load_rules(), synthetic=True)
    store.ingest(result.events, load_rules())
    yield store
    database.close()


def test_snapshot_persistence_and_exports(store):
    alerts = store.alerts()
    report = store.create_incident(
        [alert.alert_id for alert in alerts],
        title="Suspected SSH brute force",
        summary="Synthetic repeated failures and success.",
        analyst="Lab analyst",
        analyst_findings="Intent remains unconfirmed.",
    )
    assert len(report.timeline) == 6  # evidence shared by two alerts is not duplicated
    assert report.synthetic
    assert report.accounts == ["alice"]
    assert report.source_addresses == ["192.0.2.10"]
    assert len(store.incidents(synthetic=True)) == 1
    assert store.incidents(synthetic=False) == []
    store.set_status(
        alerts[0].alert_id, AlertStatus.RESOLVED, actor="Analyst", note="Later lab resolution"
    )
    saved = store.incident(report.incident_id)
    assert saved.alerts[0].status == AlertStatus.NEW
    assert '"report_version": 1' in export_report(saved, "json")
    rows = list(csv.DictReader(io.StringIO(export_report(saved, "csv"))))
    assert len(rows) == 6
    assert rows[0]["synthetic"] == "True"
    html = export_report(saved, "html")
    assert "SYNTHETIC LAB INVESTIGATION" in html
    assert "Observed evidence" in html and "Analyst interpretation" in html
    assert "Intent remains unconfirmed." in html


def test_html_and_csv_handle_untrusted_strings(store):
    alert = store.alerts()[0]
    events = store.supporting_events(alert.alert_id)
    malicious = events[0].model_copy(
        update={
            "username": '=HYPERLINK("https://example.invalid")',
            "raw": {"line": "<script>alert(1)</script>"},
        }
    )
    events[0] = malicious
    report = build_report(
        [alert],
        events,
        title="<img src=x onerror=alert(1)>",
        summary="=FORMULA()",
        analyst="analyst",
    )
    html = export_report(report, "html")
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    rows = list(csv.DictReader(io.StringIO(export_report(report, "csv"))))
    assert rows[0]["summary"].startswith("'=")
    assert next(row["username"] for row in rows if "HYPERLINK" in row["username"]).startswith("'=")
    with pytest.raises(ValueError):
        build_report(
            [alert], events[:-1], title="Missing evidence", summary="Incomplete", analyst="analyst"
        )
    with pytest.raises(ValueError):
        store.create_incident(
            [alert.alert_id, alert.alert_id],
            title="Duplicate",
            summary="Invalid",
            analyst="analyst",
        )


def test_reporting_routes_require_token_and_export_stored_snapshot(store):
    token = "synthetic-report-test-token-at-least-32-characters"
    headers = {"Authorization": f"Bearer {token}"}
    alert = store.alerts()[0]
    with TestClient(create_app(store, token)) as client:
        assert client.get("/api/incidents").status_code == 401
        request = {
            "alert_ids": [str(alert.alert_id)],
            "title": "Synthetic lab",
            "summary": "Review required",
            "analyst": "Lab analyst",
        }
        assert client.post("/api/incidents", json=request).status_code == 401
        response = client.post("/api/incidents", json=request, headers=headers)
        assert response.status_code == 201
        incident_id = response.json()["incident_id"]
        assert (
            client.get(f"/api/incidents/{incident_id}", headers=headers).json()["title"]
            == "Synthetic lab"
        )
        for format in ["json", "csv", "html"]:
            response = client.get(
                f"/api/incidents/{incident_id}/export?format={format}", headers=headers
            )
            assert response.status_code == 200
            assert "attachment" in response.headers["content-disposition"]
        assert client.get(f"/api/incidents/{incident_id}/export").status_code == 401
        assert client.get(f"/api/incidents/{uuid4()}", headers=headers).status_code == 404
        assert (
            client.get("/api/summary?synthetic=true", headers=headers).json()["incident_count"] == 1
        )
        assert (
            client.get("/api/summary?synthetic=false", headers=headers).json()["incident_count"]
            == 0
        )
