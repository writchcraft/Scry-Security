"""File-change evidence feeds the same rules and persistent investigation API."""

from fastapi.testclient import TestClient

from scry_security.api.app import create_app
from scry_security.database.database import Database
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.integrity.monitor import compare_baseline, create_baseline


def test_integrity_baseline_scan_detection_and_api(tmp_path):
    path = tmp_path / "sensitive.txt"
    path.write_text("known state")
    baseline = create_baseline(
        [path], approved_by="Lab analyst", approval_note="Known synthetic state", synthetic=True
    )
    database = Database(tmp_path / "fim.sqlite")
    store = Store(database)
    try:
        store.save_baseline(baseline)
        stable = compare_baseline(baseline)
        assert stable.events == []
        store.save_integrity_scan(stable)
        path.write_text("changed state")
        scan = compare_baseline(baseline)
        assert store.ingest(scan.events, load_rules()) == {"added_events": 1, "added_alerts": 1}
        store.save_integrity_scan(scan)
        assert store.alerts()[0].rule_id == "SCRY-FILE-001"
        token = "synthetic-fim-test-token-at-least-32-characters"
        with TestClient(create_app(store, token)) as client:
            assert client.get("/api/integrity").status_code == 401
            response = client.get(
                "/api/integrity?synthetic=true", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            assert response.json()[0]["latest_scan"]["events"][0]["event_type"] == "file_modified"
            assert (
                client.get(
                    "/api/integrity?synthetic=false", headers={"Authorization": f"Bearer {token}"}
                ).json()
                == []
            )
    finally:
        database.close()
