"""Real SQLite persistence, replay deduplication, evidence links and rollback."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select, text

from scry_security.alerts.manager import AlertStatus
from scry_security.database.database import Database
from scry_security.database.models import AlertRecord, EventRecord
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.services.replay import replay_file


def fixture_replay():
    path = Path(__file__).resolve().parents[2] / "sample_logs/linux/suspicious/brute_force.txt"
    return replay_file(path, format="linux", rules=load_rules(), synthetic=True)


def test_persist_restart_idempotency_and_status(tmp_path):
    path = tmp_path / "private" / "scry.sqlite"
    database = Database(path)
    store = Store(database)
    result = store.ingest(fixture_replay().events, load_rules())
    assert result == {"added_events": 6, "added_alerts": 2}
    # Fresh parsing creates new ingestion UUIDs, but identical evidence deduplicates.
    assert store.ingest(fixture_replay().events, load_rules()) == {
        "added_events": 0,
        "added_alerts": 0,
    }
    alerts = store.alerts(operating_system="linux", synthetic=True)
    assert len(alerts) == 2
    assert store.alerts(synthetic=False) == []
    assert store.alerts(hostname="absent") == []
    assert len(store.alerts(limit=1, offset=1)) == 1
    chosen = alerts[0]
    assert len(store.supporting_events(chosen.alert_id)) == chosen.evidence_count
    updated = store.set_status(
        chosen.alert_id,
        AlertStatus.INVESTIGATING,
        actor="analyst",
        note="Checking owner and source",
    )
    assert updated.history[0].actor == "analyst"
    database.close()
    reopened = Database(path)
    try:
        assert Store(reopened).alert(chosen.alert_id).status == AlertStatus.INVESTIGATING
        assert len(Store(reopened).alerts(status=AlertStatus.NEW)) == 1
        with reopened.sessions() as session:
            assert session.scalar(text("PRAGMA foreign_keys")) == 1
    finally:
        reopened.close()


def test_rollback_on_uuid_evidence_conflict_and_safe_retention(tmp_path):
    database = Database(tmp_path / "scry.sqlite")
    store = Store(database)
    try:
        events = fixture_replay().events
        store.ingest(events, load_rules())
        changed = events[0].model_copy(update={"username": "changed"})
        with pytest.raises(ValueError, match="UUID reused"):
            store.ingest(
                [
                    events[0].model_copy(
                        update={"event_id": events[1].event_id, "hostname": "new-host"}
                    ),
                    changed,
                ],
                load_rules(),
            )
        with database.sessions() as session:
            assert session.scalar(select(func.count()).select_from(EventRecord)) == 6
            assert session.scalar(select(func.count()).select_from(AlertRecord)) == 2
        # All six records are linked evidence and must survive cleanup.
        assert store.cleanup_unlinked(datetime(2027, 1, 1, tzinfo=UTC)) == 0
        benign = events[0].model_copy(
            update={
                "event_id": __import__("uuid").uuid4(),
                "hostname": "benign-host",
                "event_type": "logoff",
            }
        )
        store.ingest([benign], load_rules())
        assert store.cleanup_unlinked(datetime(2027, 1, 1, tzinfo=UTC)) == 1
    finally:
        database.close()
