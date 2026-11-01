"""Investigation status, evidence preservation and repeat-finding identity."""

import pytest

from scry_security.alerts.manager import AlertStatus, change_status, create_alert
from scry_security.detection.engine import DetectionEngine
from scry_security.detection.rules import initial_rules
from scry_security.parsers.linux_parser import parse_auth_line


def finding():
    events = [
        parse_auth_line(
            f"2026-10-31T10:30:0{i}Z lab sshd[1]: Failed password for alice "
            "from 192.0.2.1 port 51000 ssh2",
            synthetic=True,
        ).event
        for i in range(5)
    ]
    return DetectionEngine(initial_rules()).analyse(events)[0]


def test_status_history_and_identity():
    observed = finding()
    alert = create_alert(observed)
    assert create_alert(observed).alert_id == alert.alert_id
    assert alert.status == AlertStatus.NEW
    investigating = change_status(
        alert, AlertStatus.INVESTIGATING, actor="analyst", note="Reviewing source"
    )
    resolved = change_status(
        investigating,
        AlertStatus.FALSE_POSITIVE,
        actor="analyst",
        note="Owner confirmed authorised lab test",
    )
    assert len(resolved.history) == 2
    assert resolved.event_ids == observed.event_ids
    assert alert.history == []
    reopened = change_status(
        resolved, AlertStatus.INVESTIGATING, actor="analyst", note="New evidence"
    )
    assert len(reopened.history) == 3
    with pytest.raises(ValueError):
        change_status(alert, AlertStatus.NEW, actor="analyst", note="Unchanged")
    with pytest.raises(ValueError):
        change_status(alert, AlertStatus.RESOLVED, actor="analyst", note=" ")
