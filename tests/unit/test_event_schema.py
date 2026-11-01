"""Evidence and time invariants shared by both operating systems."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from scry_security.core.event_schema import SecurityEvent
from scry_security.parsers.event_normaliser import normalise_records


def canonical_event(**overrides):
    return {
        "timestamp": "2026-10-31T10:30:00+02:00",
        "operating_system": "linux",
        "hostname": "lab-host",
        "category": "authentication",
        "event_type": "authentication_failure",
        "outcome": "failure",
        "source": "auth.log",
        **overrides,
    }


def test_utc_optional_fields_and_json_roundtrip():
    event = SecurityEvent(**canonical_event(raw={"line": "original evidence"}))
    assert event.timestamp == datetime(2026, 10, 31, 8, 30, tzinfo=UTC)
    assert event.timestamp.tzinfo == UTC
    assert event.username is None
    assert event.source_ip is None
    assert event.ingested_at.tzinfo == UTC
    assert SecurityEvent.model_validate_json(event.model_dump_json()) == event
    assert event.raw == {"line": "original evidence"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"timestamp": "2026-10-31T10:00:00"},
        {"ingested_at": datetime(2026, 10, 31)},
        {"source_ip": "invalid"},
        {"hostname": ""},
        {"operating_system": "unsupported"},
        {"raw": {"line": "x" * 262_144}},
        {"details": {"number": float("nan")}},
        {"unexpected": True},
    ],
)
def test_invalid_event_rejected(overrides):
    with pytest.raises(ValidationError):
        SecurityEvent(**canonical_event(**overrides))


@pytest.mark.parametrize("os_name", ["windows", "linux"])
def test_equivalent_events_and_ipv6(os_name):
    event = SecurityEvent(**canonical_event(operating_system=os_name, source_ip="2001:db8::1"))
    assert event.event_type == "authentication_failure"
    assert str(event.source_ip) == "2001:db8::1"


def test_ids_identify_ingestions_not_native_records():
    assert (
        SecurityEvent(**canonical_event()).event_id != SecurityEvent(**canonical_event()).event_id
    )


def test_aware_datetime_normalised():
    timestamp = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=-5)))
    event = SecurityEvent(**canonical_event(timestamp=timestamp))
    assert event.timestamp.hour == 5


def test_bad_record_does_not_stop_stream_or_echo_evidence():
    results = list(
        normalise_records(
            [
                canonical_event(),
                canonical_event(source_ip="secret invalid value"),
                canonical_event(operating_system="windows"),
            ]
        )
    )
    assert results[0].event is not None
    assert results[1].event is None
    assert results[1].error == "Invalid event fields: source_ip"
    assert results[2].event.operating_system == "windows"
