"""Synthetic Windows XML and mocked native handles; no audit changes required."""

from unittest.mock import MagicMock

import pytest

from scry_security.collectors.base import SourceStatus
from scry_security.collectors.windows.event_logs import read_event_log
from scry_security.parsers.windows_parser import parse_windows_xml


def xml_event(
    event_id="4625",
    fields=None,
    provider="Microsoft-Windows-Security-Auditing",
    channel="Security",
    record_id="7",
):
    fields = fields or {"TargetUserName": "alice", "IpAddress": "192.0.2.10", "LogonType": "3"}
    data = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in fields.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        '<TimeCreated SystemTime="2026-10-31T10:30:00.1234567Z"/>'
        f"<EventRecordID>{record_id}</EventRecordID><Channel>{channel}</Channel>"
        f"<Computer>win-lab</Computer></System><EventData>{data}</EventData></Event>"
    )


@pytest.mark.parametrize(
    "event_id,event_type",
    [
        ("4624", "authentication_success"),
        ("4625", "authentication_failure"),
        ("4634", "logoff"),
        ("4648", "explicit_credentials_used"),
        ("4672", "privileges_assigned"),
        ("4720", "account_created"),
        ("4726", "account_deleted"),
        ("4738", "account_modified"),
        ("4728", "group_membership_added"),
        ("4732", "group_membership_added"),
        ("4740", "account_locked"),
        ("4719", "audit_policy_changed"),
        ("4697", "service_installed"),
        ("4688", "process_created"),
    ],
)
def test_security_event_mapping(event_id, event_type):
    result = parse_windows_xml(xml_event(event_id), synthetic=True)
    assert result.error is None
    assert result.event.event_type == event_type
    assert result.event.native_event_id == event_id
    assert result.event.synthetic
    assert result.event.details["LogonType"] == "3"
    assert result.event.raw["xml"].startswith("<Event")


def test_provider_identity_and_malformed_inputs():
    assert parse_windows_xml(xml_event(provider="UnrelatedProvider")).skipped
    assert parse_windows_xml(xml_event(channel="Application")).skipped
    assert parse_windows_xml("bad XML").error
    assert parse_windows_xml("x" * 262_145).error
    assert parse_windows_xml('<!DOCTYPE x [<!ENTITY a "expand">]><Event>&a;</Event>').error
    assert parse_windows_xml(xml_event(fields={"IpAddress": "not-ip"})).error
    event = parse_windows_xml(xml_event(fields={"TargetUserName": "alice", "IpAddress": "-"})).event
    assert event.source_ip is None


def test_log_clearing_userdata():
    xml = xml_event("1102", provider="Microsoft-Windows-Eventlog")
    start, end = xml.index("<EventData>"), xml.index("</EventData>") + len("</EventData>")
    xml = (
        xml[:start]
        + (
            '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
            "<SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>"
        )
        + xml[end:]
    )
    event = parse_windows_xml(xml).event
    assert event.event_type == "audit_log_cleared"
    assert event.username == "admin"


def test_group_actor_and_target_are_distinct():
    event = parse_windows_xml(
        xml_event(
            "4732",
            fields={
                "SubjectUserName": "operator",
                "TargetUserName": "Administrators",
                "MemberSid": "S-1-5-21-123-1001",
                "TargetSid": "S-1-5-32-544",
            },
        )
    ).event
    assert event.username == "S-1-5-21-123-1001"
    assert event.details["SubjectUserName"] == "operator"
    assert event.details["TargetUserName"] == "Administrators"


def native_api(monkeypatch):
    api = MagicMock()
    api.error = OSError
    api.EvtQueryChannelPath = 1
    api.EvtQueryForwardDirection = 256
    api.EvtNext.side_effect = [[MagicMock()], []]
    api.EvtRender.return_value = xml_event()
    monkeypatch.setattr(
        "scry_security.collectors.windows.event_logs.importlib.import_module", lambda _: api
    )
    return api


def test_native_snapshot_closes_handles_and_advances_skipped_records(monkeypatch):
    api = native_api(monkeypatch)
    api.EvtRender.return_value = xml_event("9999")
    result = read_event_log(max_records=1)
    assert result.status == SourceStatus.AVAILABLE
    assert result.results[0].skipped
    assert result.cursor == "7"
    api.EvtQuery.return_value.Close.assert_called_once()
    api.EvtNext.side_effect = PermissionError("denied")
    # A native Windows error carries winerror; POSIX errno alone is insufficient.
    error = OSError("denied")
    error.winerror = 5
    api.EvtQuery.side_effect = error
    assert read_event_log().status == SourceStatus.PERMISSION_DENIED


def test_native_missing_dependency_and_validation(monkeypatch):
    monkeypatch.setattr(
        "scry_security.collectors.windows.event_logs.importlib.import_module",
        MagicMock(side_effect=ImportError),
    )
    assert read_event_log().status == SourceStatus.UNAVAILABLE
    with pytest.raises(ValueError):
        read_event_log(channel="Security; malicious")
    with pytest.raises(ValueError):
        read_event_log(after_record_id=-1)
