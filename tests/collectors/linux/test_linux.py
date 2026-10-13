"""Historical Linux telemetry and read-only incremental source contracts."""

import io
import json
from datetime import UTC
from unittest.mock import MagicMock

import pytest

from scry_security.collectors.base import SourceStatus
from scry_security.collectors.linux.auth_logs import read_auth_log
from scry_security.collectors.linux.journal import parse_journal_record, read_journal
from scry_security.parsers.linux_parser import parse_auth_line

PREFIX = "2026-10-31T10:30:00+00:00 lab sshd[42]: "
FAILED = "Failed password for invalid user test from 192.0.2.10 port 51000 ssh2"


@pytest.mark.parametrize(
    "message,event_type,outcome",
    [
        (FAILED, "authentication_failure", "failure"),
        (
            "Accepted publickey for alice from 2001:db8::1 port 51000 ssh2",
            "authentication_success",
            "success",
        ),
        ("Invalid user unknown from 192.0.2.10 port 51000", "invalid_username", "failure"),
    ],
)
def test_ssh_variants(message, event_type, outcome):
    result = parse_auth_line(PREFIX + message, synthetic=True)
    assert result.error is None
    assert result.event.event_type == event_type
    assert result.event.outcome == outcome
    assert result.event.synthetic
    assert result.event.timestamp.tzinfo == UTC


def test_legacy_context_and_unknown_records():
    line = "Oct 31 10:30:00 lab sshd[42]: " + FAILED
    assert parse_auth_line(line).error
    assert parse_auth_line(line, year=2026, source_timezone=UTC).event.timestamp.year == 2026
    assert parse_auth_line(PREFIX + "Connection closed by 192.0.2.10").skipped
    assert parse_auth_line("malformed").error
    assert parse_auth_line(PREFIX + FAILED.replace("192.0.2.10", "invalid-ip")).error
    assert parse_auth_line("x" * 65_537).error
    assert parse_auth_line(PREFIX.replace("+00:00", "") + FAILED).error


@pytest.mark.parametrize(
    "program,message,event_type",
    [
        (
            "sudo",
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
            "privilege_use",
        ),
        ("sudo", "alice : user NOT in sudoers ; TTY=pts/0", "privilege_use"),
        ("useradd", "new user: name=service, UID=1002, GID=1002", "account_created"),
        ("userdel", "delete user 'service'", "account_deleted"),
        ("usermod", "change user 'service' shell from /bin/sh to /bin/bash", "account_modified"),
    ],
)
def test_privilege_and_accounts(program, message, event_type):
    line = f"2026-10-31T10:30:00Z lab {program}[1]: {message}"
    event = parse_auth_line(line).event
    assert event.event_type == event_type
    assert "command_line" not in event.details


def test_read_incremental_partial_line_truncation_and_rotation(tmp_path):
    path = tmp_path / "auth.log"
    line = (PREFIX + FAILED + "\n").encode()
    path.write_bytes(line + b"partial")
    first = read_auth_log(path, year=2026, source_timezone=UTC)
    assert len(first.batch.results) == 1
    assert first.checkpoint.offset == len(line)
    assert (
        read_auth_log(
            path, year=2026, source_timezone=UTC, checkpoint=first.checkpoint
        ).batch.results
        == ()
    )
    path.write_bytes(line)
    # Same file truncated to the saved offset: no new records.
    assert not read_auth_log(
        path, year=2026, source_timezone=UTC, checkpoint=first.checkpoint
    ).batch.results
    path.rename(tmp_path / "auth.log.1")
    path.write_bytes(line)
    rotated = read_auth_log(path, year=2026, source_timezone=UTC, checkpoint=first.checkpoint)
    assert len(rotated.batch.results) == 1
    path.write_bytes(b"bad\n")
    truncated = read_auth_log(path, year=2026, source_timezone=UTC, checkpoint=rotated.checkpoint)
    assert truncated.batch.status == SourceStatus.DEGRADED
    assert truncated.checkpoint.offset == 4


def test_bounded_file_records_and_source_errors(tmp_path, monkeypatch):
    path = tmp_path / "auth.log"
    assert (
        read_auth_log(path, year=2026, source_timezone=UTC).batch.status == SourceStatus.UNAVAILABLE
    )
    path.write_bytes(b"x" * 140_000 + b"\n" + (PREFIX + FAILED + "\n").encode())
    result = read_auth_log(path, year=2026, source_timezone=UTC, max_records=1)
    assert result.batch.results[0].error
    assert result.checkpoint.discarding
    result = read_auth_log(path, year=2026, source_timezone=UTC, checkpoint=result.checkpoint)
    assert len(result.batch.results) == 1
    assert result.batch.results[0].event is not None
    with pytest.raises(ValueError):
        read_auth_log(path, year=2026, source_timezone=UTC, max_records=0)
    monkeypatch.setattr(type(path), "open", MagicMock(side_effect=PermissionError))
    assert (
        read_auth_log(path, year=2026, source_timezone=UTC).batch.status
        == SourceStatus.PERMISSION_DENIED
    )


def journal_record():
    return {
        "MESSAGE": FAILED,
        "_HOSTNAME": "lab",
        "SYSLOG_IDENTIFIER": "sshd",
        "__REALTIME_TIMESTAMP": "1793442600000000",
        "__CURSOR": "s=test;i=1",
    }


def test_journal_parse_and_unavailable(monkeypatch):
    result = parse_journal_record(journal_record())
    assert result.event.event_type == "authentication_failure"
    assert result.event.native_record_id == "s=test;i=1"
    assert parse_journal_record({}).error
    monkeypatch.setattr("scry_security.collectors.linux.journal.shutil.which", lambda _: None)
    assert read_journal().status == SourceStatus.UNAVAILABLE


def test_journal_bounded_forward_cursor(monkeypatch):
    process = MagicMock()
    process.stdout = io.BytesIO((json.dumps(journal_record()) + "\n").encode())
    process.poll.return_value = None
    process.returncode = -9
    process.__enter__.return_value = process
    popen = MagicMock(return_value=process)
    monkeypatch.setattr(
        "scry_security.collectors.linux.journal.shutil.which", lambda _: "/usr/bin/journalctl"
    )
    monkeypatch.setattr("scry_security.collectors.linux.journal.subprocess.Popen", popen)
    result = read_journal(cursor="s=old;i=0", max_records=1)
    assert result.status == SourceStatus.AVAILABLE
    assert result.cursor == "s=test;i=1"
    args = popen.call_args.args[0]
    assert "--lines=all" in args
    assert "--after-cursor=s=old;i=0" in args
    assert len(result.results) == 1
    process.kill.assert_called_once()
