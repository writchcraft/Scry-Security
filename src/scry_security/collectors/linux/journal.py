"""Bounded journal snapshots using a fixed executable argument list."""

import json
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from threading import Thread

from scry_security.collectors.base import CollectionBatch, SourceStatus
from scry_security.parsers.event_normaliser import ParseResult
from scry_security.parsers.linux_parser import parse_linux_message


def parse_journal_record(record: dict, *, synthetic: bool = False) -> ParseResult:
    try:
        message, hostname = record["MESSAGE"], record["_HOSTNAME"]
        program = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM", "")
        cursor = record.get("__CURSOR")
        if not all(isinstance(value, str) for value in (message, hostname, program)):
            raise ValueError
        timestamp = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
            microseconds=int(record["__REALTIME_TIMESTAMP"])
        )
        return parse_linux_message(
            message,
            timestamp=timestamp,
            hostname=hostname,
            program=program,
            source="systemd-journal",
            raw=record,
            native_record_id=cursor,
            synthetic=synthetic,
            process_id=int(record["_PID"])
            if str(record.get("_PID", "")).isdigit() and len(str(record["_PID"])) < 11
            else None,
        )
    except (KeyError, ValueError, TypeError, OverflowError):
        return ParseResult(error="Invalid journal record")


def read_journal(*, cursor: str | None = None, max_records: int = 1000) -> CollectionBatch:
    """Read a bounded recent snapshot, or entries after a previously stored cursor.

    A first read intentionally starts with the latest max_records, not all history.
    Native journal access can be partial: systemd may show only the caller's logs.
    """
    if not 1 <= max_records <= 10_000:
        raise ValueError("max_records must be between 1 and 10000")
    executable = shutil.which("journalctl")
    if executable is None:
        return CollectionBatch((), SourceStatus.UNAVAILABLE, "journalctl not installed")
    args = [executable, "--no-pager", "--quiet", "--output=json", f"--lines={max_records}"]
    if cursor is not None:
        if not cursor or len(cursor) > 4096 or "\x00" in cursor:
            raise ValueError("Invalid journal cursor")
        # --lines is a tail selection. With a cursor, use forward head selection
        # so a backlog does not silently skip to its newest entries.
        args = [
            executable,
            "--no-pager",
            "--quiet",
            "--output=json",
            "--lines=all",
            f"--after-cursor={cursor}",
            "--output-fields=MESSAGE,_HOSTNAME,SYSLOG_IDENTIFIER,_COMM",
        ]
    lines: list[bytes] = []
    failures: list[str] = []
    limited = False

    def consume(stream) -> None:
        nonlocal limited
        total = 0
        try:
            for _ in range(max_records):
                line = stream.readline(262_145)
                if not line:
                    return
                total += len(line)
                if len(line) > 262_144 or total > 8_388_608:
                    failures.append("Journal record or batch size limit exceeded")
                    return
                lines.append(line)
            limited = True
        except OSError:
            failures.append("Journal stream read failed")

    try:
        with tempfile.TemporaryFile() as errors:
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=errors) as process:
                reader = Thread(target=consume, args=(process.stdout,), daemon=True)
                reader.start()
                reader.join(timeout=15)
                if reader.is_alive():
                    failures.append("Journal read timed out")
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                reader.join(timeout=5)
                returncode = process.returncode
            errors.seek(0)
            stderr = errors.read(4096)
    except PermissionError:
        return CollectionBatch((), SourceStatus.PERMISSION_DENIED, "Journal access denied")
    except (OSError, subprocess.TimeoutExpired):
        return CollectionBatch((), SourceStatus.DEGRADED, "Journal command failed or timed out")
    if failures:
        return CollectionBatch((), SourceStatus.DEGRADED, failures[0], cursor)
    if returncode and not limited:
        return CollectionBatch((), SourceStatus.DEGRADED, "Journal command returned an error")
    results = []
    last_cursor = cursor
    for line in lines:
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError
            results.append(parse_journal_record(record))
            if isinstance(record.get("__CURSOR"), str):
                last_cursor = record["__CURSOR"]
        except (ValueError, UnicodeDecodeError):
            results.append(ParseResult(error="Invalid journal JSON"))
    degraded = bool(stderr) or any(item.error for item in results)
    return CollectionBatch(
        tuple(results),
        SourceStatus.DEGRADED if degraded else SourceStatus.AVAILABLE,
        "Journal snapshot; access may be limited to this user",
        last_cursor,
    )
