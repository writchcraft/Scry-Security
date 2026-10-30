# Stage 3 — Linux authentication collection

Target distributions are Ubuntu and Debian with Python 3.12+. Use the README's
virtual-environment instructions first. This stage adds library adapters; the
monitoring service and persistence arrive in later stages.

## Historical parsing

`parse_auth_line` in `src/scry_security/parsers/linux_parser.py` recognises selected
OpenSSH password/public-key/keyboard-interactive outcomes, invalid usernames,
sudo command/denial records and user/group-management messages. A normal SSH
connection closure is skipped. Other log formats and PAM variants are not
implicitly supported. Unknown messages do not become suspicious events.

```python
from scry_security.parsers.linux_parser import parse_auth_line

result = parse_auth_line(
    "2026-10-31T10:30:00Z lab sshd[42]: Failed password for alice from 192.0.2.10 port 51000 ssh2",
    synthetic=True,
)
print(result.event.model_dump_json(indent=2))
```

Expected: a labelled synthetic Linux `authentication_failure`, source address
192.0.2.10, account alice, UTC time, and original line retained. Legacy
`Oct 31 10:30:00` timestamps require `year=` and `source_timezone=`. Year rollover
and daylight-saving ambiguity must be resolved by the importer using source
context; the parser never infers them from today's date.

## Auth files

`read_auth_log(Path('/var/log/auth.log'), year=2026, source_timezone=UTC)` reads a
bounded snapshot and returns a `FileBatch`. Supply its `checkpoint` on the next
poll. Select `/var/log/secure` explicitly on distributions that use it; some
installations have no authentication text file at all.

The reader opens files in binary read-only mode, handles incomplete lines,
malformed UTF-8, oversized lines, inode changes and detected truncation. File
checkpoints are caller-owned until the storage/service stages. Rename-and-create
rotation may lose unread bytes from the old file. Copy-truncate followed by rapid
regrowth can escape size-based truncation detection. Ingest archives separately
when completeness matters; this is not an exactly-once transport.

Read permissions vary. Use narrowly delegated log access where appropriate;
running the whole application as root is not required by the design. Membership
in log-reading groups can reveal sensitive logs and must be an explicit local
administrator decision. Missing files, denied access and parse degradation are
reported separately from an empty healthy result.

## Journal

`read_journal(max_records=1000)` starts with a recent snapshot. Pass its returned
cursor to continue forward. The adapter uses `journalctl` with an argument list,
no shell, a timeout, bounded lines and an 8 MiB memory budget. It stops the child
after the requested record count. Native journal timestamps are microseconds
since the Unix epoch. The cursor advances over skipped messages too.

Journal records may be limited to the current user's accessible logs. An empty
successful response does not prove access to system authentication telemetry.
No auditing policy, journal group or log file is modified. Linux auditd parsing
is not implemented in this stage.

References: [journalctl manual](https://www.freedesktop.org/software/systemd/man/254/journalctl.html),
[journal JSON format](https://systemd.io/JOURNAL_EXPORT_FORMATS/#journal-json-format).

Run `python -m pytest tests/collectors/linux` using the environment's Python.
Tests exercise synthetic messages, real temporary file polling and mocked journal
execution on Windows. Native Linux execution still requires Linux CI/lab testing.
