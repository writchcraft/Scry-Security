# Explicit collection and recorded source health

`services/monitoring.py` connects native adapters to shared detection and storage.
The collector runs separately from the web process. It validates an explicit
TOML source list and commits canonical events, alerts and source checkpoints in
one transaction. A failed ingestion does not advance committed checkpoints.
Restarting resumes from those checkpoints.

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m scry_security --collect-once examples/monitor-windows.toml --database data/scry.sqlite
.\.venv\Scripts\python.exe -m scry_security --monitor examples/monitor-windows.toml --database data/scry.sqlite
```

Ubuntu/Debian:

```bash
.venv/bin/python -m scry_security --collect-once examples/monitor-linux.toml --database data/scry.sqlite
.venv/bin/python -m scry_security --monitor examples/monitor-linux.toml --database data/scry.sqlite
```

Start with one poll and inspect statuses before running a loop. Stop with Ctrl+C.
No service is installed, audit policy changed or permission granted. Run `--serve`
against the same database in another terminal. **Settings** shows last committed
source checks and marks them stale after the expected interval. Availability does
not prove comprehensive telemetry coverage.

`poll_seconds` accepts 2–3600 seconds. Each source needs a unique `source_id` and
`kind`; `enabled` and bounded `max_records` are optional. Kinds are `linux_auth`,
`linux_journal`, `windows_eventlog` and `connections`. OS-specific sources report
unavailable on other hosts. `synthetic` defaults to false; label lab feeds explicitly.

Auth files require `path`, `year` and a fixed `utc_offset`. Relative paths resolve
against the TOML file. Year rollover/DST context must be resolved explicitly.
Journal sources use native cursors. Windows sources use allowed channels and
channel-local record IDs. Connection sources have an empty watched-port list
by default, and persist snapshot tuples to avoid recounting unchanged connections
after restart. Native permission restrictions can make any source incomplete.

Choose one authentication feed per host unless duplicate telemetry across file
and journal sources has been independently addressed. Source IDs should be
unique across all configs writing to one database. Changing a source definition
intentionally resets its checkpoint. First Windows reads start at oldest retained
records in bounded batches; a first journal read uses a recent bounded snapshot.
Windows record-ID resets after log clearing remain a documented acquisition gap.
See platform guides for rotation, retention and permission limitations.

Single-poll exit codes are 0 when all sources report available and 2 otherwise.
The loop keeps checking recoverable unavailable/degraded sources. Database
failures stop it safely with committed cursors preserved. Empty unchanged polls
do not rebuild detection history. New events or rule changes trigger a bounded
rebuild over at most 100,000 stored records.

File integrity retains its separate approved-baseline commands. Neither command
starts live packet capture. Collect only authorised systems and telemetry.
