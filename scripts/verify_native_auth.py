"""Read native auth telemetry into a NEW private evidence directory; never create activity."""

import argparse
import ctypes
import hashlib
import json
import platform
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from scry_security.collectors.linux.auth_logs import read_auth_log
from scry_security.collectors.linux.journal import parse_journal_record, read_journal
from scry_security.collectors.windows.event_logs import read_event_log
from scry_security.database.database import Database
from scry_security.database.models import EventRecord
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.parsers.linux_parser import parse_auth_line
from scry_security.parsers.windows_parser import parse_windows_xml


def recent_windows_start(limit: int) -> int:
    """Find a recent channel-local record range without changing the collector API."""
    import win32evtlog as api
    from defusedxml import ElementTree

    try:
        query = api.EvtQuery(
            "Security", api.EvtQueryChannelPath | api.EvtQueryReverseDirection, "*"
        )
    except api.error:
        # Native pywin32 errors are not necessarily OSError subclasses. Let the
        # collector describe denied/unavailable access rather than crashing here.
        return 0
    try:
        handles = api.EvtNext(query, 1, 1000, 0)
        try:
            if not handles:
                return 0
            root = ElementTree.fromstring(api.EvtRender(handles[0], api.EvtRenderEventXml))
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            latest = int(root.findtext(f"{ns}System/{ns}EventRecordID"))
            return max(0, latest - limit)
        finally:
            for handle in handles:
                handle.Close()
    finally:
        query.Close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", choices=["windows-security", "linux-journal", "linux-auth"], required=True
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-records", type=int, default=1000)
    parser.add_argument("--path", type=Path)
    parser.add_argument("--year", type=int)
    parser.add_argument("--utc-offset", default="+00:00")
    parser.add_argument("--journal-cursor")
    parser.add_argument(
        "--lab-generated",
        action="store_true",
        help="label OS events generated in an authorised lab; still not synthetic",
    )
    args = parser.parse_args()
    if not 1 <= args.max_records <= 10000:
        parser.error("max-records must be 1..10000")
    if platform.system() != ("Windows" if args.source == "windows-security" else "Linux"):
        parser.error("native verification must run on the source OS")
    timezone = datetime.fromisoformat(f"2000-01-01T00:00:00{args.utc_offset}").tzinfo
    if timezone is None:
        parser.error("utc-offset must specify a timezone")
    if args.source == "linux-auth" and (args.path is None or args.year is None):
        parser.error("linux-auth requires --path and --year")
    args.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    start = None
    if args.source == "windows-security":
        try:
            start = recent_windows_start(args.max_records)
        except (OSError, ImportError):
            start = 0  # Collector reports the actual availability/permission failure.
        batch = read_event_log(after_record_id=start, max_records=args.max_records)
    elif args.source == "linux-journal":
        batch = read_journal(cursor=args.journal_cursor, max_records=args.max_records)
    else:
        batch = read_auth_log(
            args.path, year=args.year, source_timezone=timezone, max_records=args.max_records
        ).batch
    events = [result.event for result in batch.results if result.event is not None]
    normalisation_matches = True
    for event in events:
        if args.source == "windows-security":
            parsed = parse_windows_xml(event.raw["xml"])
        elif args.source == "linux-journal":
            parsed = parse_journal_record(event.raw)
        else:
            parsed = parse_auth_line(
                event.raw["line"], year=args.year, source_timezone=timezone, source=str(args.path)
            )
        exclude = {"event_id", "ingested_at"}
        normalisation_matches &= parsed.event is not None and (
            parsed.event.model_dump(mode="json", exclude=exclude)
            == event.model_dump(mode="json", exclude=exclude)
        )
    evidence_path = args.output_dir / "events.jsonl"
    evidence_path.write_text("".join(e.model_dump_json() + "\n" for e in events), encoding="utf-8")
    database_path = args.output_dir / "native.sqlite"
    database = Database(database_path)
    try:
        result = Store(database).ingest(events, load_rules())
    finally:
        database.close()
    database = Database(database_path)
    try:
        with database.sessions() as session:
            stored = {
                row.event_id: row.payload for row in session.scalars(select(EventRecord)).all()
            }
        preserved = all(stored.get(str(e.event_id)) == e.model_dump(mode="json") for e in events)
        alerts = Store(database).alerts(limit=1000)
    finally:
        database.close()
    auth = [
        e for e in events if e.event_type in {"authentication_failure", "authentication_success"}
    ]
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "unknown"
    summary = {
        "checked_at": datetime.now(UTC).isoformat(),
        "commit": revision,
        "platform": platform.platform(),
        "source": args.source,
        "elevated": bool(ctypes.windll.shell32.IsUserAnAdmin())
        if platform.system() == "Windows"
        else None,
        "lab_generated": args.lab_generated,
        "synthetic": False,
        "status": batch.status.value,
        "message": batch.message,
        "records": len(batch.results),
        "events": len(events),
        "authentication_events": len(auth),
        "event_types": dict(Counter(e.event_type for e in events)),
        "authentication_native_ids": dict(Counter(e.native_event_id for e in auth)),
        "errors": sum(bool(r.error) for r in batch.results),
        "skipped": sum(r.skipped for r in batch.results),
        "start_record_id": start,
        "cursor": batch.cursor,
        "ingestion": result,
        "normalisation_matches_raw": normalisation_matches if events else None,
        "reopened_storage_matches": preserved if events else None,
        "positive_detection": bool(alerts),
        "detected_rules": dict(Counter(a.rule_id for a in alerts)),
        "events_jsonl_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "authentication_acquired": bool(auth),
    }
    content = json.dumps(summary, indent=2) + "\n"
    (args.output_dir / "summary.json").write_text(content, encoding="utf-8")
    print(content, end="")
    return (
        0
        if (batch.status.value == "available" and auth and preserved and normalisation_matches)
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
