"""Explicit diagnostic, historical replay and local dashboard entry points."""

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from scry_security import __version__
from scry_security.core.config import Settings
from scry_security.core.logging import configure_logging
from scry_security.core.platform import OperatingSystem, detect_platform
from scry_security.database.database import DatabaseIdentityError
from scry_security.detection.loader import load_rules
from scry_security.detection.policy import load_policy
from scry_security.services.replay import replay_file, replay_pcap


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _run(argv)
    except DatabaseIdentityError:
        print(
            "Choose a new or Scry-owned database file; unrelated databases are not modified.",
            file=sys.stderr,
        )
        return 2
    except SQLAlchemyError:
        print(
            "Database operation failed; check access, storage and concurrent writers.",
            file=sys.stderr,
        )
        return 2
    except ValidationError:
        print(
            "Invalid configuration or stored evidence; check the documented schema.",
            file=sys.stderr,
        )
        return 2


def _run(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scry-Security — See what others don't.")
    parser.add_argument("--version", action="version", version=f"Scry-Security {__version__}")
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--check", action="store_true", help="check configuration and host platform"
    )
    action.add_argument("--replay", type=Path, help="analyse a bounded historical input file")
    action.add_argument(
        "--pcap", type=Path, help="analyse an explicitly supplied authorised offline capture"
    )
    parser.add_argument(
        "--capture-os", choices=["windows", "linux"], help="source OS of the saved capture"
    )
    parser.add_argument("--capture-host", help="source hostname represented by the capture")
    parser.add_argument(
        "--max-packets", type=int, default=10_000, help="offline capture packet budget"
    )
    action.add_argument(
        "--serve", action="store_true", help="serve the local authenticated dashboard"
    )
    action.add_argument("--export-incident", type=UUID, help="export a saved incident snapshot")
    action.add_argument("--collect-once", type=Path, help="poll explicitly configured sources once")
    action.add_argument(
        "--monitor", type=Path, help="poll explicitly configured sources until interrupted"
    )
    action.add_argument(
        "--fim-baseline", type=Path, help="create a newly approved file baseline JSON"
    )
    action.add_argument("--fim-check", type=Path, help="compare files against a baseline JSON")
    parser.add_argument(
        "--watch",
        action="append",
        type=Path,
        help="explicit baseline file/directory; repeat as needed",
    )
    parser.add_argument("--approved-by", help="baseline approver name")
    parser.add_argument("--approval-note", help="reason the initial file state is trusted")
    parser.add_argument("--export-format", choices=["json", "csv", "html"], default="json")
    parser.add_argument(
        "--output", type=Path, help="write an export to a new file instead of stdout"
    )
    parser.add_argument("--port", type=int, default=8765, help="loopback dashboard port")
    parser.add_argument("--format", choices=["canonical", "linux", "windows"], default="canonical")
    parser.add_argument("--rules", type=Path, help="custom YAML rule catalogue")
    parser.add_argument("--policy", type=Path, help="explicit host detection policy TOML")
    parser.add_argument(
        "--database", type=Path, help="persist replay evidence and alerts to this SQLite file"
    )
    parser.add_argument(
        "--synthetic", action="store_true", help="label imported events as synthetic"
    )
    parser.add_argument("--year", type=int, help="explicit year for legacy Linux syslog")
    parser.add_argument("--utc-offset", help="explicit fixed syslog offset, for example +00:00")
    args = parser.parse_args(argv)
    if args.collect_once or args.monitor:
        import time

        from scry_security.database.database import Database
        from scry_security.database.repositories import Store
        from scry_security.services.monitoring import CollectorRuntime, load_monitor_config

        try:
            config = load_monitor_config(args.collect_once or args.monitor)
            rules = load_rules(args.rules)
            policy = load_policy(args.policy) if args.policy else None
            settings = Settings()
        except (OSError, ValueError):
            print(
                "Invalid monitor configuration or rules; verify the documented fields.",
                file=sys.stderr,
            )
            return 2
        database = Database(args.database or settings.data_dir / "scry.sqlite")
        try:
            runtime = CollectorRuntime()
            while True:
                result = runtime.collect_once(config, Store(database), rules, policy=policy)
                print(json.dumps(result), flush=True)
                if args.collect_once:
                    return (
                        0
                        if all(source["status"] == "available" for source in result["sources"])
                        else 2
                    )
                time.sleep(config.poll_seconds)
        except KeyboardInterrupt:
            return 0
        finally:
            database.close()
    if args.fim_baseline or args.fim_check:
        from scry_security.database.database import Database
        from scry_security.database.repositories import Store
        from scry_security.integrity.monitor import compare_baseline, create_baseline, load_baseline

        database = None
        try:
            if args.fim_baseline:
                if not args.watch or not args.approved_by or not args.approval_note:
                    raise ValueError("Baseline requires explicit paths and approval")
                baseline = create_baseline(
                    args.watch,
                    approved_by=args.approved_by,
                    approval_note=args.approval_note,
                    synthetic=args.synthetic,
                )
                content = baseline.model_dump_json(indent=2)
                if len(content.encode("utf-8")) > 8_388_608:
                    raise ValueError("Baseline exceeds 8 MiB")
                with args.fim_baseline.open("x", encoding="utf-8") as stream:
                    stream.write(content)
                if args.database:
                    database = Database(args.database)
                    Store(database).save_baseline(baseline)
                print(
                    json.dumps(
                        {"baseline_id": str(baseline.baseline_id), "files": len(baseline.entries)}
                    )
                )
                return 0
            baseline = load_baseline(args.fim_check)
            scan = compare_baseline(baseline)
            if args.database:
                database = Database(args.database)
                store = Store(database)
                store.save_baseline(baseline)
                if scan.events:
                    store.ingest(
                        scan.events,
                        load_rules(args.rules),
                        policy=load_policy(args.policy) if args.policy else None,
                    )
                store.save_integrity_scan(scan)
            print(scan.model_dump_json(indent=2))
            return 2 if scan.errors else 0
        except (OSError, ValueError, KeyError, BufferError):
            print(
                "File integrity operation failed: verify paths, approval, host, "
                "access and scan limits.",
                file=sys.stderr,
            )
            return 2
        finally:
            if database:
                database.close()
    if args.export_incident:
        from scry_security.database.database import Database
        from scry_security.database.repositories import Store
        from scry_security.reports.report_generator import export_report

        path = args.database or Settings().data_dir / "scry.sqlite"
        if not path.is_file():
            print("Incident database not found.", file=sys.stderr)
            return 2
        database = Database(path)
        try:
            report = Store(database).incident(args.export_incident)
            if report is None:
                print("Incident not found.", file=sys.stderr)
                return 2
            content = export_report(report, args.export_format)
            if args.output:
                with args.output.open("x", encoding="utf-8", newline="") as stream:
                    stream.write(content)
            else:
                print(content, end="")
            return 0
        except (OSError, ValueError):
            print("Cannot export incident; output files must not already exist.", file=sys.stderr)
            return 2
        finally:
            database.close()
    if args.replay or args.pcap:
        try:
            source_timezone = None
            if args.utc_offset:
                source_timezone = datetime.fromisoformat(
                    f"2000-01-01T00:00:00{args.utc_offset}"
                ).tzinfo
                if source_timezone is None:
                    raise ValueError("Timezone must include an offset")
            rules = load_rules(args.rules)
            policy = load_policy(args.policy) if args.policy else None
            if args.pcap:
                if not args.capture_os or not args.capture_host:
                    raise ValueError("Capture replay requires its source OS and hostname")
                result = replay_pcap(
                    args.pcap,
                    operating_system=OperatingSystem(args.capture_os),
                    hostname=args.capture_host,
                    rules=rules,
                    synthetic=args.synthetic,
                    policy=policy,
                    max_packets=args.max_packets,
                )
            else:
                result = replay_file(
                    args.replay,
                    format=args.format,
                    rules=rules,
                    synthetic=args.synthetic,
                    year=args.year,
                    source_timezone=source_timezone,
                    policy=policy,
                )
            for finding in result.findings:
                print(finding.model_dump_json())
            if args.database is not None:
                from scry_security.database.database import Database
                from scry_security.database.repositories import Store

                database = Database(args.database)
                try:
                    print(
                        json.dumps(
                            Store(database).ingest(
                                result.events,
                                rules,
                                policy=load_policy(args.policy) if args.policy else None,
                            )
                        ),
                        file=sys.stderr,
                    )
                finally:
                    database.close()
            print(
                json.dumps(
                    {
                        "events": len(result.events),
                        "findings": len(result.findings),
                        "errors": result.errors,
                        "skipped": result.skipped,
                    }
                ),
                file=sys.stderr,
            )
            return 2 if result.errors else 0
        except ImportError:
            print("Offline packet analysis requires the packet-analysis extra.", file=sys.stderr)
            return 2
        except (OSError, ValueError, BufferError):
            print(
                "Replay failed: check input, rules, timezone and documented limits.",
                file=sys.stderr,
            )
            return 2
    if not args.check and not args.serve:
        parser.print_help()
        return 0

    try:
        settings = Settings()
    except ValidationError as exc:
        # Do not echo environment values: future settings may include secrets.
        fields = ", ".join(".".join(map(str, error["loc"])) for error in exc.errors())
        print(f"Invalid configuration fields: {fields}", file=sys.stderr)
        return 2

    logger = configure_logging(settings.log_level)
    if args.serve:
        if settings.api_token is None or len(settings.api_token.get_secret_value()) < 32:
            print(
                "Set SCRY_API_TOKEN to at least 32 random characters before serving.",
                file=sys.stderr,
            )
            return 2
        if not 1 <= args.port <= 65535:
            print("Invalid server port.", file=sys.stderr)
            return 2
        import uvicorn

        from scry_security.api.app import create_app
        from scry_security.database.database import Database
        from scry_security.database.repositories import Store

        database = Database(args.database or settings.data_dir / "scry.sqlite")
        try:
            app = create_app(Store(database), settings.api_token.get_secret_value())
            uvicorn.run(app, host="127.0.0.1", port=args.port, log_level=settings.log_level.lower())
        finally:
            database.close()
        return 0
    host = detect_platform()
    supported = host.operating_system != OperatingSystem.UNSUPPORTED
    print(
        json.dumps(
            {
                "application": "Scry-Security",
                "version": __version__,
                "operating_system": host.operating_system.value,
                "hostname": host.hostname,
                "release": host.release,
                "platform_family_supported": supported,
                "data_dir": str(settings.data_dir.resolve()),
                "log_level": settings.log_level,
                "collection_enabled": False,
            },
            indent=2,
        )
    )
    if not supported:
        logger.error("Unsupported platform family; target platforms are Windows and Linux.")
        return 1
    logger.info("Foundation check passed; collection is not started by this command.")
    return 0
