"""Create a fresh, labelled synthetic demo database without replacing existing data."""

import argparse
import json
from pathlib import Path

from scry_security.database.database import Database
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.integrity.monitor import compare_baseline, create_baseline
from scry_security.services.replay import replay_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("data/demo.sqlite"))
    args = parser.parse_args()
    path = args.database.resolve()
    laboratory = path.parent / f"{path.stem}-file-lab"
    if path.exists() or laboratory.exists():
        parser.error("Choose a new database path; existing demo data and lab files are preserved")
    root = Path(__file__).resolve().parents[1]
    database = Database(path)
    totals = {"added_events": 0, "added_alerts": 0}
    try:
        store = Store(database)
        rules = load_rules()
        sources = [
            ("linux/suspicious/brute_force.txt", "linux"),
            ("linux/benign/ordinary.txt", "linux"),
            ("windows/suspicious/authentication.xml", "windows"),
            ("windows/suspicious/admin_group.xml", "windows"),
            ("windows/benign/ordinary.xml", "windows"),
            ("network/suspicious/connections.jsonl", "canonical"),
            ("network/benign/connections.jsonl", "canonical"),
        ]
        for relative, format in sources:
            replay = replay_file(
                root / "sample_logs" / relative, format=format, rules=rules, synthetic=True
            )
            if replay.errors:
                raise ValueError("A committed synthetic fixture failed to parse")
            events = [
                event.model_copy(update={"source": f"synthetic-fixture:{relative}"})
                if format == "linux"
                else event
                for event in replay.events
            ]
            imported = store.ingest(events, rules)
            for key in totals:
                totals[key] += imported[key]
        laboratory.mkdir(mode=0o700)
        modified = laboratory / "configuration.txt"
        removed = laboratory / "retired.txt"
        modified.write_text("approved synthetic configuration\n", encoding="utf-8")
        removed.write_text("disposable synthetic fixture\n", encoding="utf-8")
        baseline = create_baseline(
            [laboratory],
            approved_by="Synthetic lab author",
            approval_note="Known generated lab files; no real sensitive files watched",
            synthetic=True,
        )
        store.save_baseline(baseline)
        modified.write_text("changed synthetic configuration\n", encoding="utf-8")
        # Created by this invocation solely for the disposable deletion scenario.
        removed.unlink()
        (laboratory / "created.txt").write_text("new synthetic fixture\n", encoding="utf-8")
        scan = compare_baseline(baseline)
        if scan.errors:
            raise ValueError("Synthetic file comparison did not complete")
        imported = store.ingest(scan.events, rules)
        for key in totals:
            totals[key] += imported[key]
        store.save_integrity_scan(scan)
        for host, rule_ids, title in [
            (
                "linux-lab",
                {"SCRY-AUTH-001", "SCRY-AUTH-003"},
                "Synthetic SSH authentication investigation",
            ),
            (
                "windows-lab",
                {"SCRY-AUTH-001", "SCRY-AUTH-003"},
                "Synthetic Windows authentication investigation",
            ),
            ("windows-lab", {"SCRY-ACCOUNT-001"}, "Synthetic privileged-group investigation"),
        ]:
            chosen = [
                alert.alert_id for alert in store.alerts(hostname=host) if alert.rule_id in rule_ids
            ]
            store.create_incident(
                chosen,
                title=title,
                summary="Generated from committed synthetic fixtures.",
                analyst="Synthetic lab author",
                analyst_findings="This is a labelled lab scenario, not a real compromise. "
                "Validate authorisation in a real investigation.",
            )
        print(
            json.dumps(
                {
                    "database": str(path),
                    **totals,
                    "saved_incidents": len(store.incidents()),
                    "synthetic_only": True,
                },
                indent=2,
            )
        )
    finally:
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
