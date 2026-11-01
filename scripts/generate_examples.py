"""Rebuild the three documented investigations entirely from synthetic fixtures."""

from pathlib import Path
from tempfile import TemporaryDirectory

from scry_security.database.database import Database
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.reports.report_generator import export_report
from scry_security.services.replay import replay_file


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / "incident_reports"
    output.mkdir(exist_ok=True)
    data = root / "data"
    data.mkdir(exist_ok=True)
    scenarios = [
        (
            "linux-ssh",
            "linux/suspicious/brute_force.txt",
            "linux",
            "Suspected SSH brute-force activity",
            "Five SSH password failures are followed by an accepted password "
            "for the same account and source.",
            "The sequence warrants investigation. It does not establish hostile access; "
            "check whether the account owner or an authorised lab exercise explains the activity.",
        ),
        (
            "windows-authentication",
            "windows/suspicious/authentication.xml",
            "windows",
            "Suspicious Windows authentication sequence",
            "Five Windows failed logons are followed by a successful network logon "
            "for the same account and source.",
            "The native LogonType is 3. Verify source ownership, failure codes and account history "
            "before interpreting the successful logon as account compromise.",
        ),
        (
            "windows-admin-group",
            "windows/suspicious/admin_group.xml",
            "windows",
            "Windows privileged-group membership review",
            "A synthetic 4732 record adds a member SID to the built-in Administrators group.",
            "The group SID identifies built-in Administrators. Change approval is absent, "
            "or subsequent actions; determine whether the actor was authorised before remediation.",
        ),
    ]
    for slug, relative, format, title, summary, findings in scenarios:
        with TemporaryDirectory(prefix="report-example-", dir=data) as temporary:
            database = Database(Path(temporary) / "example.sqlite")
            try:
                store = Store(database)
                rules = load_rules()
                result = replay_file(
                    root / "sample_logs" / relative, format=format, rules=rules, synthetic=True
                )
                if result.errors:
                    raise ValueError("Synthetic fixture failed parsing")
                # Shareable lab provenance, not the author's absolute checkout path.
                events = [
                    event.model_copy(update={"source": f"synthetic-fixture:{relative}"})
                    if format == "linux"
                    else event
                    for event in result.events
                ]
                store.ingest(events, rules)
                report = store.create_incident(
                    [alert.alert_id for alert in store.alerts()],
                    title=title,
                    summary=summary,
                    analyst="Synthetic lab author",
                    analyst_findings=findings,
                )
                for extension in ("json", "csv", "html"):
                    (output / f"{slug}.{extension}").write_text(
                        export_report(report, extension), encoding="utf-8", newline=""
                    )
                print(
                    f"Generated {slug}: {len(report.timeline)} events, {len(report.alerts)} alerts"
                )
            finally:
                database.close()


if __name__ == "__main__":
    main()
