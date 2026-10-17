"""Portable exports with HTML escaping and spreadsheet formula neutralisation."""

import csv
import io
import json
from html import escape
from typing import Literal

from scry_security.reports.incident_report import IncidentReport


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def export_report(report: IncidentReport, format: Literal["json", "csv", "html"]) -> str:
    if format == "json":
        return report.model_dump_json(indent=2) + "\n"
    if format == "csv":
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(
            [
                "incident_id",
                "title",
                "status",
                "synthetic",
                "analyst",
                "summary",
                "analyst_findings",
                "event_id",
                "timestamp_utc",
                "host",
                "operating_system",
                "event_type",
                "outcome",
                "username",
                "source_ip",
                "destination_ip",
                "event_source",
                "native_event_id",
                "raw_evidence_json",
                "normalised_details_json",
            ]
        )
        for event in report.timeline:
            writer.writerow(
                [
                    csv_safe(value)
                    for value in [
                        report.incident_id,
                        report.title,
                        report.status.value,
                        report.synthetic,
                        report.analyst,
                        report.summary,
                        report.analyst_findings,
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.hostname,
                        event.operating_system.value,
                        event.event_type,
                        event.outcome.value,
                        event.username,
                        event.source_ip,
                        event.destination_ip,
                        event.source,
                        event.native_event_id,
                        json.dumps(event.raw, ensure_ascii=False),
                        json.dumps(event.details, ensure_ascii=False),
                    ]
                ]
            )
        return output.getvalue()
    if format != "html":
        raise ValueError("Unsupported report format")

    def list_html(values: list[str]) -> str:
        return "<ul>" + "".join(f"<li>{escape(value)}</li>" for value in values) + "</ul>"

    rows = "".join(
        "<tr>"
        + (
            "".join(
                f"<td>{escape(str(value))}</td>"
                for value in [
                    event.timestamp.isoformat(),
                    event.hostname,
                    event.operating_system.value,
                    event.event_type,
                    event.username or "Unavailable",
                    event.source_ip or "Unavailable",
                ]
            )
        )
        + "</tr>"
        for event in report.timeline
    )
    label = "SYNTHETIC LAB INVESTIGATION" if report.synthetic else "SECURITY INVESTIGATION"
    evidence = escape(
        json.dumps(
            [event.model_dump(mode="json") for event in report.timeline],
            indent=2,
            ensure_ascii=False,
        )
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{escape(report.title)} · Scry-Security</title>"
        "<style>body{font:15px/1.6 system-ui,sans-serif;max-width:1100px;"
        "margin:40px auto;padding:0 24px;color:#17213b;background:#f7f8fc}"
        "header{border-bottom:3px solid #7664c5;padding-bottom:20px}"
        "h1{font-size:30px}h2{margin-top:32px;color:#463975}table{border-collapse:collapse;width:100%;"
        "font-size:12px}th,td{border:1px solid #ccd0de;padding:9px;"
        "text-align:left;overflow-wrap:anywhere}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#e9ebf3;padding:20px;font-size:11px}"
        ".label{font-weight:700;letter-spacing:2px;color:#6552a1}.note{background:#e9e5f5;padding:15px}"
        "@media print{body{margin:0;background:white}details{display:block}}</style></head><body>"
        f'<header><p class="label">{label}</p><h1>{escape(report.title)}</h1>'
        f"<p>Scry-Security · See what others don't.</p><p>Incident {report.incident_id}<br>"
        f"Created {report.created_at.isoformat()} · Status {escape(report.status.value)}<br>"
        f"Analyst: {escape(report.analyst)}</p></header><h2>Incident summary</h2>"
        f'<p>{escape(report.summary)}</p><p class="note">{escape(report.assessment)}</p>'
        "<h2>Affected scope</h2>"
        + list_html(
            [
                f"Hosts: {', '.join(report.affected_hosts)}",
                f"Operating systems: {', '.join(report.operating_systems)}",
                f"Accounts: {', '.join(report.accounts) or 'Unavailable'}",
                f"Source addresses: {', '.join(report.source_addresses) or 'Unavailable'}",
                "Destination addresses: "
                f"{', '.join(report.destination_addresses) or 'Unavailable'}",
            ]
        )
        + "<h2>Observed evidence</h2>"
        + list_html(report.observed_evidence)
        + f"<h2>Analyst interpretation</h2><p>{escape(report.analyst_findings)}</p>"
        + "<h2>Detection context</h2>"
        + (
            "".join(
                f"<h3>{escape(alert.rule_id)}</h3><pre>"
                f"{escape(json.dumps(alert.context, indent=2, ensure_ascii=False))}</pre>"
                for alert in report.alerts
                if alert.context
            )
            or "<p>No additional host-policy context was recorded for these detections.</p>"
        )
        + "<h2>Possible false positives</h2>"
        + list_html(report.possible_false_positives)
        + "<h2>Recommended defensive actions</h2>"
        + list_html(report.recommended_actions)
        + "<h2>ATT&amp;CK references</h2>"
        + list_html(report.mitre_techniques or ["No automatic mapping"])
        + "<h2>UTC event timeline</h2><table><thead><tr><th>Time</th><th>Host</th><th>OS</th>"
        "<th>Event</th><th>Account</th><th>Source</th></tr></thead><tbody>"
        + rows
        + "</tbody></table>"
        "<h2>Retained evidence</h2><details><summary>"
        "Native and normalised event snapshots</summary>"
        f"<pre>{evidence}</pre></details></body></html>\n"
    )
