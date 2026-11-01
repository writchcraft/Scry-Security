# Stage 11 — Incident reporting and investigation

A report is a saved snapshot of selected alerts, their complete linked evidence,
and the analyst's account of the investigation. Later alert-status changes do
not rewrite an existing report. An incident requires 1–100 unique alerts,
complete supporting events, one synthetic/real classification, a title, summary
and named analyst. Limits are 10,000 events and 8 MiB per report; oversized scope
is rejected rather than silently truncated.

In the dashboard, open an alert, complete **Save an incident snapshot**, and save.
The **Incident Reports** section lists saved reports for the selected evidence
mode. Read the snapshot or export JSON, CSV or HTML. Bearer authentication protects
creation, reading and every export. The public static page contains no evidence.

JSON contains the full versioned report, original alert snapshots and event
timeline. CSV exports one row per supporting event, with incident identity,
summary, analyst interpretation, source context and native/normalised evidence.
HTML provides a standalone readable investigation with summary, scope, timeline,
false-positive considerations, defensive actions and retained evidence.
HTML escapes untrusted log strings; CSV prefixes potentially executable formula
cells with an apostrophe. The CSV safeguard intentionally changes those cells'
presentation; use JSON for exact machine-readable evidence values.

Observed evidence and analyst interpretation are separate fields. A rule match
or successful logon after failures does not establish hostile intent. Check the
source system's auditing, account owner, maintenance/change records and related
telemetry before deciding an incident's disposition. Recommended actions are
guidance, not commands executed by Scry.

Export an existing snapshot from the CLI:

```powershell
.\.venv\Scripts\python.exe -m scry_security --export-incident INCIDENT_UUID --database data/demo.sqlite --export-format html --output incident.html
```

Replace `INCIDENT_UUID` with the ID shown in a saved report. `--output` creates a
new file and refuses to overwrite an existing file; omit it to write to stdout.
On Linux use `.venv/bin/python`. Reports can contain sensitive native evidence:
store them privately and review them before sharing.

## Three synthetic investigations

`incident_reports/` contains Linux SSH, Windows authentication and Windows
privileged-group examples in all three export formats. They use only committed
synthetic fixtures and documentation IP ranges. Rebuild them with:

```powershell
.\.venv\Scripts\python.exe scripts/generate_examples.py
```

The script replaces only its nine named generated example files. It creates
temporary databases beneath ignored `data/`, closes them and removes those
temporary directories. These are generated lab demonstrations, not findings
from the developer's computer.

Tests in `tests/integration/test_reports.py` cover saved snapshots, restart-safe
storage, deduplicated timeline evidence, separation of observations and
interpretation, HTML escaping, CSV formula neutralisation and authenticated
export routes. Browser verification and the wider release review follow in
Stages 13–14.
