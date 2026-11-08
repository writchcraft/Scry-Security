# Stage 10 — Local security dashboard

FastAPI serves the locally bundled HTML/CSS/JavaScript interface and authenticated
JSON routes from `src/scry_security/api/app.py`. The application factory accepts a
store and token explicitly; importing it starts no server or collectors.

## Start the dashboard

First import one or more synthetic fixtures as described in `detection_logic.md`,
using the same SQLite file for each import. Then, in PowerShell:

```powershell
$env:SCRY_API_TOKEN = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))")
# Copy the generated token locally for the login form. Do not share it.
$env:SCRY_API_TOKEN
.\.venv\Scripts\python.exe -m scry_security --serve --database data/demo.sqlite
```

Linux:

```bash
export SCRY_API_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
printf '%s\n' "$SCRY_API_TOKEN"
.venv/bin/python -m scry_security --serve --database data/demo.sqlite
```

Open [the local dashboard](http://127.0.0.1:8765/) and enter that token. The
server requires at least 32 characters; use randomly generated tokens, not
memorable passwords or the public token used in tests. The token remains in the
page's memory, never a URL, cookie or local-storage setting. Refreshing the page
locks it. Close with Ctrl+C and clear the environment variable when finished.
`--port` changes the loopback port. Without `--database`, storage defaults to
`SCRY_DATA_DIR/scry.sqlite`.

The public shell and static assets contain no evidence. Every `/api/` route
requires a bearer token. The command binds only to 127.0.0.1 and does not provide
a public hosting mode. No collector runs inside the web process. Treat this as a
single-user local workspace; analyst names in notes are self-reported, not
independently authenticated user identities. Remote/multiuser use needs TLS,
individual identity, authorisation, concurrency review and operational hardening.

## What works

Overview counters, authentication-hour bars, severity distribution, host OS
breakdown and top source addresses associated with findings query stored data.
The three evidence selections are synthetic, real, and mixed; synthetic is the
initial view. Empty real storage displays zeros, not demonstration values.
Hosts are labelled observed rather than assumed to be actively monitored.

Events show UTC times, native sources and expandable JSON evidence. Windows,
Linux, authentication and network sections select matching events. Alert tables
support severity/status and shared table filters for OS, exact hostname, rule ID
and UTC dates. Metrics cover all stored dates in the selected evidence mode.
Tables paginate. Investigation dialogs show evidence, interpretation, possible
false positives, guidance, ATT&CK references and status history. Saving a new
status requires a named actor and a note, and writes to SQLite.

Threat Detection/Detection Rules show the packaged catalogue. A custom replay
catalogue is stored with imported alerts; the rules view currently shows packaged
defaults rather than an editable active service configuration. Incident Reports
now lists immutable investigation snapshots with JSON/CSV/HTML export controls.
File Integrity displays approved scopes and recorded comparisons. Settings shows
recorded collector health, stale checks and current host-policy scope. These
sections use authenticated stored data; the dashboard does not start collectors.

Chart.js 4.5.1 is bundled in `dashboard/static/` with its MIT licence. Browser
operation makes no chart-CDN requests. Native evidence is rendered through text
nodes rather than HTML injection. Content Security Policy, no-sniff, no-referrer,
no-store headers and a loopback host allowlist add browser protections.
Database access remains protected by filesystem permissions, not API tokens.

## Verification

`tests/integration/test_api.py` tests missing/wrong-token rejection, host
validation, actual stored totals, synthetic filtering, evidence retrieval,
status updates, pagination constraints and offset-aware date validation.
The Windows sandbox blocked asyncio's internal socketpair during the first API
test run. Allowing loopback sockets let all 91 tests pass locally.

Browser verification used a private synthetic database with 18 events, five
alerts and one observed host of each OS. The real-evidence selection showed zero
events/alerts. A group-change investigation was opened and saved as investigating,
and the table reflected the persisted update. Narrow and desktop layout
breakpoints were inspected. A full overview screenshot is stored at
`screenshots/dashboard-overview.jpg`. This is synthetic evidence, visibly labelled.

The initial browser results above describe an earlier development snapshot.
The 8 November 2026 GUI update applies the supplied eleven-colour palette to
backgrounds, navigation, cards, controls, chart datasets, status indicators and
the SVG logo. Browser-computed CSS tokens matched every supplied hex value;
the overview, chart area, alert badges and investigation dialog were inspected.
Screenshots show the private synthetic review database (27 events, 12 alerts,
four saved incidents), with colours taken from shared CSS tokens.

| Role | Colour |
| --- | --- |
| Primary background | `#0B111B` |
| Secondary background | `#101A28` |
| Cards and surfaces | `#151F2E` |
| Borders | `#263548` |
| Primary accent | `#38BDF8` |
| Protected/success state | `#00D6B2` |
| Primary text | `#E7EEF7` |
| Muted text | `#8C9DB2` |
| Critical/error | `#FF5765` |
| Warning | `#F5B942` |
| Informational | `#818CF8` |

The [initial remote CI run](https://github.com/writchcraft/Scry-Security/actions/runs/42491272049)
passed on Windows/Ubuntu with Python 3.12/3.13. These results verify runtime tests
and installation on those runners; permitted native Security-log and deployed
Linux authentication-source checks remain separate release gates.
