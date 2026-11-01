# Portfolio demonstration

The demonstration uses committed synthetic fixtures and a small disposable file
laboratory generated specifically for file-change comparison. It never reads
real authentication logs or opens a capture interface. All events, baselines and
reports are labelled synthetic. The file laboratory uses the actual local host
metadata; inspect paths before sharing screenshots or exports.

```powershell
.\.venv\Scripts\python.exe scripts/seed_demo.py --database data/demo.sqlite
```

Use a new filename if that database or its generated laboratory already exists.
The script preserves previous data. Its printed event/alert/report counts are
computed from actual imports and scans rather than supplied to the dashboard.
It creates three saved investigations and a recorded file comparison with
creation, modification and deletion evidence.

Generate a random token and start the same database:

```powershell
$env:SCRY_API_TOKEN = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))")
$env:SCRY_API_TOKEN
.\.venv\Scripts\python.exe -m scry_security --serve --database data/demo.sqlite
```

Open [the local dashboard](http://127.0.0.1:8765/) and enter that token. It stays
in page memory. Linux uses `.venv/bin/python` and the token commands shown in
`dashboard.md`. Stop with Ctrl+C. Do not use test-suite tokens with real evidence.

## Suggested walkthrough

1. Show the synthetic label, stored event totals, severity distribution, observed
   Windows/Linux hosts, recent incidents and authentication timeline.
2. Select real evidence and show that empty real storage produces zeros.
3. Open SSH/Windows authentication alerts. Explain threshold, time window,
   supporting records and why the successful logon does not prove compromise.
4. Save an investigating status with a note, then reopen it to show history.
5. Open Incident Reports, separate observations from interpretation, and export
   JSON/CSV/HTML. Point out synthetic provenance and false-positive guidance.
6. Show File Integrity's approved scope, hashes and create/modify/delete evidence.
   Explain why comparison never automatically accepts the changed state.
7. Show Detection Rules and the optional host-policy guide. Explain explicit
   expectations instead of claiming that unusual administration is malicious.
8. Show Settings. An unconfigured collector is not presented as healthy/live.
   Actual monitoring is a separate, explicitly configured process.

For a terminal demonstration, replay either authentication fixture or the
network/PCAP commands in the relevant guides. Show real stdout findings and
stderr record/error counts. Expected authentication results are six events and
two findings per suspicious fixture; the default benign fixtures produce none.

Be ready to explain how missing IPs, timestamps, Windows audit policy, Linux
source variation, source checkpoints, false positives and least privilege affect
confidence. The release checklist distinguishes tested behaviour from remaining
native-platform and CI gates; do not present planned or unverified work as proven.
