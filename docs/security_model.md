# Security model

Scry is a local single-user investigation application. Native logs, imported
records, XML, rules and filesystem state are untrusted input. Original logs stay
read-only. The application does not change audit policy, block accounts, execute
remediation, or equate suspicion with confirmed compromise.

## Privilege and access boundaries

Collector and dashboard commands are separate processes. Run both with minimum
rights; the web process does not need native Security log or capture rights.
Platform guides document telemetry permissions. No service, driver, group
membership or privilege is configured automatically.

The server binds to IPv4 loopback. All data routes require a bearer token,
including exports, file-integrity results and source health. Tokens remain in
page memory. Native evidence is rendered as text, not HTML. CSP, no-sniff,
no-referrer, no-store and a host allowlist add browser protections. Analyst names
are self-reported; this is not a multiuser identity system. Remote use needs TLS,
individual authentication/authorisation, rate limits and deployment review.

SQLite, baseline and report access depends on private filesystem permissions,
not API tokens. New data directories request restrictive Unix modes; Windows
inherits parent ACLs. Verify permissions and backups. Storage is not encrypted
or a tamper-proof chain of custody. A compromised local account is outside this
application's isolation boundary.

## Input and integrity safeguards

Pydantic schemas and record/replay/rule/report/correlation/scan budgets reject
invalid or oversized scopes. XML rejects DTDs/entities. YAML uses safe types,
unique keys and no aliases; TOML uses the standard parser and typed validation.
Journal subprocesses use argument lists without a shell and bounded reads/time.
Mutating HTTP bodies have a 64 KiB budget and 10-second receive timeout, including
chunked input. Fields impose narrower limits after parsing.

HTML reports escape native evidence. CSV prefixes potentially executable formula
cells; JSON preserves exact values. Alert revisions reject stale dashboard edits,
and an atomic revision condition prevents silently replacing concurrent notes.
Event/alert ingestion and source cursors share a transaction. Explicit retention
preserves alert-linked evidence. Incident snapshots preserve their original state.

File comparisons never replace approved trust state, follow links deliberately,
or retain file contents. Incomplete comparisons yield no deletion conclusions.
Scanning is not an atomic filesystem snapshot or race-proof acquisition system.

## Evidence and verification limits

UTC source time differs from ingestion time. Missing IPs are not grouped into a
fictional attacker. Synthetic and real contexts stay separate. Fingerprints
deduplicate identical imports but do not guarantee lossless collection across
different feeds. Windows log clearing, text rotation, retention and permissions
can cause gaps. Last-check timestamps help reveal stalled polling; source
availability does not prove all auditing is enabled.

Tests cover native parsers, suspicious and benign patterns, SQLite transactions,
auth, report escaping, file changes, source checkpoints and request budgets.
Ruff and package advisory checks supplement tests; they do not prove absence of
security flaws. See verification and release-checklist documents for actual
results. Windows/Ubuntu CI passed on Python 3.12/3.13 at commit `aaf1779`.
Elevated Windows Security acquisition/preservation passed on 8 November 2026.
Genuine Linux authentication collection remains unverified; mocked source tests
must not be presented as native source certification.
