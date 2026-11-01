# Stages 5–6 — Shared detections and YAML rules

The engine consumes only `SecurityEvent`. Windows 4625 and an SSH failure have
the same `authentication_failure` type, so the correlation code has no Windows
event numbers, Linux regular expressions or platform imports.

## Default catalogue

| ID | Logic | Benign counterexample |
| --- | --- | --- |
| SCRY-AUTH-001 | 5 failures for one host, OS, source IP and account in 300 seconds | Fewer failures or failures outside the window |
| SCRY-AUTH-002 | 5 distinct accounts failing from one host/OS/source in 300 seconds | Repeated mistakes against one account |
| SCRY-AUTH-003 | Success following 5 failures for that host/OS/source/account | Success without the preceding failure threshold |
| SCRY-ACCOUNT-001 | Membership added to built-in Administrators SID S-1-5-32-544 | Addition to an ordinary group |
| SCRY-SYSTEM-001 | Windows Security audit log clearing event | Ordinary privileged logon |

These are investigation leads, not verdicts. Authorised administrative changes
and lab resets can trigger the latter rules. Configure explicit exclusions only
after validating local policy. Account creation, sudo use, unusual ports and
special privilege assignment alone do not automatically generate alerts.

## Replay a complete scenario

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m scry_security --replay sample_logs/linux/suspicious/brute_force.txt --format linux --synthetic
.\.venv\Scripts\python.exe -m scry_security --replay sample_logs/windows/suspicious/authentication.xml --format windows --synthetic
.\.venv\Scripts\python.exe -m scry_security --replay sample_logs/linux/benign/ordinary.txt --format linux --synthetic
```

On Linux, replace the executable with `.venv/bin/python`. Suspicious inputs
produce two JSON findings on stdout: repeated failures and success after failures.
The ordinary fixture produces no findings. Counts go to stderr. Malformed records
increment an error count without stopping valid records; the command exits 2 if
any record failed. Unknown supported envelopes can be skipped without error.
Canonical JSONL input is also accepted with `--format canonical` (the default).

`--year 2026 --utc-offset=+00:00` supplies legacy syslog context. A fixed offset is
appropriate only when the importer has resolved source daylight-saving context.
Do not label real evidence synthetic or mix test evidence into real investigations.

## Write and tune rules

The packaged default is `src/scry_security/rule_catalog/default.yaml`, a list of
rule mappings. Copy it to a custom file and select it with `--rules path.yaml`.
Each rule requires ID, name, description, severity, supported operating systems,
required source description, event types, false positives, investigation guidance
and defensive actions. Unknown fields are rejected. Useful configurable fields:

- `mode: threshold` counts matching records; `threshold` and `window_seconds`
  set the boundary (inclusive start). A distinct mode counts nonmissing distinct
  scalar values in `distinct_field`. A sequence mode requires preceding events
  of `preceding_event_type` before a matching final event.
- `group_by` partitions evidence. Missing or nonscalar grouping values prevent
  a match, so unknown IPs are never pooled into an invented shared attacker.
- `conditions` maps allowed fields to accepted values (AND across fields, OR
  within a list). `exclude` suppresses an event if any listed field matches.
  Native detail fields use `details.FieldName`. There are no executable
  expressions, regular-expression operators, arbitrary attribute paths or imports.
- `required_sources` documents telemetry prerequisites; it does not assert that
  auditing is enabled. Source-health monitoring must establish availability.
- `mitre_techniques` records justified ATT&CK references. New mappings require
  review of the evidence and current authoritative technique definitions.

Add tests for a triggering sequence, ordinary activity, missing context and time
boundaries. Change expected test values when intentionally tuning thresholds.
The loader uses safe YAML types, rejects aliases/anchors and duplicate keys,
limits files to 1 MiB and catalogues to 100 rules. Invalid catalogues fail closed.

## Correlation limits

Replay sorts a maximum of 10,000 records by source event time. Streaming `process`
requires nondecreasing timestamps; a later service must reorder/replay late
telemetry rather than silently ignore it. Memory holds at most the configured
event capacity and the longest rule window. Capacity exhaustion is explicit.
Repeated event UUIDs within retained context are ignored. UUID deduplication
cannot replace native source checkpoints for newly imported copies of a record.

A rule/group emits once per rule window to reduce repeated findings. Synthetic
and real contexts remain separate. Finding IDs derive from rule and supporting
event IDs. Findings retain the evidence IDs, count, rule description, severity,
false positives and investigation guidance. Alert status and persistence are
introduced in Stages 8–9; this engine's current correlation state is in memory.

## ATT&CK and Sigma

Repeated authentication patterns map to [T1110](https://attack.mitre.org/techniques/T1110/).
Multiple targeted accounts do not prove the same password was reused, so the
catalogue does not claim T1110.003 specifically. A success after failures does
not establish credential theft and carries no automatic T1078 mapping.
Privileged group changes relate to [T1098](https://attack.mitre.org/techniques/T1098/).
The current [T1685.005](https://attack.mitre.org/techniques/T1685/) covers Windows
log clearing; the older T1070.001 identifier was not retained in this catalogue.
These mappings describe potentially relevant behaviour, not confirmed intent.

The schema borrows readable selection, grouping and time-window concepts from
detection engineering. It is **not Sigma-compatible** and does not import Sigma
rules. Sigma has its own [correlation specification](https://sigmahq.io/docs/meta/correlations),
field mappings and backend semantics. An adapter would need explicit translation
and independent conformance tests before any compatibility claim.
