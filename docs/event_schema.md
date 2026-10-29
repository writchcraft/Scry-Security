# Stage 2 — Unified evidence contract

`src/scry_security/core/event_schema.py` defines the canonical Pydantic event.
All collectors produce this model before events can reach detection. Required
fields identify event time, source OS, host, category, event type and source.
Account, IP addresses, process information, native IDs and details are optional.
An absent IP is not an empty string or a shared correlation identity.

Time must contain a UTC offset and is converted to UTC. `ingested_at` is distinct
from source event time. UUIDs identify ingestions, not unique native records;
channel/file cursors are needed to avoid replay duplication. JSON serialisation
preserves the schema version. Unknown fields and unsupported source OS families
are rejected. Raw and normalised detail maps each have a 256 KiB encoded limit.

`normalise_records` streams independent results. A bad record produces a safe
field-name error while subsequent records continue. `ParseResult.skipped` means
an envelope was understood but its message/type is outside current coverage.
The event model is frozen at field level; nested evidence maps must be treated
as read-only by consumers. It is not a tamper-proof forensic evidence store.

An optional `context` map supports temporary derived detection information.
The engine discards supplied context and recomputes it from native fields and
approved policy. Database event payloads keep context empty; alert snapshots
retain the actual review reasons and policy hash. Context is excluded from event
fingerprints so policy changes do not manufacture new source records.

Security implication: retaining native evidence helps investigation but may
retain sensitive strings already present in logs. No collector should obtain
passwords or credentials deliberately. Access control and retention remain
necessary when persistence is added.

Run `python -m pytest tests/unit/test_event_schema.py` using the virtual
environment's Python. Fourteen schema tests passed locally on Windows, covering
UTC conversion, optional fields, IPv6, invalid input, bounded evidence and
continuation after malformed records.
