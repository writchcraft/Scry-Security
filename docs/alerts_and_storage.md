# Stages 8–9 — Investigation workflow and SQLite

A detection finding describes observed evidence and a rule match. An alert adds
`new`, `investigating`, `resolved` or `false_positive` status, a stable alert ID
and an attributed status history. Every status change requires an actor and a
nonempty investigation note. Closed alerts can be reopened when evidence changes.
Changes never remove the rule evidence or claim that suspicion proves compromise.
No external notifications or automatic account/network blocking are implemented.

`alerts/manager.py` owns these transitions. `database/models.py` maps hosts,
canonical events, rules, alerts and evidence links with SQLAlchemy. Configuration
and incident records provide storage for the subsequent service/reporting stages.
Raw and normalised evidence travel together in a versioned event JSON payload;
indexed columns support time, type, OS, host, severity and status filtering.

## Persist a demonstration

```powershell
.\.venv\Scripts\python.exe -m scry_security --replay sample_logs/linux/suspicious/brute_force.txt --format linux --synthetic --database data/demo.sqlite
```

First import: six new events and two new alerts. Repeating the command against
that file adds zero events and zero alerts. Synthetic evidence stays labelled.
From Python, use `Database(Path(...))` and `Store(database)` to query alerts,
retrieve supporting events, apply `set_status`, or run explicit cleanup. Close
the database with `database.close()` when finished.

`Store.alerts` supports inclusive UTC dates, severity, OS, host, rule ID, status,
synthetic label and bounded pagination. `supporting_events` returns a chronological
timeline. Alert notes survive reopening the database. Event/alert insertion and
evidence linking happen in one transaction. A failure rolls back the import.
Foreign-key enforcement is enabled explicitly on every connection; SQLite does
not provide that guarantee merely because models declare relationships. See
[SQLAlchemy's SQLite guidance](https://docs.sqlalchemy.org/en/20/dialects/sqlite.html).

## Limits and security

Evidence fingerprints exclude ingestion UUID and ingestion time, so importing
identical normalised evidence does not duplicate it. Native record IDs and raw
data are included. Identical text records without unique native identity and
with identical source timestamps cannot be distinguished; this is not an
exactly-once forensic acquisition guarantee.

The initial implementation recomputes chronological context over a maximum of
100,000 stored records on import. It supports correlation across imported batches
and is intentionally bounded; larger deployments need incremental durable
correlation and a migration plan. Late historical evidence can change a finding's
supporting set and generate an additional finding. Existing analyst state remains
attached to its original alert rather than being overwritten by a rebuild.

SQLite files and retained native evidence are not encrypted by this application.
New database files request mode 0600 on Unix, including in existing directories.
Windows ACLs remain inherited. A SQLite application marker identifies Scry-owned
files; unrelated nonempty databases are rejected before table creation. Recognised
early Scry development schemas can adopt the marker without deleting data.
New data directories request restrictive Unix permissions; Windows permissions
inherit the parent ACL. Use a private directory, verify local permissions, and
protect backups. No automatic permission elevation occurs. PostgreSQL remains a
future backend, not a verified capability. Schema migrations are not implemented;
do not treat this development database format as a stable release contract.

`cleanup_unlinked(before)` removes only events older than an explicit UTC cutoff
that are not linked to alerts. It never deletes an alert's supporting evidence.
No scheduled deletion runs by default. Closing an alert does not authorise
deleting its evidence. A future retention policy must address alert/incident
archives, backups and the owner’s investigation requirements explicitly.

Run `python -m pytest tests/unit/test_alerts.py tests/integration/test_database.py`.
Tests exercise real SQLite files, fresh-import deduplication, restart persistence,
filtering, status notes, transaction rollback and preservation of linked evidence.
