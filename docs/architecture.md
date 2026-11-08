# Architecture

## Shared core, native collection

Windows 10/11 are the primary release targets; Linux adapters remain experimental.
Both platforms retain the same shared architecture and mandatory CI. Their
telemetry differs, but the
meaning of a normalised authentication failure can be shared. Collection source
and native event identifiers must remain attached to the evidence.

```mermaid
flowchart LR
    W[Windows Event Log adapter] --> P[Native parsers]
    L[Linux auth log / journal adapter] --> P
    S[Synthetic or historical inputs] --> P
    P --> N[Validated UTC event schema]
    N --> D[Shared detection and correlation]
    D --> A[Alert management]
    N --> DB[(Event and alert storage)]
    A --> DB
    DB --> API[API and dashboard]
    DB --> R[Incident reports]
```

This diagram describes the implemented pipeline: native collection and parsing,
shared detection, durable SQLite evidence, authenticated dashboard and saved
incident exports. Native Windows 11 verification covers Security/System reads,
4624/4625/4672, re-parsing, persistence, deduplication and restart checkpoints.
Host-specific native verification details remain private.
The complete rule catalogue is additionally covered by synthetic automated tests.
Native Linux authentication collection remains unverified; Ubuntu tests exercise
fixtures and mocks. It is a deferred qualification, not a Windows release gate.

For example, Windows event 4625 and a Linux SSH failure will map to a common
authentication-failure event. A shared rule can count failures within a time
window, grouped by host and source address. Native fields remain available for
investigation. Missing addresses must not be treated as one shared attacker.

## Refinements to the brief

- Separate native reading from parsing. Parsers can accept historical fixtures
  without administrator permissions or platform-specific imports.
- Keep optional Windows imports inside Windows adapters. Installing or importing
  the core on Linux must not require pywin32; Linux sources must not be assumed
  present on every distribution.
- Detect capabilities separately from OS family. Windows identification does not
  prove Security log access, audit policy, or PowerShell telemetry availability.
  Linux identification does not prove auth.log, systemd, or journal access.
  Collectors report available, unavailable, permission-denied, and
  degraded states rather than silently showing zero events.
- Keep privileged collection separate from the web process. The dashboard
  queries stored results without inheriting collector privileges. Transport
  and authentication will be designed before introducing remote collection.
- Preserve raw evidence where justified, with retention and access controls.
  Fingerprint deduplication and transactional source cursors support polling,
  restart and journal continuation. Windows log clearing/record-ID reset still
  requires operator reconciliation; lossless collection is not guaranteed.
  Event time and ingestion time are distinct; timezone-free historical records
  need explicit source context.
- Bound buffers and correlation windows. An input flood must not cause unbounded
  memory growth. Malformed records need isolated errors and health counters.
- File integrity monitoring uses explicit paths and separates baseline approval
  from comparison; silently accepting changed hashes defeats the purpose.

## Technology decisions

Python 3.12+ is the initial baseline. `pyproject.toml` owns metadata and dependencies;
`src/` separates installable code from repository files. Pydantic Settings supplies
typed environment validation. Python logging and pathlib cover console diagnostics
and native filesystem paths without extra runtime packages.

Stages 2–9 introduce Pydantic event models, pywin32 on Windows only, Linux file
and journal readers, safe YAML loading, psutil metadata, optional offline Scapy
analysis, SQLAlchemy and SQLite. Stage 10 adds FastAPI/Uvicorn with HTML/CSS/JavaScript
and Chart.js. PostgreSQL and live capture remain later options. Dependencies are
added when their implementation and tests exist. No Sigma compatibility is claimed.

## Repository structure

Foundation layout (later package contents are documented in stage guides):

```text
pyproject.toml
src/scry_security/
    __init__.py
    __main__.py
    main.py
    core/
        config.py
        platform.py
        logging.py
tests/unit/test_foundation.py
docs/
    architecture.md
    stage-1.md
    roadmap.md
    security_model.md
.github/workflows/tests.yml
```

Implemented packages also include collectors/{windows,linux,network}, parsers,
detection, alerts, database, services, integrity, API, reports and dashboard.
The default rule catalogue is packaged under `rule_catalog/` so installed commands
can load it independently of the checkout. Root `rules/` documents custom catalogues;
synthetic sample logs and future incident examples remain outside the package.
