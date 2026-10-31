# Staged roadmap

Stages 1–12 have implementation and local tests. Native Linux execution and
successful privileged Windows collection remain unverified. Stage 13 is active.
Continue stages in order, verifying and explaining each without approval stops.

1. Foundation: packaging, environment, configuration, UTC logging, OS detection.
2. Unified event schema: event validation, normalisation, UTC timestamp handling.
3. Linux collectors: authentication logs, journal, parsers and fixtures.
4. Windows collectors: native Event Log integration, parsers and fixtures.
5. Shared detection engine: authentication, privilege, account manipulation.
6. YAML rules: bounded conditions, thresholds, ATT&CK references and rule guide.
7. Network analysis: connection metadata, synthetic data, optional packet capture.
8. Alerts: severity, correlation, evidence and investigation status.
9. Database: SQLAlchemy, SQLite, persistence, retention and cleanup.
10. Dashboard: protected FastAPI endpoints, real stored metrics and investigation UI.
11. Reporting: JSON, CSV, HTML and three synthetic example investigations.
12. File integrity: explicit paths, approved baselines and change detection.
13. Security and QA: broaden existing tests, CI, dependency and security review.
14. Release: documentation, branding, screenshots, demonstrations and licence.

Tests and security considerations accompany every stage, rather than waiting for
Stage 13. Platform-independent foundations are tested against both OS families
before native adapters arrive. CI configuration is introduced early for the same reason.
