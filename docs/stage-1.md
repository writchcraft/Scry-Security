# Stage 1 — Foundation

## Objective and code walkthrough

Establish an installable, testable core that does not depend on either operating
system's event APIs. This stage is infrastructure, not a working SIEM.

- `src/scry_security/core/config.py`: a frozen settings object validates the log
  level and data path. Explicit constructor arguments override environment values,
  which override defaults. `pathlib.Path` avoids hardcoded path separators.
- `src/scry_security/core/platform.py`: a small enum and immutable dataclass
  describe the OS family, hostname, and release. Unknown families are explicitly
  unsupported. This does not inspect privileges or guarantee version support.
- `src/scry_security/core/logging.py`: the application logger emits UTC timestamps
  to stderr. Reconfiguration updates the level without duplicating its handler
  or replacing the root logger's handlers. UTC makes later timelines comparable
  across hosts; it cannot correct an inaccurate source clock.
- `src/scry_security/main.py`: an explicit entry point loads settings only when
  requested. Configuration errors report field names without echoing values.
  Importing the core starts no monitoring, file writes, or background threads.
- `pyproject.toml`: one source of package metadata and dependency requirements.
  The CLI and `python -m scry_security` call the same function.

## Run and verify

Use the installation and test commands in the README. A successful check prints
`platform_family_supported: true` and `collection_enabled: false` on Windows or
Linux. Ruff should pass, and pytest should pass all collected foundation tests.
Coverage reports show lines exercised; coverage alone does not prove correctness.

Tests cover defaults, paths with spaces, environment precedence, invalid settings,
logging idempotence and UTC output, CLI results, and Windows/Linux/unsupported
platform selection. Mocking `platform.system()` tests branch behaviour, not real
Windows log collection or real Linux execution. GitHub Actions is configured for
both runners with Python 3.12 and 3.13; remote results must be checked separately.

An optional negative check in PowerShell:

```powershell
$env:SCRY_LOG_LEVEL = 'INVALID'
.\.venv\Scripts\python.exe -m scry_security --check
$LASTEXITCODE
Remove-Item Env:SCRY_LOG_LEVEL
```

Expected: `Invalid configuration fields: log_level` and exit code `2`. Restoring
the variable allows the normal check to pass again.

## Explain it back

Try answering: why does identifying Windows tell us nothing about
whether failed logons are being audited? Why should a detection consume a common
authentication-failure event instead of querying Windows event IDs directly?

Stage 2 defines the event contract, validation rules, optional fields, raw
evidence handling, and timestamp policy before the native collectors.
