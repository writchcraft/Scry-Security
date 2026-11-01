# Security and quality review

Current qualification and remaining release gates are in the
[release checklist](release_checklist.md). Windows is the primary release target;
Linux native collection remains experimental. Native-host audit details and
private test results stay outside the public repository and packages.

The application safeguards include bounded correlation contexts, transactional
source checkpoints, timestamped source health, request-body budgets, revision
checks for investigation updates, explicit file baseline approval, incomplete-scan
handling, escaped HTML and formula-safe CSV exports. These controls have
regression coverage; tests do not establish the absence of security flaws.

## Reproducible automated checks

Install review tools with `python -m pip install -e '.[dev,audit]'`, then run:

```text
python -m ruff check .
python -m ruff format --check .
python -m pytest --cov=scry_security --cov-branch --cov-report=term-missing
python -m pip check
python -m pip_audit --local --skip-editable
python -m build
python scripts/check_installed_wheel.py
```

Advisory results apply to the dependencies and date actually checked. The
unpublished editable project may be skipped by advisory lookup; its source
requires separate review and regression checks. Keep local dependency inventories
private if they reveal the operator environment.

Windows/Ubuntu CI remains mandatory. CI fixtures verify shared behaviour;
private native verification separately establishes source acquisition where
available. Final merge, tagging and publication require explicit owner approval.
