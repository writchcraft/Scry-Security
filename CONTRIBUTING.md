# Contributing

Use Python 3.12+ and the virtual-environment setup in the README. Install the
`dev` extra; add `windows` for native Windows tests, `packet-analysis` for offline
capture tests, and `audit` for dependency/build checks. Do not run collectors or
the dashboard as administrator merely to make a test pass.

Keep native source reading separate from parsing, and feed the shared event
schema rather than adding platform-specific detection branches. Preserve native
evidence, UTC timestamps, missing-field semantics, source-health reporting and
explicit synthetic labels. Default monitoring must remain opt-in and read-only.

For a detection, include required telemetry, bounded grouping/window logic,
false-positive considerations, investigation guidance and defensive actions.
Add both triggering and ordinary scenarios. Avoid claiming a technique mapping
or native platform capability that the evidence does not support. Host policy
must be explicit; unusual administration is not automatically compromise.

Run Ruff, pytest, dependency consistency and relevant packaging checks described
in `docs/quality_review.md`. Run the Windows/Ubuntu CI matrix before claiming
cross-platform support. Mocked tests are useful but do not replace native lab
evidence. Keep guides, example data and the release checklist consistent with code.

Never submit real credentials, operational databases, real log exports, incident
evidence or private environment files. Use documentation IP ranges and clearly
labelled synthetic examples. Report security issues according to `SECURITY.md`.

Describe the concrete problem, final behaviour, validation and material limits
in a pull request. The project uses the MIT licence; retain third-party notices.
