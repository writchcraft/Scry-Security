# Stage 12 — Explicit file integrity monitoring

SHA-256 identifies content changes relative to a separately approved baseline.
The baseline records selected files/directories, hashes, sizes, timestamps, host,
OS and the approver's reason for trusting that initial state. It never contains
file contents. A comparison produces creation, content-modification and deletion
events without accepting the new state. SCRY-FILE-001 sends those events through
the shared detection engine; legitimate updates remain a possible explanation.

## Create and compare a lab baseline

Keep outputs and databases outside the watched directory. In PowerShell:

```powershell
New-Item -ItemType Directory -Force data/fim-lab | Out-Null
Set-Content data/fim-lab/example.txt 'known lab content'
.\.venv\Scripts\python.exe -m scry_security --fim-baseline data/lab-baseline.json --watch data/fim-lab --approved-by 'Lab analyst' --approval-note 'Verified synthetic initial content' --synthetic --database data/demo.sqlite
.\.venv\Scripts\python.exe -m scry_security --fim-check data/lab-baseline.json --database data/demo.sqlite
Set-Content data/fim-lab/example.txt 'changed lab content'
.\.venv\Scripts\python.exe -m scry_security --fim-check data/lab-baseline.json --database data/demo.sqlite
```

The first comparison has zero changes. The second reports `file_modified` with
old/new hashes and sizes and stores a medium-severity investigation lead. The
dashboard's **File Integrity** section shows approved scopes and the latest saved
comparison, including failures. Creation/deletion can be demonstrated by adding
or removing a test file within this explicitly disposable lab directory.

Linux equivalents use `.venv/bin/python`, `mkdir -p data/fim-lab` and
`printf '%s\n' 'known lab content' > data/fim-lab/example.txt`. The Python command
options and baseline logic are shared. No administrator access is required for
files the current user can read. Repeat `--watch` for additional explicit paths.
There is no default filesystem-wide watch list or live background scanner.

Creating a baseline refuses to overwrite an existing JSON file. After reviewing
an approved update, create a new baseline with a new output path and approval
reason. Existing database baselines cannot be edited in place. Protect baseline
JSON, the database and backups against tampering; hashes do not authenticate an
unprotected baseline or provide an independent chain of custody.

## Failure and coverage limits

Default limits are 10,000 files/directories, 64 MiB per file and 512 MiB total
content read. Library callers can supply validated `ScanLimits`. File hashes are
streamed in 64 KiB chunks. Baseline imports are limited to 8 MiB. Symlinks,
junctions, non-regular files, access failures and files changing during hashing
prevent a completed comparison. Such failures produce no deletion conclusions.
An actually missing approved root is reported as absent, so its former files
can generate deletion events. Baselines belong to their original host and OS.

The scanner checks identities and modification metadata before/after reads and
rejects links, but it is not an atomic filesystem snapshot or an adversarially
race-proof acquisition system. Remote/slow filesystems can block native I/O;
keep sensitive local scopes small. Metadata-only changes with unchanged content
hashes do not generate content-change events. Compare results describe what was
observed during the scan, not every intermediate change between scans.

Tests cover stable content, creation/modification/deletion, immutable trust state,
JSON round trips, capacity failure, access failure, cross-host rejection, CLI
approval requirements, database integration and shared-rule alerts. The Unix
symlink test is explicitly skipped on Windows and must run under Linux CI.
