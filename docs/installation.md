# Installation

Windows 10/11 are the primary target platforms, using Python 3.12+.
Native qualification covers Windows 11; Windows 10 remains unverified.
Linux functionality is experimental. Windows/Ubuntu Python 3.12/3.13 CI remains
mandatory, but genuine Linux authentication acquisition is a future qualification,
not a Windows-first release gate. No Ubuntu VM is required. See
[release evidence](release_checklist.md) for the tested candidate and limits.

## Windows PowerShell

From the checked-out repository:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev,windows,packet-analysis,audit]"
.\.venv\Scripts\python.exe -m scry_security --check
```

This installs project and review tools only into `.venv`. Calling that Python
directly avoids changing PowerShell execution policy. The Windows extra installs
pywin32 only on Windows. Packet analysis is optional and does not grant capture
rights. The check prints actual host/configuration metadata and starts no collector.

## Ubuntu/Debian (experimental)

Install an approved Python 3.12+ distribution and its matching `venv` package.
Distribution defaults vary; check the version before creating the environment.

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev,packet-analysis,audit]'
.venv/bin/python -m scry_security --check
```

Do not install application packages into the distribution's system Python or run
pip as root. Auth/journal permissions are a separate source configuration decision.
Follow `linux_setup.md` for available sources rather than assuming auth.log exists.

## Distribution and runtime-only use

`pyproject.toml` is the dependency/metadata source. `python -m build` creates a
source distribution and universal Python wheel. Install a built wheel with your
environment's pip. The wheel includes rules, dashboard assets and licence notices;
source distributions also contain guides, tests and synthetic demonstrations.
Editable installs are intended for development. Optional extras can be selected
on an installed distribution as well.

For a clean Windows candidate installation, build from the checkout and install
into a new virtual environment (choose a new directory each time):

```powershell
.\.venv\Scripts\python.exe -m build
python -m venv data\candidate-venv
.\data\candidate-venv\Scripts\python.exe -m pip install --upgrade pip
.\data\candidate-venv\Scripts\python.exe -m pip install "dist\scry_security-1.0.0rc1-py3-none-any.whl[windows,packet-analysis]"
.\data\candidate-venv\Scripts\scry-security.exe --version
.\data\candidate-venv\Scripts\scry-security.exe --check
.\data\candidate-venv\Scripts\python.exe -m pip check
```

The release candidate is `1.0.0rc1`; installing it does not publish or approve
`1.0.0`. Keep collectors and the dashboard in separate processes. Run the
dashboard unelevated; elevate only a bounded collector when required.

The default application data directory is `./data`, relative to the working
directory. Set `SCRY_DATA_DIR` or an explicit `--database` path when needed. Use
a private directory and protect exported evidence. Unrelated SQLite files are
rejected; recognised earlier Scry development schemas can adopt the application
marker. Development schemas are not a production migration guarantee.

For a safe first demonstration, see `demonstration.md`. For actual collection,
use `monitoring.md`, platform guides and the security model. No service or driver
is installed automatically. Use the dashboard guide for local token-authenticated
serving and incident investigation.
