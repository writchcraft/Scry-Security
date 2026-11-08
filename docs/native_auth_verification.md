# Native authentication verification

Linux native collection is experimental and is not a Windows-first release gate.
No Ubuntu VM is required for this release. The optional Linux procedure below
has not been executed against genuine native Linux authentication telemetry.

Host-specific test results, native records, audit summaries and evidence hashes
are private operator material. Keep them outside version control and distribution
archives. Public CI uses synthetic fixtures and never generates host logon attempts.

## Windows: exact read-only elevated commands

Install dependencies first from a normal PowerShell in the repository:

```powershell
Set-Location 'C:\path\to\Scry-Security'
.\.venv\Scripts\python.exe -m pip install -e '.[windows]'
Start-Process powershell.exe -Verb RunAs
```

Approve the Windows UAC prompt yourself. In the new elevated PowerShell:

```powershell
Set-Location 'C:\path\to\Scry-Security'
$scryPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$scryPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# Must print True. A sandbox exception is not equivalent to administrator elevation.
$scryEvidence = Join-Path (Get-Location).Path ('data\native-auth-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
.\.venv\Scripts\python.exe scripts\verify_native_auth.py --source windows-security --max-records 10000 --output-dir $scryEvidence
$scryResult = $LASTEXITCODE
Get-Content (Join-Path $scryEvidence 'summary.json')
Write-Output "Verifier exit: $scryResult"
```

The output directory must not already exist. The script looks up the latest
channel record ID and reads a bounded recent forward range through Scry's
existing collector. It creates `events.jsonl`, `native.sqlite` and `summary.json`.
It never clears logs, changes policies/ACLs/groups or generates authentication
attempts. Close the elevated shell afterwards; keep the dashboard unelevated.
Protect these files using your existing private parent ACLs. Do not upload raw
Security XML or the database to GitHub. Directory mode 0700 applies on Unix;
Windows uses inherited ACLs.

Exit 0 requires an available source, at least one native authentication event,
matching re-parsed normalisation and matching evidence after reopening SQLite.
It does **not** require an alert. Exit 2 means the acquisition/preservation gate
was not met; inspect status, parse errors and event counts. An empty source is
not successful authentication verification. Source availability alone says
nothing about the completeness of the host's audit configuration.

## Ubuntu 24.04 disposable VM preparation

Provision a new Ubuntu 24.04 LTS VM using your approved hypervisor and official
Ubuntu image. Use its console, a snapshot, an ordinary sudo-capable operator
account, UTC timezone and NAT with **no port forwards or bridged adapter**.
No existing workloads, accounts or network services should depend on this VM.
Record image/version, time, hostname and the commit. Installing a hypervisor or
changing the host's virtualisation/security settings is outside this procedure.

All following commands run in **Bash inside that VM**, never on a Windows host
or a production server. These are optional future qualification instructions,
not a claim that native Linux acquisition has passed.

```bash
sudo apt-get update
sudo apt-get install -y python3.12-venv git openssh-server openssh-client
# This is a fresh isolated VM; stop the distribution listener/socket.
sudo systemctl stop ssh.service ssh.socket
umask 077
mkdir -p "$HOME/scry-release"
cd "$HOME/scry-release"
git clone --branch codex/portfolio-preview https://github.com/writchcraft/Scry-Security.git
cd Scry-Security
git checkout --detach 87f0c53d8ccb91bb7aa571b3d3d5eb4b1c752adf
test "$(git rev-parse HEAD)" = 87f0c53d8ccb91bb7aa571b3d3d5eb4b1c752adf
# This is the exact application/verifier candidate requested for native testing.
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev,packet-analysis,audit]'
.venv/bin/python -m scry_security --check
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m pytest --cov=scry_security --cov-branch --cov-report=term-missing
.venv/bin/python -m pip_audit --local --skip-editable
mkdir -p data
SCRY_PY="$PWD/.venv/bin/python"
SCRY_VERIFY="$PWD/scripts/verify_native_auth.py"
SCRY_LAB="$PWD/data/linux-native-lab"
mkdir -m 700 "$SCRY_LAB"
cat /etc/os-release
uname -a
date -u
hostname
```

Record package versions with `.venv/bin/python -m pip freeze`. Never run pip as
root. Root is used below only for the dedicated lab sshd, its files and read-only
system journal collection; no journal group memberships or access ACLs are granted.

## Dedicated loopback-only SSH lab

Create a dedicated unprivileged account. Set a random lab-only password at the
interactive prompt so the account is not locked. The dedicated daemon accepts
keys only, so this password is not sent by SSH or stored in scripts.

```bash
sudo useradd --create-home --shell /bin/bash scry-lab
sudo passwd scry-lab
ssh-keygen -q -t ed25519 -N '' -f "$SCRY_LAB/accepted"
ssh-keygen -q -t ed25519 -N '' -f "$SCRY_LAB/rejected"
sudo install -d -m 755 /etc/scry-release-lab /run/sshd
sudo ssh-keygen -q -t ed25519 -N '' -f /etc/scry-release-lab/host_ed25519
sudo install -m 644 "$SCRY_LAB/accepted.pub" /etc/scry-release-lab/authorized_keys
sudo tee /etc/scry-release-lab/sshd_config >/dev/null <<'EOF'
Port 22222
AddressFamily inet
ListenAddress 127.0.0.1
HostKey /etc/scry-release-lab/host_ed25519
PidFile /run/scry-release-sshd.pid
AuthorizedKeysFile /etc/scry-release-lab/authorized_keys
AllowUsers scry-lab
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
StrictModes yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
LogLevel VERBOSE
SyslogFacility AUTHPRIV
EOF
sudo /usr/sbin/sshd -t -f /etc/scry-release-lab/sshd_config
sudo systemd-run --unit=scry-release-sshd --property=Type=simple \
    /usr/sbin/sshd -D -f /etc/scry-release-lab/sshd_config
sudo systemctl status scry-release-sshd --no-pager
sudo ss -lntp '( sport = :22222 )'
# Require 127.0.0.1:22222 only. Stop immediately if externally bound.
sudo cat /etc/scry-release-lab/host_ed25519.pub | \
    awk '{print "[127.0.0.1]:22222 "$1" "$2}' > "$SCRY_LAB/known_hosts"
```

Only the public authorised key is world-readable. Private keys remain private;
no normal SSH configuration, audit policy, PAM policy or firewall is weakened.
Check VM-local lockout/security policy before proceeding. Do not disable a
lockout or anti-abuse control to make a test pass; use a fresh authorised image
or record that limitation. The next commands are authorised lab activity and must
never be pointed at another host or account.

## Benign live baseline before failure activity

These additional checks are prepared, not executed. Run them in the same VM
Bash session after starting the dedicated loopback sshd. First collect one genuine
accepted-key logon before generating failures:

```bash
sudo journalctl --sync
SCRY_BENIGN_CURSOR=$(sudo journalctl -n 1 --no-pager -o json | \
    "$SCRY_PY" -c 'import sys,json; print(json.loads(sys.stdin.readline())["__CURSOR"])')
ssh -p 22222 -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o PreferredAuthentications=publickey -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$SCRY_LAB/known_hosts" -o ConnectTimeout=5 \
    -i "$SCRY_LAB/accepted" scry-lab@127.0.0.1 true
# Require the SSH command above to exit 0 before continuing.
sudo journalctl --sync
sudo "$SCRY_PY" "$SCRY_VERIFY" --source linux-journal \
    --journal-cursor "$SCRY_BENIGN_CURSOR" --max-records 10000 --lab-generated \
    --output-dir "$SCRY_LAB/benign-evidence"
sudo "$SCRY_PY" - "$SCRY_LAB/benign-evidence" <<'PYTHON'
import json, sys
from pathlib import Path
from scry_security.database.database import Database
from scry_security.database.repositories import Store
p = Path(sys.argv[1])
s = json.loads((p / 'summary.json').read_text())
assert s['status'] == 'available' and s['reopened_storage_matches'], s
rows = [json.loads(line) for line in (p / 'events.jsonl').read_text().splitlines()]
lab = [e for e in rows if e['username'] == 'scry-lab' and e['source_ip'] == '127.0.0.1']
assert any(e['event_type'] == 'authentication_success' for e in lab)
assert not any(e['event_type'] == 'authentication_failure' for e in lab)
db = Database(p / 'native.sqlite')
try:
    assert not [a for a in Store(db).alerts(limit=1000)
                if a.username == 'scry-lab' and a.source_ip == '127.0.0.1']
finally:
    db.close()
print('Observed benign live baseline acquired without a targeted alert.')
PYTHON
```

Only print a passing result after assertions succeed on actual OS records.
Use a new cursor below so the benign baseline is not counted in the failure run.

## Capture cursor, five failed SSH attempts, then one success

```bash
sudo journalctl --sync
SCRY_CURSOR=$(sudo journalctl -n 1 --no-pager -o json | \
    "$SCRY_PY" -c 'import sys,json; print(json.loads(sys.stdin.readline())["__CURSOR"])')
printf '%s\n' "$SCRY_CURSOR" > "$SCRY_LAB/start-cursor.txt"
SCRY_SSH=(-p 22222 -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o PreferredAuthentications=publickey -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$SCRY_LAB/known_hosts" -o ConnectTimeout=5)
for attempt in 1 2 3 4 5; do
    if ssh "${SCRY_SSH[@]}" -i "$SCRY_LAB/rejected" scry-lab@127.0.0.1 true; then
        echo 'Unexpected rejected-key success; stop and inspect configuration.'
        exit 1
    else
        echo "Expected lab rejection $attempt"
    fi
done
ssh "${SCRY_SSH[@]}" -i "$SCRY_LAB/accepted" scry-lab@127.0.0.1 true
# Require exit 0 above. Complete all attempts within the five-minute rule window.
sudo journalctl --sync
sudo "$SCRY_PY" "$SCRY_VERIFY" --source linux-journal \
    --journal-cursor "$SCRY_CURSOR" --max-records 10000 --lab-generated \
    --output-dir "$SCRY_LAB/journal-evidence"
```

Wrong-key client exit codes alone do not establish that the server logged
normalisable authentication failures. Inspect the actual records and summary.
The source program may be `sshd` or `sshd-session`; both are supported. Preserve
raw `MESSAGE`, hostname, microsecond timestamp, program and `__CURSOR` fields.
The `lab_generated=true` run metadata describes **genuine OS events generated in
an authorised lab**, while each event remains `synthetic=false`. This is different
from hand-authored parser fixtures.

Check targeted detections and stored source provenance, not just global counts:

```bash
sudo "$SCRY_PY" - "$SCRY_LAB/journal-evidence" <<'PY'
import json, sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from scry_security.core.event_schema import SecurityEvent
from scry_security.detection.engine import DetectionEngine
from scry_security.detection.loader import load_rules
from scry_security.database.database import Database
from scry_security.database.repositories import Store
p = Path(sys.argv[1])
s = json.loads((p / 'summary.json').read_text())
assert s['status'] == 'available', s
assert s['normalisation_matches_raw'] and s['reopened_storage_matches'], s
rows = [json.loads(line) for line in (p / 'events.jsonl').read_text().splitlines()]
lab = [e for e in rows if e['username'] == 'scry-lab' and e['source_ip'] == '127.0.0.1']
assert sum(e['event_type'] == 'authentication_failure' for e in lab) >= 5
assert sum(e['event_type'] == 'authentication_success' for e in lab) >= 1
assert all(not e['synthetic'] and e['source'] == 'systemd-journal'
           and e['native_record_id'] == e['raw']['__CURSOR'] for e in lab)
for e in lab:
    native_time = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
        microseconds=int(e['raw']['__REALTIME_TIMESTAMP']))
    assert datetime.fromisoformat(e['timestamp']) == native_time
    assert e['operating_system'] == 'linux' and e['hostname'] == e['raw']['_HOSTNAME']
# Verification-only replay of acquired OS records, not generated fixtures:
failures = sorted([SecurityEvent.model_validate(e) for e in lab
                   if e['event_type'] == 'authentication_failure'], key=lambda e: e.timestamp)
assert failures[4].timestamp - failures[0].timestamp <= timedelta(seconds=300)
assert 'SCRY-AUTH-001' not in {f.rule_id for f in DetectionEngine(load_rules()).analyse(failures[:4])}
assert 'SCRY-AUTH-001' in {f.rule_id for f in DetectionEngine(load_rules()).analyse(failures[:5])}
db = Database(p / 'native.sqlite')
try:
    alerts = [a for a in Store(db).alerts(limit=1000)
              if a.username == 'scry-lab' and a.source_ip == '127.0.0.1']
    assert {'SCRY-AUTH-001', 'SCRY-AUTH-003'} <= {a.rule_id for a in alerts}
    assert all(not a.synthetic and Store(db).supporting_events(a.alert_id) for a in alerts)
    print('Live lab acquisition, evidence reopen and two positive detections passed.')
finally:
    db.close()
PY
```

If these assertions fail, preserve the output and keep the affected gate open.
Do not relabel synthetic fixtures as live results. No spray/lockout/account-change
or host-policy positive detection is expected from this six-attempt scenario.

## Monitoring CLI checkpoints and restart

```bash
cat > "$SCRY_LAB/monitor.toml" <<'EOF'
synthetic = false
[[sources]]
source_id = "lab-journal"
kind = "linux_journal"
max_records = 10000
EOF
sudo "$SCRY_PY" -m scry_security --collect-once "$SCRY_LAB/monitor.toml" \
    --database "$SCRY_LAB/monitor.sqlite"
sudo "$SCRY_PY" -m scry_security --collect-once "$SCRY_LAB/monitor.toml" \
    --database "$SCRY_LAB/monitor.sqlite"
```

Require an available source on both calls; inspect stored `source:lab-journal`
configuration using `Store.configuration()` and verify cursor continuity. New
sudo activity may produce additional genuine records; do not demand zero total
new events as a substitute for checking duplicate SSH evidence. Compare SSH raw
cursors and counts across the two calls. Never mix journal and auth-file feeds
in the same evidence database and assume cross-feed deduplication.

## File-source alternative and real negative-access probes

An absent `/var/log/auth.log` is normal on some installations. Do not create a
fake auth.log and claim OS telemetry. If an existing OS-managed file is present,
use a fresh output and the log's actual year/UTC offset:

```bash
if sudo test -f /var/log/auth.log; then
    sudo "$SCRY_PY" "$SCRY_VERIFY" --source linux-auth --path /var/log/auth.log \
        --year "$(date -u +%Y)" --utc-offset=+00:00 --max-records 10000 \
        --lab-generated --output-dir "$SCRY_LAB/auth-file-evidence"
fi
# Missing source: this name must not exist.
test ! -e "$SCRY_LAB/absent-auth.log"
"$SCRY_PY" - "$SCRY_LAB/absent-auth.log" <<'PY'
import sys
from datetime import UTC, datetime
from pathlib import Path
from scry_security.collectors.linux.auth_logs import read_auth_log
r = read_auth_log(Path(sys.argv[1]), year=datetime.now(UTC).year, source_timezone=UTC)
assert r.batch.status.value == 'unavailable' and not r.batch.results
print('Real missing-file handling passed.')
PY
# Restrict a NEW empty probe file, not an existing system log.
sudo install -m 600 -o root -g root /dev/null "$SCRY_LAB/root-only-probe"
"$SCRY_PY" - "$SCRY_LAB/root-only-probe" <<'PY'
import sys
from datetime import UTC, datetime
from pathlib import Path
from scry_security.collectors.linux.auth_logs import read_auth_log
r = read_auth_log(Path(sys.argv[1]), year=datetime.now(UTC).year, source_timezone=UTC)
assert r.batch.status.value == 'permission_denied' and not r.batch.results
print('Real OS permission denial passed; probe contains no telemetry.')
PY
# Without sudo, observe the operator's journal visibility; empty/partial access
# is not proof of full system-auth access and need not return permission_denied.
"$SCRY_PY" "$SCRY_VERIFY" --source linux-journal --max-records 1000 \
    --output-dir "$SCRY_LAB/unprivileged-journal"
```

The last verifier may return 2, degraded status or only user-visible events.
Record the actual result. This negative probe is not a successful full-system
journal test. No existing log permissions/groups are changed.

## Finish and evidence return

```bash
sudo systemctl stop scry-release-sshd
```

Keep evidence local/private. Return only reviewed aggregate summaries, image/OS
and package versions, exact commit, timestamps, exit codes, event-type counts,
raw evidence digest, reopen checks and detection rule IDs. Do not commit account
secrets, keys or raw authentication records. Destroy/revert the disposable VM
through the hypervisor once evidence is retained under your normal policy.
Do not use recursive host deletion commands for cleanup.

A completed Linux gate requires actual observed acquisition, preserved evidence,
targeted lab detections and negative-access results, not successful execution of
synthetic tests alone. Any application fix discovered must be followed by native
retesting and the ordinary regression/CI gates.

References consulted for this prepared procedure:
[Ubuntu OpenSSH guide](https://ubuntu.com/server/docs/how-to/security/openssh-server/),
[OpenSSH sshd_config](https://man.openbsd.org/sshd_config), and
[systemd journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl).
