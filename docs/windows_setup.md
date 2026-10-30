# Stage 4 — Windows Event Logs

Windows 10/11 are the primary release targets. Native verification currently
covers Windows 11; native Windows 10 remains unverified. See
[the current checklist](release_checklist.md) for exact release-candidate evidence.

Target Windows 10/11 with Python 3.12+. From the repository root, install the
native adapter inside the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,windows]"
.\.venv\Scripts\python.exe -m pytest tests/collectors/windows
```

The `windows` extra installs pywin32 only on Windows. The shared package remains
importable and its synthetic XML tests run on Linux without this dependency.
`defusedxml` rejects DTD/entity XML constructs before external evidence is parsed.

`parse_windows_xml` in `src/scry_security/parsers/windows_parser.py` accepts a
single exported Event XML record. It checks channel and provider, reads named
EventData fields, handles the 1102 UserData envelope, preserves native XML, and
returns the same authentication event types as Linux. An unrelated provider's
numeric event ID is skipped instead of being misclassified.

## Initial coverage and interpretation

| Event | Meaning | Important limitation |
| --- | --- | --- |
| 4624 | Successful logon | Includes service/network logons; inspect LogonType and account context |
| 4625 | Failed logon | Inspect failure codes; absent IPs must stay absent |
| 4634 | Logon session ended | Not necessarily a user-initiated logoff |
| 4648 | Explicit credentials used | An attempt; not proof the target accepted credentials |
| 4672 | Sensitive privileges assigned to a logon | Common for system/admin activity; not proof of escalation |
| 4720 / 4726 / 4738 | Account created / deleted / changed | Authorised administration is common; actor and target differ |
| 4728 / 4732 / 4756 | Member added to global / local / universal security group | Group names can be localised; use SIDs and configured policy |
| 4729 / 4733 | Member removed from a security group | Do not assume every removal is malicious |
| 4740 | Account locked out | Shows lockout, not the full preceding attack history |
| 4719 | Audit policy changed | May be an authorised policy deployment |
| 1102 | Security audit log cleared | Important evidence loss; maintenance can explain it |
| 4697 / System 7045 | Service installed | Software installation commonly creates services |
| 4698 / 4702 | Scheduled task created / updated | Requires context about the task and actor |
| 4688 | Process created | Availability and command-line fields depend on audit policy |
| PowerShell 4104 | Script block telemetry | Requires configured telemetry; a script block alone is not malicious |
| Defender 1116 / 1117 / 5007 | Threat detected / action taken / configuration changed | Provider reports require contextual investigation |

Only events actually configured, generated, retained and accessible can be read.
This project does not change audit policy automatically. PowerShell script text,
process arguments and other raw fields may contain sensitive material; restrict
access and apply retention when storing them.

## Native read-only snapshots

```python
from scry_security.collectors.windows.event_logs import read_event_log

batch = read_event_log("Security", max_records=100)
print(batch.status, batch.message, batch.cursor)
```

Supply `after_record_id=int(batch.cursor)` on subsequent reads of the same
channel. Handles are closed after each bounded query. Checkpoints are channel-local
and must be reconciled if logs are cleared or replaced. The monitoring CLI
persists cursors transactionally with events and alerts. Unrecognised records
still advance the cursor.

Security log access may require explicit delegated access or elevated rights.
Use narrowly assigned Event Log permissions where possible. Run the dashboard
unelevated. A denied source must report `permission_denied`, rather than claiming
that no authentication events occurred. No audit policy or permissions are
changed automatically. See [native verification](native_auth_verification.md)
for generic read-only instructions; operator results remain private.

Check source status, parser errors, skipped records and the bounded query range
separately. An absent event in one snapshot does not establish that auditing is
disabled or that the collector failed. Generated logon tests require explicit
owner approval; never change audit settings or security controls to force a pass.

Missing IP addresses stay absent. Remote authentication rules require a real
source address; the shipped local-interactive rule uses a ten-failure threshold.
A local test below that threshold is not a positive default detection test.
Host-specific lab rules and their test results are retained locally.

References: [Microsoft event querying](https://learn.microsoft.com/en-us/windows/win32/wes/querying-for-events),
[4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624),
[1102](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-1102),
[pywin32 Event Log example](https://github.com/mhammond/pywin32/blob/main/win32/Demos/EvtSubscribe_pull.py).
