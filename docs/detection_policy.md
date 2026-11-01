# Explicit host policy and extended detections

The packaged catalogue contains 25 rules. Telemetry-based patterns include
repeated failures, multi-account attempts, success-after-failures, lockouts,
repeated sudo denials, sensitive Windows group/log events and compound PowerShell
indicators. Context-sensitive rules require explicit host policy rather than
treating every administrative action as malicious.

The local-interactive failure rule requires a normalised local logon channel
and ten failures for one host/account. It does not merge missing-IP remote
events into an invented attacker. The watched-outbound rule requires TCP
`SYN_SENT`; established/UDP snapshots do not establish initiation direction.

Edit `examples/detection-policy.toml` using approved local expectations. Each
scope names an exact OS and hostname; there are no wildcard hosts. An omitted
optional approval list means **not assessed**; an explicitly empty list means
**nothing approved for that condition**. No commands or native security changes
are executed by a policy.

```powershell
.\.venv\Scripts\python.exe -m scry_security --replay sample_logs/windows/suspicious/authentication.xml --format windows --synthetic --policy examples/detection-policy.toml --database data/demo.sqlite
.\.venv\Scripts\python.exe -m scry_security --monitor examples/monitor-windows.toml --policy my-policy.toml --database data/scry.sqlite
```

Use `.venv/bin/python` on Linux. A supplied policy becomes the database's current
policy; subsequent database imports/polls reuse it unless another is supplied.
Standalone replay uses only its supplied policy. Its stdout covers the current
batch, while persisted analysis also considers historical context. Policy changes
re-evaluate historical events without reimporting native evidence. Existing
alerts and analyst statuses are preserved rather than automatically rewritten.

## Controls

| Control | Meaning |
| --- | --- |
| `privileged_accounts`, `allowed_admin_sources` | Review privileged remote logons outside approved CIDRs; require a source IP. Windows types 3/10 are selected. |
| `approved_sudo_users` | Review sudo attempts by another invoking account targeting a configured privileged account. |
| `approved_privilege_users` | Review Windows sensitive privilege assignment outside the configured account list. |
| `approved_accounts`, `approved_account_deletions` | Define approved account creation and deletion targets. |
| `protected_accounts`, `approved_account_actors` | Review sensitive account changes unless the observed actor is approved. |
| `privileged_groups`, `approved_group_actors` | Review configured group membership changes; prefer Windows SIDs. |
| `approved_services`, `protected_services` | Review services outside inventory or affecting a protected service. |
| `approved_tasks`, `protected_tasks` | Review task changes outside inventory or affecting a protected task. |
| `approved_change_actors`, `review_security_changes` | Approve known change actors or opt into audit/Defender change review. |
| `watched_processes`, `watched_command_fragments` | Exact executable basenames and literal case-insensitive command fragments; no executable expressions. |
| `watched_destinations` | Review repeated new connection observations to configured CIDRs. |
| `watched_dns_suffixes` | Review three observable queries for configured suffixes, matching case-insensitively on domain boundaries. |
| `review_connection_bursts` | Opt into the catalogue's 100-new-observations/minute rule; tune against expected workload. |

Names are observed strings, not directory lookups. Native Windows domain fields
remain available; resolve account/domain ambiguity during policy review. Unknown
actors are not fabricated or described as confirmed unauthorised users. The
default built-in Administrators rule remains a sensitive-change review lead
independent of optional policy approvals. A custom YAML catalogue can exclude
approved actors explicitly where appropriate.

## Telemetry and platform differences

Windows XML supplies actor, group, service, task and process context where
present. A `MemberName` of `-` no longer hides an available member SID. Command
lines are used only when existing telemetry supplies them; no new command-line
collection mechanism is enabled.

Linux SSH, sudo, user/group tools and selected crontab REPLACE/DELETE messages
feed the same engine. Ordinary cron execution is not a task configuration change.
Journal formats/availability vary. Native Linux auditd/process execution
collection is not implemented; process rules can analyse supplied canonical
historical events without claiming native execution visibility.

Linux service/scheduling files require an approved file-integrity baseline and
explicit `service_unit_directories` or `task_config_directories` in policy.
Changes to `.service`, `.timer`, or selected cron files can then produce review
leads. File changes do not establish installation, daemon reload, activation or
execution. Naming a directory in policy does not start monitoring it.

PowerShell detection requires both Base64 decoding and an IEX/Invoke-Expression
token in one observed script block. It is a compound indicator, not a complete
interpreter: comments, legitimate loaders, split blocks, obfuscation and missing
script logging can affect results.

## Evidence and mappings

The engine recomputes derived `context`; imported flags cannot enable policy
rules. Canonical records keep native evidence without policy assertions. Alerts
carry review reasons and a policy SHA-256 identifier. Applied policies are
archived and retrievable through authenticated `/api/policies/{digest}`.
The dashboard shows policy scope and alert context; report JSON/HTML retain it.

[T1548.003](https://attack.mitre.org/techniques/T1548/003/) relates to observed sudo
elevation attempts, and [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
to the PowerShell indicator. These identify relevant behaviour, not proven intent.
Lockout/network rules make no automatic attack-technique assertion, and a success
after failures does not establish T1078 credential abuse. Tests include suspicious,
benign, missing-context, unconfigured-host and forged-context scenarios.
