# Troubleshooting

| Symptom | Check and next step |
| --- | --- |
| `python` missing or too old | Install/select Python 3.12+ and verify `python --version` or `python3 --version`. |
| `venv` unavailable on Linux | Install the matching venv support package for your approved interpreter; distribution defaults vary. |
| Module/command not found | Use the project's virtual-environment Python and install `-e '.[dev]'` from the repository root. |
| pip DNS/network error | Verify the approved package index and network access; do not disable TLS verification. |
| Config validation failure | Check exact documented names, types, bounds and uppercase log levels. `.env` is not automatically loaded. |
| Windows Event Log denied | The current account lacks channel access. Have the administrator review narrow read permissions or use synthetic/exported XML; do not elevate the dashboard. |
| No Windows events | Inspect source health, auditing, channel/provider, retention and checkpoint state. Empty results do not prove auditing is enabled. |
| Linux auth file missing | Some systems use journal-only logging. Choose an available source explicitly. |
| Journal shows only user events | Native access can be partial even on command success; verify appropriate log-reading policy. |
| Legacy syslog fails parsing | Supply the correct year and UTC offset. Resolve rollover/DST context explicitly. |
| Duplicate authentication findings | Avoid ingesting the same host's auth.log and journal feed without deduplication. Use committed source checkpoints for polling. |
| Network counts seem low | Snapshot polling misses short-lived connections, and permissions can omit records. Encrypted DNS is not inferred. |
| Scapy warns that libpcap/Npcap is absent | Offline PCAP parsing can still work; live capture is not implemented or required. |
| PCAP exits 2 after partial results | Check malformed records and `--max-packets`; a reached budget is reported, not silently called complete. |
| Policy produces no findings | Match exact OS/hostname, observed account/group strings, required telemetry and configured optional lists. Missing IP/actor fields are not invented. |
| Legitimate administration triggers a review lead | Verify authorisation, tune approved actors/inventory or YAML exclusions, and retain benign tests. |
| Database is rejected | Choose a new or Scry-owned SQLite file. The app refuses to initialise unrelated nonempty databases. |
| Database write/lock failure | Check private-directory permissions, disk capacity and concurrent writers; committed source cursors are preserved. |
| Status save returns 409 | Another update changed the alert. Reopen it to see the new revision before applying your note. |
| File comparison reports incomplete | Check access, links/junctions, active file changes and file/byte limits. No deletion conclusion is emitted for an incomplete scan. |
| Demo seed refuses to run | It preserves existing databases and lab directories. Choose a new `--database` path; do not delete real evidence to reset a demo. |
| Tests hang before API startup in a restricted Windows shell | Asyncio may be blocked creating its internal socketpair. Run tests in an approved environment with loopback access; do not disable application auth. |

Share minimal synthetic reproductions and version/command information when
reporting a bug. Review output for hostnames, paths and evidence before sharing.
Never post API tokens, credentials or real security logs in a public issue.
