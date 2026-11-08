# Windows-first v1.0.0 release checklist

**Recommendation: NO-GO for final v1.0.0; continue as 1.0.0rc1.** Windows 10/11
are primary targets. Native Windows 10 qualification and native positive coverage
of shipped authentication thresholds remain open. Linux native authentication is
experimental and is not a Windows-first release blocker. No Ubuntu VM is required.

## Privacy and evidence

Native-host test results, raw logs, databases, audit inventories, collection
cursors, evidence hashes and host configuration details remain local. They are
excluded from version control and distribution archives. Native lab scripts and
their dedicated tests are also retained locally. Public CI checks use synthetic
fixtures and ordinary disposable test data, not operator event logs.

Only repository CI outcomes and product-level qualification status belong in this
public checklist. Detailed native verification evidence is reviewed privately.
Removing files from the current tree does not remove copies from older Git history.

## Feature qualification

| Feature | Classification | Scope and limitations |
| --- | --- | --- |
| Windows Security/System acquisition | Verified privately on native Windows 11 | Read-only acquisition, genuine 4624/4625/4672 handling and source health; private evidence retained locally |
| Persistence, deduplication and restart checkpoints | Verified privately on native Windows 11 | Raw preservation, repeat collection, reversed ingestion and durable checkpoints |
| Configured local detection and investigations | Verified privately on native Windows 11 | Explicit lab rules; does not qualify every shipped rule against native telemetry |
| Shipped remote correlation and local threshold | Verified through automated tests only | Remote rules require a real source IP; the default local threshold is ten failures |
| Full rule catalogue and false-positive controls | Verified through automated tests only | Synthetic positive/negative, policy, missing-IP and boundary scenarios |
| Clean wheel, CLI, dashboard API and exports | Verified privately on native Windows 11 | Unelevated application, authentication, persistence, JSON/CSV/HTML; public clean-wheel CI additionally runs on both operating systems |
| File integrity | Verified privately on native Windows 11 | Disposable files only; Windows symlink policy case remains unverified |
| Offline packet analysis | Verified on Windows with synthetic captures | No live capture or driver qualification |
| Malformed and unavailable sources | Native Windows checks plus automated tests | Source denial is distinct from an empty available source |
| Other Windows event families | Verified through automated tests only | No forced log clearing, protection changes or destructive scenarios |
| Linux auth files and journal | Experimental on Linux | Existing Ubuntu runtime/parser/mock CI retained; genuine native authentication acquisition unverified |
| Windows 10 | Not yet verified | Primary target; native qualification remains open |
| Remote deployment, live capture and endurance | Outside current qualification | Local single-user tool; no lossless or long-duration guarantee |

## Candidate gates

- [x] Windows-first documentation and explicit feature classifications.
- [x] Private native Windows 11 acquisition, preservation, source-health and application review.
- [x] Private Windows wheel installation and bounded application checks.
- [x] Keep Windows/Ubuntu Python 3.12/3.13 tests and dependency auditing intact.
- [x] Add a clean built-wheel installation check to every matrix job.
- [x] Verify the privacy-sanitised implementation candidate in GitHub Actions.
- [ ] Native Windows 10 qualification, or owner-approved narrower support scope.
- [ ] Native shipped-rule positive qualification, or explicit acceptance of automated-only qualification.
- [ ] Final 1.0.0 metadata/artifacts and renewed checks after final changes.
- [ ] Explicit owner approval to merge, tag and publish.

## Public CI evidence

Repository history was rewritten to remove private metadata. Older commit IDs
and CI run links have been retired; prior local verification records remain
private. Clean-history CI is tracked in [GitHub Actions](https://github.com/writchcraft/Scry-Security/actions).
The source code, existing tests and workflow matrix are unchanged by the rewrite.
CI artifacts contain synthetic-test and runner data only; private host evidence
is not uploaded or packaged.

## Known limitations

Bearer access is local and single-user, with no server-side session registry,
idle timeout, MFA or per-user permissions. Lock clears the browser token without
revoking a copied token; rotate the secret and restart to revoke access. SQLite
inherits Windows ACLs and is unencrypted and not tamper-proof. Replay is bounded
at 100,000 stored events. Log clearing/record-ID reset, rotation, retention and
partial visibility require operator reconciliation. FIM is not atomic or
race-proof forensic acquisition. There is no lossless collection, throughput or
endurance qualification, dependency lockfile or remote service security claim.
Package advisory checks are dated known-vulnerability lookups; unpublished Scry
source is reviewed and tested separately.

Linux functionality and automated tests remain intact. No Ubuntu-native
authentication success is claimed, and Linux native verification is deferred.
