# Verification

Scry-Security uses a Windows-first qualification strategy. Windows 10/11 are
primary targets; Linux functionality remains experimental. Native Linux
authentication acquisition is unverified and requires no Ubuntu VM for this release.
See the [release checklist](release_checklist.md) for product status and public CI.

## Public automated checks

GitHub Actions retains Windows and Ubuntu on Python 3.12/3.13. Each matrix job runs
Ruff, formatting, pytest with coverage, CLI diagnostics, wheel construction and a
clean wheel installation outside the source tree. A separate job audits package
advisories. Fixtures and disposable files are synthetic test inputs; green CI
is not proof of native authentication-source acquisition.

## Private native checks

Native Windows verification covers read-only source acquisition, supported
authentication records, normalisation, persistence, detection, repeat collection,
checkpoint restart, event ordering and denied-access behaviour. Application
qualification also checks clean installation, local API access, saved
investigations, exports, disposable file monitoring and offline sample captures.
Detailed results, host metadata, native lab tools and operational evidence remain
local and are excluded from repository commits and distribution archives.

Generated logon attempts require explicit owner approval. No audit policy, log
permissions, firewall settings or security protections are changed implicitly.
An unavailable or denied source, parser failure and absent event are distinct
outcomes. Synthetic results must never be relabelled as native evidence.
