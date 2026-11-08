"""Verification-tool failure contracts; mocks here are not native telemetry evidence."""

import json
import sys
from types import SimpleNamespace

from scripts import verify_native_auth as verifier
from scry_security.collectors.base import CollectionBatch, SourceStatus


def test_recent_record_lookup_handles_non_oserror_pywin32_denial(monkeypatch):
    class NativeError(Exception):
        pass

    def denied(*args):
        raise NativeError(5, "EvtQuery", "Access is denied")

    monkeypatch.setitem(
        sys.modules,
        "win32evtlog",
        SimpleNamespace(
            error=NativeError, EvtQuery=denied, EvtQueryChannelPath=1, EvtQueryReverseDirection=512
        ),
    )
    assert verifier.recent_windows_start(100) == 0


def test_denied_verifier_writes_summary_without_claiming_preservation(monkeypatch, tmp_path):
    output = tmp_path / "new-evidence"
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify_native_auth", "--source", "windows-security", "--output-dir", str(output)],
    )
    monkeypatch.setattr(verifier.platform, "system", lambda: "Windows")
    monkeypatch.setattr(verifier, "recent_windows_start", lambda _: 0)
    monkeypatch.setattr(
        verifier,
        "read_event_log",
        lambda **kwargs: CollectionBatch(
            (), SourceStatus.PERMISSION_DENIED, "Event Log query failed", "0"
        ),
    )
    monkeypatch.setattr(
        verifier.ctypes,
        "windll",
        SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: 0)),
        raising=False,
    )
    assert verifier.main() == 2
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "permission_denied"
    assert summary["authentication_acquired"] is False
    assert summary["positive_detection"] is False
    assert summary["normalisation_matches_raw"] is None
    assert summary["reopened_storage_matches"] is None
    assert (output / "events.jsonl").read_text() == ""
