"""Real-file hash baselines, benign stability, change evidence and bounded failure."""

import os
from unittest.mock import MagicMock

import pytest

from scry_security.integrity.monitor import (
    ScanError,
    ScanLimits,
    compare_baseline,
    create_baseline,
    load_baseline,
)
from scry_security.main import main


def approved(paths, **kwargs):
    return create_baseline(
        paths, approved_by="Lab analyst", approval_note="Known synthetic content", **kwargs
    )


def test_file_creation_modification_deletion_and_stable_baseline(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    existing = watched / "existing.txt"
    deleted = watched / "deleted.txt"
    existing.write_text("before")
    deleted.write_text("remove")
    baseline = approved([watched], synthetic=True)
    original_hash = baseline.entries[str(existing)].sha256
    assert compare_baseline(baseline).events == []
    existing.write_text("after")
    deleted.unlink()
    (watched / "new.txt").write_text("created")
    scan = compare_baseline(baseline)
    assert scan.errors == []
    assert {event.event_type for event in scan.events} == {
        "file_created",
        "file_modified",
        "file_deleted",
    }
    modified = next(event for event in scan.events if event.event_type == "file_modified")
    assert modified.details["previous_sha256"] == original_hash
    assert modified.details["current_sha256"] != original_hash
    assert baseline.entries[str(existing)].sha256 == original_hash  # never auto-accept
    assert all(event.synthetic for event in scan.events)
    assert all(not event.raw for event in scan.events)  # file content is never evidence


def test_limits_access_failure_and_missing_path(tmp_path, monkeypatch):
    path = tmp_path / "file.txt"
    path.write_bytes(b"12345")
    with pytest.raises(ScanError):
        approved([path], limits=ScanLimits(max_file_bytes=4))
    with pytest.raises(ScanError):
        approved([tmp_path / "missing"])
    baseline = approved([path])
    monkeypatch.setattr(
        "scry_security.integrity.monitor._hash_file", MagicMock(side_effect=PermissionError)
    )
    scan = compare_baseline(baseline)
    assert scan.errors
    assert scan.events == []  # denied access must not become an invented deletion


def test_single_file_deleted_and_json_roundtrip(tmp_path):
    path = tmp_path / "file.txt"
    path.write_text("original")
    baseline = approved([path])
    saved = tmp_path / "baseline.json"
    saved.write_text(baseline.model_dump_json())
    assert load_baseline(saved) == baseline
    path.unlink()
    assert compare_baseline(baseline).events[0].event_type == "file_deleted"


def test_changed_host_rejected(tmp_path):
    path = tmp_path / "file.txt"
    path.write_text("original")
    baseline = approved([path]).model_copy(update={"hostname": "different-host"})
    with pytest.raises(ValueError, match="different host"):
        compare_baseline(baseline)


@pytest.mark.skipif(os.name == "nt", reason="Creating Windows symlinks needs separate local policy")
def test_symlink_is_not_followed(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("private")
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "link").symlink_to(outside)
    with pytest.raises(ScanError):
        approved([watched])


def test_cli_requires_approval_and_never_overwrites_baseline(tmp_path, capsys):
    path = tmp_path / "file.txt"
    path.write_text("test")
    output = tmp_path / "baseline.json"
    assert main(["--fim-baseline", str(output), "--watch", str(path)]) == 2
    assert not output.exists()
    args = [
        "--fim-baseline",
        str(output),
        "--watch",
        str(path),
        "--approved-by",
        "Lab analyst",
        "--approval-note",
        "Known state",
        "--synthetic",
    ]
    assert main(args) == 0
    assert main(args) == 2
    assert main(["--fim-check", str(output)]) == 0
    assert '"events": []' in capsys.readouterr().out
