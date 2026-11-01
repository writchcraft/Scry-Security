"""Collector-to-database flow and checkpoint safety across process restarts."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from scry_security.core.platform import OperatingSystem
from scry_security.database.database import Database
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.services.monitoring import (
    CollectorRuntime,
    MonitorConfig,
    SourceConfig,
    load_monitor_config,
)


def line(index, success=False):
    action = "Accepted" if success else "Failed"
    return (
        f"2026-10-31T10:30:0{index}Z lab sshd[42]: {action} password for alice "
        "from 192.0.2.10 port 51000 ssh2\n"
    )


def test_incremental_collection_restart_and_bad_record_health(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "scry_security.services.monitoring.detect_platform",
        lambda: SimpleNamespace(operating_system=OperatingSystem.LINUX),
    )
    path = tmp_path / "auth.txt"
    path.write_text(line(0) + line(1))
    config = MonitorConfig(
        synthetic=True,
        sources=[SourceConfig(source_id="lab-auth", kind="linux_auth", path=path, year=2026)],
    )
    database = Database(tmp_path / "monitor.sqlite")
    store = Store(database)
    try:
        first = CollectorRuntime().collect_once(config, store, load_rules())
        assert first["added_events"] == 2
        assert first["added_alerts"] == 0
        with path.open("a") as output:
            output.write(line(2) + line(3) + line(4) + line(5, success=True))
        second = CollectorRuntime().collect_once(config, store, load_rules())
        assert second["added_events"] == 4
        assert second["added_alerts"] == 2
        assert store.source_health()[0]["status"] == "available"
        assert CollectorRuntime().collect_once(config, store, load_rules())["added_events"] == 0
        with path.open("a") as output:
            output.write("malformed source record\n")
        bad = CollectorRuntime().collect_once(config, store, load_rules())
        assert bad["sources"][0]["errors"] == 1
        assert store.source_health()[0]["status"] == "degraded"
        assert (
            CollectorRuntime().collect_once(config, store, load_rules())["sources"][0]["status"]
            == "available"
        )
    finally:
        database.close()


def test_failed_ingestion_does_not_commit_source_cursor(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "scry_security.services.monitoring.detect_platform",
        lambda: SimpleNamespace(operating_system=OperatingSystem.LINUX),
    )
    path = tmp_path / "auth.txt"
    path.write_text(line(0))
    config = MonitorConfig(
        synthetic=True,
        sources=[SourceConfig(source_id="lab-auth", kind="linux_auth", path=path, year=2026)],
    )
    database = Database(tmp_path / "monitor.sqlite")
    store = Store(database)
    original = store.ingest
    try:
        monkeypatch.setattr(
            store, "ingest", MagicMock(side_effect=ValueError("Simulated ingestion failure"))
        )
        with pytest.raises(ValueError):
            CollectorRuntime().collect_once(config, store, load_rules())
        assert store.configuration("source:lab-auth") is None
        monkeypatch.setattr(store, "ingest", original)
        assert CollectorRuntime().collect_once(config, store, load_rules())["added_events"] == 1
    finally:
        database.close()


def test_config_resolution_and_unsupported_source_health(tmp_path, monkeypatch):
    path = tmp_path / "monitor.toml"
    path.write_text(
        '[[sources]]\nsource_id="auth"\nkind="linux_auth"\npath="auth.txt"\nyear=2026\n'
    )
    assert load_monitor_config(path).sources[0].path == tmp_path / "auth.txt"
    monkeypatch.setattr(
        "scry_security.services.monitoring.detect_platform",
        lambda: SimpleNamespace(operating_system=OperatingSystem.LINUX),
    )
    config = MonitorConfig(
        sources=[SourceConfig(source_id="windows-security", kind="windows_eventlog")]
    )
    database = Database(tmp_path / "monitor.sqlite")
    try:
        result = CollectorRuntime().collect_once(config, Store(database), load_rules())
        assert result["sources"][0]["status"] == "unavailable"
        assert result["added_events"] == 0
    finally:
        database.close()
