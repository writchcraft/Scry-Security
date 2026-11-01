"""Explicit collector orchestration with transactionally saved source checkpoints."""

import hashlib
import json
import tomllib
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from scry_security.collectors.base import CollectionBatch, SourceStatus
from scry_security.collectors.linux.auth_logs import FileCursor, read_auth_log
from scry_security.collectors.linux.journal import read_journal
from scry_security.collectors.network.connection_monitor import ConnectionMonitor
from scry_security.collectors.windows.event_logs import CHANNELS, read_event_log
from scry_security.core.platform import OperatingSystem, detect_platform
from scry_security.database.repositories import Store
from scry_security.detection.policy import DetectionPolicy
from scry_security.detection.rules import Rule

Port = Annotated[int, Field(ge=1, le=65535)]


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,59}$")
    kind: Literal["linux_auth", "linux_journal", "windows_eventlog", "connections"]
    enabled: bool = True
    path: Path | None = None
    year: int | None = Field(default=None, ge=1970, le=2100)
    utc_offset: str = "+00:00"
    channel: str = "Security"
    max_records: int = Field(default=1000, ge=1, le=10_000)
    watched_ports: list[Port] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_source(self) -> "SourceConfig":
        if self.kind == "linux_auth" and (self.path is None or self.year is None):
            raise ValueError("Auth logs require a path and explicit syslog year")
        timestamp = datetime.fromisoformat(f"2000-01-01T00:00:00{self.utc_offset}")
        if timestamp.tzinfo is None:
            raise ValueError("Source timezone requires an offset")
        if self.kind == "windows_eventlog" and self.channel not in CHANNELS:
            raise ValueError("Unsupported Event Log channel")
        return self


class MonitorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    poll_seconds: float = Field(default=5, ge=2, le=3600)
    synthetic: bool = False
    sources: list[SourceConfig] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def unique_sources(self) -> "MonitorConfig":
        if len({source.source_id for source in self.sources}) != len(self.sources):
            raise ValueError("Source IDs must be unique")
        if not any(source.enabled for source in self.sources):
            raise ValueError("Enable at least one explicit source")
        return self


def load_monitor_config(path: Path) -> MonitorConfig:
    with path.open("rb") as stream:
        raw = stream.read(65_537)
    if len(raw) > 65_536:
        raise ValueError("Monitor config exceeds 64 KiB")
    data = tomllib.loads(raw.decode("utf-8"))
    # Relative sources resolve against the configuration file, never the caller's cwd.
    config = MonitorConfig.model_validate(data)
    sources = [
        source.model_copy(update={"path": (path.parent / source.path).resolve()})
        if source.path is not None and not source.path.is_absolute()
        else source
        for source in config.sources
    ]
    return config.model_copy(update={"sources": sources})


class CollectorRuntime:
    def collect_once(
        self,
        config: MonitorConfig,
        store: Store,
        rules: list[Rule],
        *,
        policy: DetectionPolicy | None = None,
    ) -> dict:
        operating_system = detect_platform().operating_system
        events = []
        updates = {}
        health_records = []
        for source in config.sources:
            if not source.enabled:
                continue
            definition = hashlib.sha256(
                json.dumps(
                    {"config": source.model_dump(mode="json"), "synthetic": config.synthetic},
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            key = f"source:{source.source_id}"
            previous = store.configuration(key) or {}
            cursor = previous.get("cursor", {}) if previous.get("definition") == definition else {}
            next_cursor = cursor
            expected = {
                "linux_auth": OperatingSystem.LINUX,
                "linux_journal": OperatingSystem.LINUX,
                "windows_eventlog": OperatingSystem.WINDOWS,
            }.get(source.kind)
            try:
                if expected is not None and operating_system != expected:
                    batch = CollectionBatch(
                        (), SourceStatus.UNAVAILABLE, "Source is not supported on this host OS"
                    )
                elif source.kind == "linux_auth":
                    checkpoint = FileCursor(**cursor) if cursor else None
                    timezone = datetime.fromisoformat(
                        f"2000-01-01T00:00:00{source.utc_offset}"
                    ).tzinfo
                    result = read_auth_log(
                        source.path,
                        year=source.year,
                        source_timezone=timezone,
                        checkpoint=checkpoint,
                        max_records=source.max_records,
                    )
                    batch = result.batch
                    next_cursor = asdict(result.checkpoint) if result.checkpoint else cursor
                elif source.kind == "linux_journal":
                    batch = read_journal(cursor=cursor.get("value"), max_records=source.max_records)
                    next_cursor = {"value": batch.cursor} if batch.cursor else cursor
                elif source.kind == "windows_eventlog":
                    batch = read_event_log(
                        source.channel,
                        after_record_id=int(cursor.get("record_id", 0)),
                        max_records=source.max_records,
                    )
                    next_cursor = {"record_id": int(batch.cursor)} if batch.cursor else cursor
                else:
                    monitor = ConnectionMonitor(
                        watched_ports=frozenset(source.watched_ports),
                        max_connections=source.max_records,
                    )
                    monitor.restore_checkpoint(cursor.get("connections", []))
                    batch = monitor.poll()
                    next_cursor = {"connections": monitor.checkpoint()}
            except (OSError, ValueError, TypeError, KeyError):
                batch = CollectionBatch(
                    (), SourceStatus.DEGRADED, "Collector failed; checkpoint unchanged"
                )
                next_cursor = cursor
            collected = [result.event for result in batch.results if result.event is not None]
            if config.synthetic:
                collected = [event.model_copy(update={"synthetic": True}) for event in collected]
            events.extend(collected)
            health = {
                "source_id": source.source_id,
                "kind": source.kind,
                "status": batch.status.value,
                "message": batch.message,
                "last_checked": datetime.now(UTC).isoformat(),
                "stale_after_seconds": max(30, config.poll_seconds * 3),
                "events": len(collected),
                "errors": sum(bool(result.error) for result in batch.results),
                "skipped": sum(result.skipped for result in batch.results),
            }
            updates[key] = {"definition": definition, "cursor": next_cursor, "health": health}
            health_records.append(health)
        # Cursor movement commits only if all canonical events and alerts commit.
        result = store.ingest(events, rules, checkpoint_updates=updates, policy=policy)
        return {**result, "sources": health_records}
