"""Shared, versioned evidence contract consumed by every detection."""

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, JsonValue, field_validator

from scry_security.core.platform import OperatingSystem

NonEmpty = Annotated[str, Field(min_length=1, max_length=1024)]


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    ACCOUNT = "account"
    PRIVILEGE = "privilege"
    SYSTEM = "system"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ProcessInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int | None = Field(default=None, ge=0)
    name: NonEmpty | None = None
    executable: NonEmpty | None = None
    # Command lines can contain secrets; collectors omit them by default.
    command_line: str | None = Field(default=None, max_length=8192)


class SecurityEvent(BaseModel):
    """UTC event with optional telemetry and separately retained native evidence.

    event_id identifies this ingestion, not a deduplication key. Native record
    identifiers belong in native_record_id and require source-specific cursors.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    operating_system: OperatingSystem
    hostname: NonEmpty
    username: NonEmpty | None = None
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    category: EventCategory
    event_type: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,79}$")]
    outcome: EventOutcome = EventOutcome.UNKNOWN
    process: ProcessInfo | None = None
    source: NonEmpty
    native_event_id: NonEmpty | None = None
    native_record_id: NonEmpty | None = None
    raw: dict[str, JsonValue] = Field(default_factory=dict)
    details: dict[str, JsonValue] = Field(default_factory=dict)
    # Detection-derived values are recomputed, never trusted from imported input.
    context: dict[str, JsonValue] = Field(default_factory=dict)
    synthetic: bool = False

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone-aware timestamp required; supply source timezone explicitly")
        return value.astimezone(UTC)

    @field_validator("operating_system")
    @classmethod
    def supported_os(cls, value: OperatingSystem) -> OperatingSystem:
        if value == OperatingSystem.UNSUPPORTED:
            raise ValueError("events require a supported source operating system")
        return value

    @field_validator("raw", "details", "context")
    @classmethod
    def bounded_evidence(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode("utf-8")) > 262_144:
            raise ValueError("evidence field exceeds 256 KiB")
        return value
