"""Explicit source health; zero events is not proof that a source is healthy."""

from dataclasses import dataclass
from enum import StrEnum

from scry_security.parsers.event_normaliser import ParseResult


class SourceStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission_denied"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class CollectionBatch:
    results: tuple[ParseResult, ...]
    status: SourceStatus
    message: str
    cursor: str | None = None
