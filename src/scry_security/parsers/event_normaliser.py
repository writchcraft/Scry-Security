"""Validate canonical records independently, isolating malformed inputs."""

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from scry_security.core.event_schema import SecurityEvent


@dataclass(frozen=True)
class ParseResult:
    event: SecurityEvent | None = None
    error: str | None = None
    skipped: bool = False


def normalise_records(records: Iterable[Mapping[str, Any]]) -> Iterator[ParseResult]:
    """Stream results without storing the batch or echoing invalid raw evidence."""
    for record in records:
        try:
            yield ParseResult(event=SecurityEvent.model_validate(record))
        except ValidationError as exc:
            fields = sorted({".".join(map(str, item["loc"])) for item in exc.errors()})
            yield ParseResult(error=f"Invalid event fields: {', '.join(fields)}")
