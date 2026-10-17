"""Bounded historical replay, useful before persistence and a web interface exist."""

from dataclasses import dataclass
from datetime import tzinfo
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from scry_security.core.event_schema import SecurityEvent
from scry_security.core.platform import OperatingSystem
from scry_security.detection.engine import DetectionEngine, Finding
from scry_security.detection.policy import DetectionPolicy
from scry_security.detection.rules import Rule
from scry_security.parsers.linux_parser import parse_auth_line
from scry_security.parsers.windows_parser import parse_windows_xml


def replay_pcap(
    path: Path,
    *,
    operating_system: OperatingSystem,
    hostname: str,
    rules: list[Rule],
    synthetic: bool = False,
    policy: DetectionPolicy | None = None,
    max_packets: int = 10_000,
) -> "ReplayResult":
    from scry_security.collectors.network.packet_analyser import analyse_pcap

    events = []
    errors = skipped = 0
    for result in analyse_pcap(
        path,
        operating_system=operating_system,
        hostname=hostname,
        synthetic=synthetic,
        max_packets=max_packets,
    ):
        if result.event is not None:
            events.append(result.event)
        errors += bool(result.error)
        skipped += result.skipped
    findings = DetectionEngine(rules, max_events=max_packets, policy=policy).analyse(events)
    return ReplayResult(tuple(events), tuple(findings), errors, skipped)


@dataclass(frozen=True)
class ReplayResult:
    events: tuple[SecurityEvent, ...]
    findings: tuple[Finding, ...]
    errors: int
    skipped: int


def replay_file(
    path: Path,
    *,
    format: Literal["canonical", "linux", "windows"],
    rules: list[Rule],
    synthetic: bool = False,
    year: int | None = None,
    source_timezone: tzinfo | None = None,
    policy: DetectionPolicy | None = None,
) -> ReplayResult:
    """Canonical JSONL, Linux lines, or one Windows XML record per line.

    Explicit synthetic=True labels the import. Canonical inputs already labelled
    synthetic retain that label, even when the caller does not override it.
    """
    events = []
    errors = skipped = 0
    records = 0
    with path.open("rb") as stream:
        while raw := stream.readline(1_048_577):
            records += 1
            if records > 10_000 or len(raw) > 1_048_576:
                raise ValueError("Replay input exceeds record count or line size limit")
            if not raw.strip():
                continue
            try:
                line = raw.decode("utf-8")
                if format == "canonical":
                    event = SecurityEvent.model_validate_json(line)
                    if synthetic and not event.synthetic:
                        event = event.model_copy(update={"synthetic": True})
                    events.append(event)
                    continue
                if format == "linux":
                    result = parse_auth_line(
                        line,
                        year=year,
                        source_timezone=source_timezone,
                        source=str(path),
                        synthetic=synthetic,
                    )
                elif format == "windows":
                    result = parse_windows_xml(line, synthetic=synthetic)
                else:
                    raise ValueError("Unknown replay format")
                if result.event is not None:
                    events.append(result.event)
                errors += bool(result.error)
                skipped += result.skipped
            except (UnicodeDecodeError, ValidationError):
                errors += 1
    findings = DetectionEngine(rules, policy=policy).analyse(events)
    return ReplayResult(tuple(events), tuple(findings), errors, skipped)
