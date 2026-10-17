"""Bounded SHA-256 scanning; file contents never enter events or baselines."""

import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scry_security.core.event_schema import SecurityEvent
from scry_security.core.platform import OperatingSystem, detect_platform


class FileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    mtime_ns: int


class ScanLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_files: int = Field(default=10_000, ge=1, le=100_000)
    max_file_bytes: int = Field(default=67_108_864, ge=1, le=1_073_741_824)
    max_total_bytes: int = Field(default=536_870_912, ge=1, le=10_737_418_240)


class FileBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    schema_version: Literal[1] = 1
    baseline_id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    operating_system: OperatingSystem
    hostname: str = Field(min_length=1, max_length=1024)
    roots: dict[str, Literal["file", "directory"]] = Field(min_length=1, max_length=100)
    entries: dict[str, FileEntry] = Field(max_length=100_000)
    approved_by: str = Field(min_length=1, max_length=200)
    approval_note: str = Field(min_length=1, max_length=4000)
    limits: ScanLimits = Field(default_factory=ScanLimits)
    synthetic: bool = False

    @field_validator("created_at")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Baseline time requires a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_scope(self) -> "FileBaseline":
        if self.operating_system == OperatingSystem.UNSUPPORTED:
            raise ValueError("Baseline source OS must be supported")
        if len(self.entries) > self.limits.max_files:
            raise ValueError("Baseline exceeds its configured file limit")
        roots = [(Path(name), kind) for name, kind in self.roots.items()]
        if any(not path.is_absolute() or ".." in path.parts for path, _ in roots):
            raise ValueError("Baseline roots must be absolute normalised paths")
        for name in self.entries:
            path = Path(name)
            if (
                not path.is_absolute()
                or ".." in path.parts
                or not any(
                    path == root if kind == "file" else path.is_relative_to(root)
                    for root, kind in roots
                )
            ):
                raise ValueError("Baseline entry is outside the approved scope")
        return self


class IntegrityScan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scan_id: UUID = Field(default_factory=uuid4)
    baseline_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    events: list[SecurityEvent] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    files_checked: int = 0
    synthetic: bool


class ScanError(ValueError):
    pass


def _unsafe_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _hash_file(path: Path, limits: ScanLimits, remaining: int) -> FileEntry:
    if _unsafe_link(path):
        raise ScanError("Symbolic links and junctions are not monitored")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ScanError("Only regular files can be hashed")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        named = path.lstat()
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (
            named.st_dev,
            named.st_ino,
        ):
            raise ScanError("File is not a stable regular file")
        if before.st_size > min(limits.max_file_bytes, remaining):
            raise ScanError("File or total byte limit exceeded")
        digest = hashlib.sha256()
        read = 0
        while chunk := stream.read(65_536):
            read += len(chunk)
            if read > min(limits.max_file_bytes, remaining):
                raise ScanError("File grew beyond scan byte limit")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        named_after = path.lstat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ino,
        ) or (named_after.st_dev, named_after.st_ino) != (before.st_dev, before.st_ino):
            raise ScanError("File changed during hashing; retry the comparison")
        return FileEntry(sha256=digest.hexdigest(), size=read, mtime_ns=after.st_mtime_ns)


def scan_paths(
    roots: dict[str, str], limits: ScanLimits, *, allow_missing: bool
) -> dict[str, FileEntry]:
    entries = {}
    total = 0

    def visit_file(path: Path) -> None:
        nonlocal total
        key = str(path)
        if key in entries:
            return
        if len(entries) >= limits.max_files:
            raise ScanError("File count limit exceeded")
        entry = _hash_file(path, limits, limits.max_total_bytes - total)
        entries[key] = entry
        total += entry.size

    for name, kind in roots.items():
        root = Path(name)
        if not root.is_absolute() or any(_unsafe_link(part) for part in (root, *root.parents)):
            raise ScanError("Roots must be absolute paths without links or junctions")
        try:
            info = root.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise ScanError("A configured baseline root does not exist") from None
        if kind == "file":
            visit_file(root)
        else:
            if not stat.S_ISDIR(info.st_mode):
                raise ScanError("Configured directory was replaced by another file type")

            def traversal_error(error: OSError) -> None:
                raise ScanError("A configured directory cannot be read") from error

            directory_count = 0
            for folder, directories, filenames in os.walk(
                root, followlinks=False, onerror=traversal_error
            ):
                directory_count += 1
                if directory_count > limits.max_files:
                    raise ScanError("Directory count limit exceeded")
                folder_path = Path(folder)
                if _unsafe_link(folder_path):
                    raise ScanError("Directory changed into a link during traversal")
                if any(_unsafe_link(folder_path / child) for child in directories):
                    raise ScanError("Directory contains a symbolic link or junction")
                for filename in sorted(filenames):
                    visit_file(folder_path / filename)
    return entries


def create_baseline(
    paths: list[Path],
    *,
    approved_by: str,
    approval_note: str,
    limits: ScanLimits | None = None,
    synthetic: bool = False,
) -> FileBaseline:
    if not 1 <= len(paths) <= 100:
        raise ValueError("Select between 1 and 100 explicit paths")
    host = detect_platform()
    if host.operating_system == OperatingSystem.UNSUPPORTED:
        raise ValueError("Unsupported file integrity host")
    roots = {}
    for path in paths:
        absolute = Path(os.path.abspath(path.expanduser()))
        roots[str(absolute)] = "directory" if absolute.is_dir() else "file"
    selected_limits = limits or ScanLimits()
    entries = scan_paths(roots, selected_limits, allow_missing=False)
    return FileBaseline(
        operating_system=host.operating_system,
        hostname=host.hostname,
        roots=roots,
        entries=entries,
        approved_by=approved_by,
        approval_note=approval_note,
        limits=selected_limits,
        synthetic=synthetic,
    )


def compare_baseline(baseline: FileBaseline) -> IntegrityScan:
    host = detect_platform()
    if (host.operating_system, host.hostname) != (baseline.operating_system, baseline.hostname):
        raise ValueError("Baseline belongs to a different host or operating system")
    result = IntegrityScan(baseline_id=baseline.baseline_id, synthetic=baseline.synthetic)
    try:
        current = scan_paths(baseline.roots, baseline.limits, allow_missing=True)
    except (OSError, ScanError):
        return result.model_copy(
            update={
                "errors": [
                    "Comparison incomplete: access, file stability or scan limits failed. "
                    "No deletion conclusions were generated."
                ]
            }
        )
    events = []
    for path in sorted(set(current) | set(baseline.entries)):
        before, after = baseline.entries.get(path), current.get(path)
        if before is None:
            event_type = "file_created"
        elif after is None:
            event_type = "file_deleted"
        elif before.sha256 != after.sha256:
            event_type = "file_modified"
        else:
            continue
        events.append(
            SecurityEvent(
                timestamp=result.timestamp,
                operating_system=host.operating_system,
                hostname=host.hostname,
                category="file",
                event_type=event_type,
                outcome="success",
                source="file-integrity",
                native_record_id=f"{result.scan_id}:{hashlib.sha256(path.encode()).hexdigest()}",
                synthetic=baseline.synthetic,
                details={
                    "path": path,
                    "baseline_id": str(baseline.baseline_id),
                    "previous_sha256": before.sha256 if before else None,
                    "current_sha256": after.sha256 if after else None,
                    "previous_size": before.size if before else None,
                    "current_size": after.size if after else None,
                },
            )
        )
    return result.model_copy(update={"events": events, "files_checked": len(current)})


def load_baseline(path: Path) -> FileBaseline:
    with path.open("rb") as stream:
        raw = stream.read(8_388_609)
    if len(raw) > 8_388_608:
        raise ValueError("Baseline exceeds 8 MiB")
    return FileBaseline.model_validate_json(raw)
