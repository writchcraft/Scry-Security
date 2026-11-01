"""Bounded, read-only auth-log polling with caller-owned checkpoints."""

from dataclasses import dataclass
from datetime import tzinfo
from pathlib import Path

from scry_security.collectors.base import CollectionBatch, SourceStatus
from scry_security.parsers.event_normaliser import ParseResult
from scry_security.parsers.linux_parser import parse_auth_line


@dataclass(frozen=True)
class FileCursor:
    device: int
    inode: int
    offset: int
    discarding: bool = False


@dataclass(frozen=True)
class FileBatch:
    batch: CollectionBatch
    checkpoint: FileCursor | None


def read_auth_log(
    path: Path,
    *,
    year: int,
    source_timezone: tzinfo,
    checkpoint: FileCursor | None = None,
    max_records: int = 1000,
) -> FileBatch:
    """Read up to max_records chunks; defer incomplete lines until a later poll.

    Rotation or truncation resets to the start. Rename-and-create rotations can
    lose unread bytes in the old file: deployments must poll before rotation or
    ingest archived files explicitly. This is not an exactly-once transport.
    """
    if not 1 <= max_records <= 10_000:
        raise ValueError("max_records must be between 1 and 10000")
    results = []
    try:
        with path.open("rb") as stream:
            import os

            stat = os.fstat(stream.fileno())
            same = (
                checkpoint is not None
                and checkpoint.device == stat.st_dev
                and checkpoint.inode == stat.st_ino
                and checkpoint.offset <= stat.st_size
            )
            offset = checkpoint.offset if same else 0
            discarding = checkpoint.discarding if same else False
            stream.seek(offset)
            for _ in range(max_records):
                start = stream.tell()
                raw = stream.readline(65_537)
                if not raw:
                    break
                complete = raw.endswith(b"\n")
                if discarding:
                    discarding = not complete
                elif len(raw) > 65_536:
                    results.append(ParseResult(error="Linux record exceeds 64 KiB"))
                    discarding = not complete
                elif not complete:
                    stream.seek(start)
                    break
                else:
                    try:
                        line = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        results.append(ParseResult(error="Linux record is not UTF-8"))
                    else:
                        results.append(
                            parse_auth_line(
                                line, year=year, source_timezone=source_timezone, source=str(path)
                            )
                        )
                offset = stream.tell()
            cursor = FileCursor(stat.st_dev, stat.st_ino, offset, discarding)
    except PermissionError:
        return FileBatch(
            CollectionBatch((), SourceStatus.PERMISSION_DENIED, "Log access denied"), checkpoint
        )
    except FileNotFoundError:
        return FileBatch(
            CollectionBatch((), SourceStatus.UNAVAILABLE, "Log file not found"), checkpoint
        )
    except OSError:
        return FileBatch(CollectionBatch((), SourceStatus.DEGRADED, "Log read failed"), checkpoint)
    status = (
        SourceStatus.DEGRADED if any(item.error for item in results) else SourceStatus.AVAILABLE
    )
    return FileBatch(CollectionBatch(tuple(results), status, "Auth log poll complete"), cursor)
