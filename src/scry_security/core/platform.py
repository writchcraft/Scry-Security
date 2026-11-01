"""Identify the host without importing operating-system-specific libraries."""

import platform
import socket
from dataclasses import dataclass
from enum import StrEnum


class OperatingSystem(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class PlatformInfo:
    operating_system: OperatingSystem
    hostname: str
    release: str


def detect_platform() -> PlatformInfo:
    """Identify an OS family; this does not establish collector capability or access."""
    operating_system = {
        "Windows": OperatingSystem.WINDOWS,
        "Linux": OperatingSystem.LINUX,
    }.get(platform.system(), OperatingSystem.UNSUPPORTED)
    return PlatformInfo(operating_system, socket.gethostname(), platform.release())
