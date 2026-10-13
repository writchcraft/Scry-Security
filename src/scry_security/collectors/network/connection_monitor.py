"""Best-effort newly observed connection metadata, never inferred packet counts."""

import importlib
import socket
from datetime import UTC, datetime

from pydantic import ValidationError

from scry_security.collectors.base import CollectionBatch, SourceStatus
from scry_security.core.event_schema import SecurityEvent
from scry_security.core.platform import OperatingSystem, detect_platform
from scry_security.parsers.event_normaliser import ParseResult


class ConnectionMonitor:
    """Keep the previous snapshot only; disappearing and reappearing tuples are new observations."""

    def __init__(
        self, *, watched_ports: frozenset[int] = frozenset(), max_connections: int = 10_000
    ):
        if any(not 1 <= port <= 65535 for port in watched_ports):
            raise ValueError("Invalid watched destination port")
        if not 1 <= max_connections <= 100_000:
            raise ValueError("Invalid connection capacity")
        self.watched_ports = watched_ports
        self.max_connections = max_connections
        self._previous: set[tuple] = set()

    def restore_checkpoint(self, connections: list[list]) -> None:
        if len(connections) > self.max_connections or any(
            len(item) != 6 or any(not isinstance(value, (str, int, type(None))) for value in item)
            for item in connections
        ):
            raise ValueError("Invalid connection checkpoint")
        self._previous = {tuple(item) for item in connections}

    def checkpoint(self) -> list[list]:
        return [list(item) for item in self._previous]

    def poll(self) -> CollectionBatch:
        host = detect_platform()
        if host.operating_system == OperatingSystem.UNSUPPORTED:
            return CollectionBatch((), SourceStatus.UNAVAILABLE, "Unsupported network host OS")
        api = importlib.import_module("psutil")
        try:
            connections = api.net_connections(kind="inet")
        except (api.AccessDenied, PermissionError):
            return CollectionBatch(
                (), SourceStatus.PERMISSION_DENIED, "Connection metadata access denied"
            )
        except OSError:
            return CollectionBatch((), SourceStatus.DEGRADED, "Connection metadata query failed")
        if len(connections) > self.max_connections:
            return CollectionBatch((), SourceStatus.DEGRADED, "Connection capacity exceeded")
        current = set()
        results = []
        timestamp = datetime.now(UTC)
        for connection in connections:
            if not connection.raddr or not connection.laddr:
                continue  # listeners and unconnected UDP sockets have no remote endpoint
            local_ip, local_port = connection.laddr
            remote_ip, remote_port = connection.raddr
            protocol = "tcp" if connection.type == socket.SOCK_STREAM else "udp"
            key = (local_ip, local_port, remote_ip, remote_port, protocol, connection.pid)
            current.add(key)
            if key in self._previous:
                continue
            try:
                event = SecurityEvent(
                    timestamp=timestamp,
                    operating_system=host.operating_system,
                    hostname=host.hostname,
                    source_ip=local_ip,
                    destination_ip=remote_ip,
                    category="network",
                    event_type="network_connection",
                    source="psutil-connections",
                    process={"pid": connection.pid} if connection.pid is not None else None,
                    details={
                        "source_port": local_port,
                        "destination_port": remote_port,
                        "protocol": protocol,
                        "status": connection.status,
                        "policy_violation": remote_port in self.watched_ports,
                        "observation": "new_in_snapshot",
                    },
                )
                results.append(ParseResult(event=event))
            except ValidationError:
                results.append(ParseResult(error="Invalid connection metadata"))
        self._previous = current
        return CollectionBatch(
            tuple(results),
            SourceStatus.DEGRADED if any(r.error for r in results) else SourceStatus.AVAILABLE,
            "Best-effort snapshot; permissions may hide connections",
        )
