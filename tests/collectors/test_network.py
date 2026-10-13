"""Snapshot deduplication, explicit network policy, and optional PCAP analysis."""

import socket
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from scry_security.collectors.base import SourceStatus
from scry_security.collectors.network.connection_monitor import ConnectionMonitor
from scry_security.collectors.network.packet_analyser import analyse_pcap
from scry_security.core.platform import OperatingSystem, PlatformInfo


def connection(port=443, local_port=51000):
    return SimpleNamespace(
        laddr=("192.0.2.1", local_port),
        raddr=("198.51.100.1", port),
        type=socket.SOCK_STREAM,
        pid=42,
        status="ESTABLISHED",
    )


@pytest.mark.parametrize("os_name", [OperatingSystem.WINDOWS, OperatingSystem.LINUX])
def test_snapshot_policy_and_duplicate_observations(monkeypatch, os_name):
    api = MagicMock()
    api.net_connections.return_value = [connection(), connection(4444, 51001)]
    api.AccessDenied = PermissionError
    monkeypatch.setattr(
        "scry_security.collectors.network.connection_monitor.importlib.import_module", lambda _: api
    )
    monkeypatch.setattr(
        "scry_security.collectors.network.connection_monitor.detect_platform",
        lambda: PlatformInfo(os_name, "lab", "test"),
    )
    monitor = ConnectionMonitor(watched_ports=frozenset({4444}))
    first = monitor.poll()
    assert first.status == SourceStatus.AVAILABLE
    assert len(first.results) == 2
    assert first.results[0].event.details["policy_violation"] is False
    assert first.results[1].event.details["policy_violation"] is True
    assert monitor.poll().results == ()
    api.net_connections.side_effect = PermissionError
    assert monitor.poll().status == SourceStatus.PERMISSION_DENIED


def test_no_watched_ports_by_default(monkeypatch):
    api = MagicMock()
    api.AccessDenied = PermissionError
    api.net_connections.return_value = [connection(4444)]
    monkeypatch.setattr(
        "scry_security.collectors.network.connection_monitor.importlib.import_module", lambda _: api
    )
    assert ConnectionMonitor().poll().results[0].event.details["policy_violation"] is False


def test_offline_dns_and_tcp_metadata(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    path = tmp_path / "synthetic.pcap"
    packets = [
        scapy.IP(src="192.0.2.1", dst="198.51.100.1") / scapy.TCP(dport=443),
        scapy.IP(src="192.0.2.1", dst="198.51.100.53")
        / scapy.UDP(dport=53)
        / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.invalid")),
    ]
    scapy.wrpcap(str(path), packets)
    results = list(
        analyse_pcap(path, operating_system=OperatingSystem.LINUX, hostname="lab", synthetic=True)
    )
    assert results[0].event.event_type == "network_packet"
    assert results[1].event.event_type == "dns_query"
    assert results[1].event.details["query"] == "example.invalid."
    assert all(item.event.synthetic for item in results)
