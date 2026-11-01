"""Optional offline PCAP metadata parsing. Never starts capture or retains payloads."""

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from scry_security.core.event_schema import SecurityEvent
from scry_security.core.platform import OperatingSystem
from scry_security.parsers.event_normaliser import ParseResult


def analyse_pcap(
    path: Path,
    *,
    operating_system: OperatingSystem,
    hostname: str,
    synthetic: bool = False,
    max_packets: int = 10_000,
) -> Iterator[ParseResult]:
    """Analyse an explicitly supplied authorised capture with a declared source OS."""
    if not 1 <= max_packets <= 100_000:
        raise ValueError("Invalid packet limit")
    if path.stat().st_size > 134_217_728:
        raise ValueError("Capture exceeds 128 MiB")
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, IPv6, PcapReader
    from scapy.error import Scapy_Exception

    try:
        with PcapReader(str(path)) as reader:
            for index, packet in enumerate(reader):
                if index >= max_packets:
                    yield ParseResult(
                        error="Packet limit reached; remaining capture was not analysed"
                    )
                    return
                network = packet.getlayer(IP) or packet.getlayer(IPv6)
                transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                if network is None or transport is None:
                    yield ParseResult(skipped=True)
                    continue
                details = {
                    "protocol": "tcp" if packet.haslayer(TCP) else "udp",
                    "source_port": int(transport.sport),
                    "destination_port": int(transport.dport),
                    "observation": "packet",
                }
                event_type = "network_packet"
                if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                    event_type = "dns_query"
                    details["query"] = bytes(packet[DNSQR].qname)[:255].decode(
                        "ascii", errors="replace"
                    )
                try:
                    yield ParseResult(
                        event=SecurityEvent(
                            timestamp=datetime.fromtimestamp(float(packet.time), tz=UTC),
                            operating_system=operating_system,
                            hostname=hostname,
                            source_ip=network.src,
                            destination_ip=network.dst,
                            category="network",
                            event_type=event_type,
                            source="offline-pcap",
                            native_record_id=str(index),
                            details=details,
                            synthetic=synthetic,
                        )
                    )
                except (ValidationError, ValueError, OverflowError, OSError):
                    yield ParseResult(error="Invalid packet metadata")
    except (Scapy_Exception, EOFError, struct.error):
        yield ParseResult(error="Malformed or unsupported capture data")
