"""Generate offline-only synthetic network fixtures; no packets are transmitted."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from scry_security.core.event_schema import SecurityEvent


def main() -> None:
    from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap

    root = Path(__file__).resolve().parents[1] / "sample_logs" / "network"
    suspicious = root / "suspicious"
    benign = root / "benign"
    suspicious.mkdir(parents=True, exist_ok=True)
    benign.mkdir(exist_ok=True)
    started = datetime(2026, 11, 1, 12, tzinfo=UTC)

    def connection(index: int, watched: bool) -> SecurityEvent:
        return SecurityEvent(
            event_id=uuid5(NAMESPACE_URL, f"scry:synthetic-network:{watched}:{index}"),
            timestamp=started + timedelta(seconds=index),
            ingested_at=started,
            operating_system="windows",
            hostname="windows-lab",
            source_ip="192.0.2.1",
            destination_ip="198.51.100.1" if watched else "203.0.113.1",
            category="network",
            event_type="network_connection",
            source="synthetic-network-fixture",
            synthetic=True,
            details={
                "protocol": "tcp",
                "source_port": 51000 + index,
                "destination_port": 4444 if watched else 443,
                "policy_violation": watched,
                "observation": "synthetic_new_tuple",
            },
        )

    (suspicious / "connections.jsonl").write_text(
        "".join(connection(index, True).model_dump_json() + "\n" for index in range(5)),
        encoding="utf-8",
    )
    (benign / "connections.jsonl").write_text(
        connection(0, False).model_dump_json() + "\n", encoding="utf-8"
    )
    packets = []
    for index in range(3):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="198.51.100.53")
            / UDP(sport=51000 + index, dport=53)
            / DNS(id=index, rd=1, qd=DNSQR(qname="watched.example.invalid"))
        )
        packet.time = (started + timedelta(seconds=index)).timestamp()
        packets.append(packet)
    wrpcap(str(suspicious / "dns.pcap"), packets)
    print(
        "Generated five watched connections, one benign connection and three offline DNS packets."
    )


if __name__ == "__main__":
    main()
