"""Demonstrations use actual parsers, catalogue and policy rather than fixed dashboard totals."""

from pathlib import Path

import pytest

from scry_security.core.platform import OperatingSystem
from scry_security.detection.loader import load_rules
from scry_security.detection.policy import load_policy
from scry_security.main import main
from scry_security.services.replay import replay_file, replay_pcap


def test_network_metadata_fixtures_and_policy():
    root = Path(__file__).resolve().parents[2]
    policy = load_policy(root / "examples/detection-policy.toml")
    positive = replay_file(
        root / "sample_logs/network/suspicious/connections.jsonl",
        format="canonical",
        rules=load_rules(),
        policy=policy,
    )
    assert positive.errors == 0
    assert {finding.rule_id for finding in positive.findings} == {
        "SCRY-NETWORK-001",
        "SCRY-NETWORK-002",
    }
    benign = replay_file(
        root / "sample_logs/network/benign/connections.jsonl",
        format="canonical",
        rules=load_rules(),
        policy=policy,
    )
    assert benign.findings == ()


def test_offline_pcap_replay_cli_and_packet_budget(capsys):
    pytest.importorskip("scapy.all")
    root = Path(__file__).resolve().parents[2]
    path = root / "sample_logs/network/suspicious/dns.pcap"
    policy_path = root / "examples/detection-policy.toml"
    result = replay_pcap(
        path,
        operating_system=OperatingSystem.LINUX,
        hostname="linux-lab",
        rules=load_rules(),
        policy=load_policy(policy_path),
        synthetic=True,
    )
    assert len(result.events) == 3
    assert {finding.rule_id for finding in result.findings} == {"SCRY-NETWORK-004"}
    assert result.errors == 0
    limited = replay_pcap(
        path,
        operating_system=OperatingSystem.LINUX,
        hostname="linux-lab",
        rules=load_rules(),
        synthetic=True,
        max_packets=2,
    )
    assert len(limited.events) == 2 and limited.errors == 1
    assert main(["--pcap", str(path)]) == 2  # origin context cannot be guessed
    assert (
        main(
            [
                "--pcap",
                str(path),
                "--capture-os",
                "linux",
                "--capture-host",
                "linux-lab",
                "--policy",
                str(policy_path),
                "--synthetic",
            ]
        )
        == 0
    )
    assert '"rule_id":"SCRY-NETWORK-004"' in capsys.readouterr().out


def test_malformed_capture_is_reported_without_stopping_the_application(tmp_path, capsys):
    pytest.importorskip("scapy.all")
    path = tmp_path / "malformed.pcap"
    path.write_bytes(b"this is not a capture")
    assert (
        main(["--pcap", str(path), "--capture-os", "linux", "--capture-host", "lab", "--synthetic"])
        == 2
    )
    assert '"errors": 1' in capsys.readouterr().err
