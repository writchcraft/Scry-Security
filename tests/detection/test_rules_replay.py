"""Rule validation and complete native-record-to-finding demonstrations."""

import json
from pathlib import Path

import pytest
import yaml

from scry_security.detection.loader import RuleLoadError, load_rules
from scry_security.main import main
from scry_security.services.replay import replay_file


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "name: example",
        "- !!python/object/apply:os.system ['whoami']",
        "- &a {name: example}\n- *a",
        "- {rule_id: SCRY-TEST-001, rule_id: SCRY-TEST-002}",
    ],
)
def test_unsafe_or_invalid_catalogue(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(RuleLoadError):
        load_rules(path)


def test_unknown_fields_duplicate_ids_and_invalid_modes(tmp_path):
    rule = load_rules()[0].model_dump(mode="json")
    path = tmp_path / "rules.yaml"
    for invalid in (
        [rule, rule],
        [{**rule, "extra": True}],
        [{**rule, "group_by": ["raw.password"]}],
        [{**rule, "mode": "distinct", "distinct_field": None}],
    ):
        path.write_text(yaml.safe_dump(invalid))
        with pytest.raises(RuleLoadError):
            load_rules(path)


def test_native_linux_replay_is_labelled_and_tolerates_bad_record(tmp_path, capsys):
    path = tmp_path / "synthetic.log"
    lines = [
        f"2026-10-31T10:30:0{i}Z lab sshd[42]: Failed password for alice "
        "from 192.0.2.10 port 51000 ssh2"
        for i in range(5)
    ]
    path.write_text("\n".join([*lines, "bad record"]) + "\n")
    result = replay_file(path, format="linux", rules=load_rules(), synthetic=True)
    assert len(result.events) == 5
    assert len(result.findings) == 1
    assert result.findings[0].synthetic
    assert result.errors == 1
    assert main(["--replay", str(path), "--format", "linux", "--synthetic"]) == 2
    output = capsys.readouterr()
    finding = json.loads(output.out)
    assert finding["rule_id"] == "SCRY-AUTH-001"
    assert json.loads(output.err)["errors"] == 1


def test_explicit_exclusion_is_respected(tmp_path):
    from scry_security.detection.engine import DetectionEngine
    from scry_security.parsers.linux_parser import parse_auth_line

    rule = load_rules()[0].model_copy(update={"exclude": {"username": ["approved-test"]}})
    events = [
        parse_auth_line(
            f"2026-10-31T10:30:0{i}Z lab sshd[42]: Failed password for approved-test "
            "from 192.0.2.10 port 51000 ssh2"
        ).event
        for i in range(5)
    ]
    assert DetectionEngine([rule]).analyse(events) == []


@pytest.mark.parametrize(
    "relative,format,expected",
    [
        ("linux/suspicious/brute_force.txt", "linux", 2),
        ("linux/benign/ordinary.txt", "linux", 0),
        ("windows/suspicious/authentication.xml", "windows", 2),
        ("windows/suspicious/admin_group.xml", "windows", 1),
        ("windows/benign/ordinary.xml", "windows", 0),
    ],
)
def test_committed_synthetic_scenarios(relative, format, expected):
    root = Path(__file__).resolve().parents[2]
    result = replay_file(
        root / "sample_logs" / relative, format=format, rules=load_rules(), synthetic=True
    )
    assert result.errors == 0
    assert len(result.findings) == expected
    assert all(item.synthetic for item in result.events)
