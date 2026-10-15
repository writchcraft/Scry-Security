"""Suspicious and ordinary activity for every initial detection."""

from datetime import UTC, datetime, timedelta

import pytest

from scry_security.core.event_schema import SecurityEvent
from scry_security.detection.engine import DetectionEngine
from scry_security.detection.rules import initial_rules


def event(index=0, **overrides):
    return SecurityEvent(
        **{
            "timestamp": datetime(2026, 10, 31, tzinfo=UTC) + timedelta(seconds=index),
            "operating_system": "linux",
            "hostname": "lab",
            "username": "alice",
            "source_ip": "192.0.2.10",
            "category": "authentication",
            "event_type": "authentication_failure",
            "outcome": "failure",
            "source": "test",
            "synthetic": True,
            **overrides,
        }
    )


def ids(findings):
    return {finding.rule_id for finding in findings}


@pytest.mark.parametrize("os_name", ["windows", "linux"])
def test_brute_force_benign_and_suspicious_both_platforms(os_name):
    engine = DetectionEngine(initial_rules())
    assert engine.analyse([event(i, operating_system=os_name) for i in range(4)]) == []
    findings = engine.process(event(4, operating_system=os_name))
    assert ids(findings) == {"SCRY-AUTH-001"}
    assert findings[0].evidence_count == 5
    assert engine.process(event(5, operating_system=os_name)) == []  # cooldown


def test_spray_distinct_accounts_and_ordinary_single_account():
    findings = DetectionEngine(initial_rules()).analyse(
        [event(i, username=f"user{i}") for i in range(5)]
    )
    assert ids(findings) == {"SCRY-AUTH-002"}
    findings = DetectionEngine(initial_rules()).analyse([event(i) for i in range(5)])
    assert "SCRY-AUTH-002" not in ids(findings)


def test_success_after_failures_and_benign_success():
    success = event(5, event_type="authentication_success", outcome="success")
    assert DetectionEngine(initial_rules()).analyse([success]) == []
    findings = DetectionEngine(initial_rules()).analyse([success, *[event(i) for i in range(5)]])
    assert "SCRY-AUTH-003" in ids(findings)
    sequence = next(item for item in findings if item.rule_id == "SCRY-AUTH-003")
    assert sequence.evidence_count == 6
    assert "not confirmed" in sequence.assessment
    assert sequence.mitre_techniques == []  # success is not proof of stolen valid accounts


def test_privileged_group_and_ordinary_group():
    addition = event(
        operating_system="windows",
        category="account",
        event_type="group_membership_added",
        details={"TargetSid": "S-1-5-32-544"},
    )
    assert ids(DetectionEngine(initial_rules()).analyse([addition])) == {"SCRY-ACCOUNT-001"}
    ordinary = addition.model_copy(update={"details": {"TargetSid": "S-1-5-32-545"}})
    assert DetectionEngine(initial_rules()).analyse([ordinary]) == []


def test_log_clearing_and_ordinary_privileges():
    cleared = event(operating_system="windows", category="system", event_type="audit_log_cleared")
    assert ids(DetectionEngine(initial_rules()).analyse([cleared])) == {"SCRY-SYSTEM-001"}
    ordinary = event(
        operating_system="windows", category="privilege", event_type="privileges_assigned"
    )
    assert DetectionEngine(initial_rules()).analyse([ordinary]) == []


def test_host_ip_missing_and_synthetic_boundaries():
    records = [event(i, hostname=f"host{i}") for i in range(5)]
    assert DetectionEngine(initial_rules()).analyse(records) == []
    records = [event(i, source_ip=None) for i in range(5)]
    assert DetectionEngine(initial_rules()).analyse(records) == []
    records = [event(i, synthetic=i < 3) for i in range(5)]
    assert DetectionEngine(initial_rules()).analyse(records) == []


def test_time_window_order_capacity_and_duplicates():
    records = [event(i * 301) for i in range(5)]
    assert DetectionEngine(initial_rules()).analyse(records) == []
    engine = DetectionEngine(initial_rules(), max_events=1)
    record = event(1)
    assert engine.process(record) == []
    assert engine.process(record) == []
    with pytest.raises(ValueError, match="Out-of-order"):
        engine.process(event(0))
    with pytest.raises(BufferError):
        engine.process(event(2))
    with pytest.raises(BufferError):
        engine.analyse([event(0), event(1)])


def test_dense_window_retains_real_attempts_without_recounting_unrelated_context():
    records = [event(0) for _ in range(5000)]
    engine = DetectionEngine(initial_rules())
    findings = engine.analyse(records)
    assert ids(findings) == {"SCRY-AUTH-001"}
    assert findings[0].evidence_count == 5
    assert len(engine._ids) == 5000


def test_network_rule_requires_explicit_policy_and_repeated_observations():
    def records(violation):
        return [
            event(
                index,
                category="network",
                event_type="network_connection",
                destination_ip="198.51.100.1",
                source="psutil-connections",
                details={"destination_port": 4444, "policy_violation": violation},
            )
            for index in range(5)
        ]

    assert DetectionEngine(initial_rules()).analyse(records(False)) == []
    findings = DetectionEngine(initial_rules()).analyse(records(True))
    assert ids(findings) == {"SCRY-NETWORK-001"}
    assert findings[0].evidence_count == 5


def test_file_rule_does_not_treat_unapproved_event_sources_as_baseline_evidence():
    ordinary = event(
        category="file",
        event_type="file_modified",
        source="other-source",
        details={"path": "/lab/example"},
    )
    assert DetectionEngine(initial_rules()).analyse([ordinary]) == []


def test_distinct_counts_expire_and_sequence_cooldown_survives_prior_expiry():
    rules = initial_rules()
    spray = next(rule for rule in rules if rule.rule_id == "SCRY-AUTH-002")
    engine = DetectionEngine([spray])
    assert engine.analyse([event(i, username=f"user{i}") for i in range(4)]) == []
    assert engine.process(event(304, username="fifth")) == []  # all first four expired
    assert not engine._contexts[next(iter(engine._contexts))].distinct_counts.get("user0")
    sequence = next(rule for rule in rules if rule.rule_id == "SCRY-AUTH-003")
    engine = DetectionEngine([sequence])
    engine.analyse([event(i) for i in range(5)])
    first = engine.process(event(299, event_type="authentication_success", outcome="success"))
    assert len(first) == 1
    assert engine.process(event(301, event_type="authentication_success", outcome="success")) == []
