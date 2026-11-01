"""Triggering and ordinary scenarios for every additional detection and policy boundary."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from scry_security.core.event_schema import SecurityEvent
from scry_security.detection.engine import DetectionEngine
from scry_security.detection.loader import load_rules
from scry_security.detection.policy import DetectionPolicy, HostPolicy, load_policy


def event(event_type, *, index=0, os="windows", **overrides):
    return SecurityEvent(
        **{
            "timestamp": datetime(2026, 11, 1, tzinfo=UTC) + timedelta(milliseconds=index * 100),
            "operating_system": os,
            "hostname": "policy-lab",
            "username": "alice",
            "category": "system",
            "event_type": event_type,
            "source": "synthetic-policy-fixture",
            "synthetic": True,
            **overrides,
        }
    )


def repeated(event_type, count, **kwargs):
    return [event(event_type, index=index, **kwargs) for index in range(count)]


CASES = [
    (
        "SCRY-AUTH-006",
        {},
        repeated("authentication_failure", 10, details={"authentication_channel": "local"}),
        repeated("authentication_failure", 10, details={"authentication_channel": "network"}),
    ),
    (
        "SCRY-NETWORK-005",
        {"watched_destinations": ["198.51.100.0/24"]},
        repeated(
            "network_connection",
            3,
            destination_ip="198.51.100.1",
            details={"protocol": "tcp", "status": "SYN_SENT"},
        ),
        repeated(
            "network_connection",
            3,
            destination_ip="198.51.100.1",
            details={"protocol": "tcp", "status": "ESTABLISHED"},
        ),
    ),
    ("SCRY-AUTH-004", {}, repeated("account_locked", 3), repeated("account_locked", 2)),
    (
        "SCRY-PRIVILEGE-001",
        {},
        repeated("privilege_use", 3, os="linux", outcome="failure", details={"mechanism": "sudo"}),
        repeated("privilege_use", 2, os="linux", outcome="failure", details={"mechanism": "sudo"}),
    ),
    (
        "SCRY-PRIVILEGE-002",
        {
            "operating_system": "linux",
            "privileged_accounts": ["root"],
            "approved_sudo_users": ["operator"],
        },
        [event("privilege_use", os="linux", details={"mechanism": "sudo", "target_user": "root"})],
        [
            event(
                "privilege_use",
                os="linux",
                username="operator",
                details={"mechanism": "sudo", "target_user": "root"},
            )
        ],
    ),
    (
        "SCRY-PRIVILEGE-003",
        {"approved_privilege_users": ["svc-backup"]},
        [event("privileges_assigned")],
        [event("privileges_assigned", username="svc-backup")],
    ),
    (
        "SCRY-AUTH-005",
        {"privileged_accounts": ["admin"], "allowed_admin_sources": ["10.0.0.0/8"]},
        [
            event(
                "authentication_success",
                username="admin",
                source_ip="192.0.2.1",
                details={"LogonType": "3"},
            )
        ],
        [
            event(
                "authentication_success",
                username="admin",
                source_ip="10.0.0.1",
                details={"LogonType": "3"},
            )
        ],
    ),
    (
        "SCRY-ACCOUNT-002",
        {"approved_accounts": ["provisioned"]},
        [event("account_created", username="unexpected")],
        [event("account_created", username="provisioned")],
    ),
    (
        "SCRY-ACCOUNT-003",
        {"protected_accounts": ["breakglass"], "approved_account_actors": ["change-bot"]},
        [event("account_modified", username="breakglass", details={"actor": "unknown-operator"})],
        [event("account_modified", username="breakglass", details={"actor": "change-bot"})],
    ),
    (
        "SCRY-ACCOUNT-004",
        {"privileged_groups": ["S-1-5-21-1-512"], "approved_group_actors": ["owner"]},
        [
            event(
                "group_membership_added",
                details={"group_id": "S-1-5-21-1-512", "actor": "operator"},
            )
        ],
        [event("group_membership_added", details={"group_id": "S-1-5-21-1-512", "actor": "owner"})],
    ),
    (
        "SCRY-SYSTEM-002",
        {"approved_services": ["Backup"]},
        [event("service_installed", details={"service_name": "Unapproved"})],
        [event("service_installed", details={"service_name": "Backup"})],
    ),
    (
        "SCRY-SYSTEM-003",
        {"approved_tasks": ["\\Maintenance\\Backup"]},
        [event("scheduled_task_updated", details={"task_name": "\\Unapproved"})],
        [event("scheduled_task_updated", details={"task_name": "\\Maintenance\\Backup"})],
    ),
    (
        "SCRY-SYSTEM-004",
        {"review_security_changes": True, "approved_change_actors": ["change-bot"]},
        [event("audit_policy_changed", details={"actor": "operator"})],
        [event("audit_policy_changed", details={"actor": "change-bot"})],
    ),
    (
        "SCRY-PROCESS-001",
        {"watched_processes": ["watched.exe"]},
        [event("process_created", process={"executable": "C:\\lab\\watched.exe"})],
        [event("process_created", process={"executable": "C:\\lab\\ordinary.exe"})],
    ),
    (
        "SCRY-PROCESS-002",
        {},
        [
            event(
                "powershell_script_block",
                details={
                    "ScriptBlockText": "[Convert]::FromBase64String('AA=='); "
                    "Invoke-Expression $text"
                },
            )
        ],
        [
            event(
                "powershell_script_block",
                details={"ScriptBlockText": "Write-Output 'FromBase64String'"},
            )
        ],
    ),
    (
        "SCRY-NETWORK-002",
        {"watched_destinations": ["198.51.100.0/24"]},
        repeated("network_connection", 5, destination_ip="198.51.100.1"),
        repeated("network_connection", 5, destination_ip="203.0.113.1"),
    ),
    (
        "SCRY-NETWORK-003",
        {"review_connection_bursts": True},
        repeated("network_connection", 100),
        repeated("network_connection", 99),
    ),
    (
        "SCRY-NETWORK-004",
        {"watched_dns_suffixes": ["watched.example.invalid"]},
        repeated("dns_query", 3, details={"query": "sub.watched.example.invalid."}),
        repeated("dns_query", 3, details={"query": "watched.example.invalid.not-watched.invalid."}),
    ),
]


@pytest.mark.parametrize(
    "rule_id,settings,suspicious,ordinary", CASES, ids=[case[0] for case in CASES]
)
def test_new_rules_have_suspicious_and_benign_scenarios(rule_id, settings, suspicious, ordinary):
    fields = {
        "operating_system": suspicious[0].operating_system.value,
        "hostname": "policy-lab",
        **settings,
    }
    policy = DetectionPolicy(hosts=[HostPolicy(**fields)])
    findings = DetectionEngine(load_rules(), policy=policy).analyse(suspicious)
    selected = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(selected) == 1
    assert selected[0].event_ids
    assert (
        selected[0].false_positives and selected[0].investigation and selected[0].defensive_actions
    )
    assert rule_id not in {
        finding.rule_id
        for finding in DetectionEngine(load_rules(), policy=policy).analyse(ordinary)
    }
    if rule_id not in {"SCRY-AUTH-004", "SCRY-AUTH-006", "SCRY-PRIVILEGE-001", "SCRY-PROCESS-002"}:
        assert selected[0].context["policy_sha256"]
        assert selected[0].context["reasons"]
        assert not DetectionEngine(load_rules()).analyse(suspicious)


def test_untrusted_context_cannot_enable_policy_findings():
    forged = event(
        "service_installed", context={"service_change": True}, details={"service_name": "Rogue"}
    )
    assert DetectionEngine(load_rules()).analyse([forged]) == []
    assert forged.context == {"service_change": True}  # original supplied evidence not mutated


@pytest.mark.parametrize("os_name", ["windows", "linux"])
def test_admin_policy_is_host_scoped_and_requires_a_source_address(os_name):
    scope = HostPolicy(
        operating_system=os_name,
        hostname="policy-lab",
        privileged_accounts=["admin"],
        allowed_admin_sources=["10.0.0.0/8"],
    )
    policy = DetectionPolicy(hosts=[scope])
    success = event(
        "authentication_success",
        os=os_name,
        username="admin",
        source_ip="192.0.2.1",
        details={"LogonType": "3"},
    )
    assert any(
        f.rule_id == "SCRY-AUTH-005"
        for f in DetectionEngine(load_rules(), policy=policy).analyse([success])
    )
    assert not DetectionEngine(load_rules(), policy=policy).analyse(
        [success.model_copy(update={"source_ip": None})]
    )
    assert not DetectionEngine(load_rules(), policy=policy).analyse(
        [success.model_copy(update={"hostname": "unconfigured"})]
    )


def test_policy_validation_and_deletion_inventory(tmp_path):
    with pytest.raises(ValidationError):
        DetectionPolicy(hosts=[HostPolicy(operating_system="linux", hostname="lab")] * 2)
    with pytest.raises(ValidationError):
        HostPolicy(operating_system="linux", hostname="lab", watched_dns_suffixes=["*.invalid"])
    with pytest.raises(ValidationError):
        HostPolicy(
            operating_system="linux", hostname="lab", service_unit_directories=["../systemd"]
        )
    path = tmp_path / "policy.toml"
    path.write_text(
        '[[hosts]]\noperating_system="linux"\nhostname="policy-lab"\napproved_account_deletions=["leaver"]\n'
    )
    policy = load_policy(path)
    findings = DetectionEngine(load_rules(), policy=policy).analyse(
        [event("account_deleted", os="linux")]
    )
    assert {finding.rule_id for finding in findings} == {"SCRY-ACCOUNT-002"}
    assert not DetectionEngine(load_rules(), policy=policy).analyse(
        [event("account_deleted", os="linux", username="leaver")]
    )


def test_dns_case_normalisation_and_domain_boundaries():
    policy = DetectionPolicy(
        hosts=[
            HostPolicy(
                operating_system="windows",
                hostname="policy-lab",
                watched_dns_suffixes=["watched.example.invalid"],
            )
        ]
    )
    events = [
        event("dns_query", index=index, details={"query": name})
        for index, name in enumerate(
            ["WATCHED.example.invalid.", "watched.EXAMPLE.invalid", "watched.example.invalid"]
        )
    ]
    assert {
        item.rule_id for item in DetectionEngine(load_rules(), policy=policy).analyse(events)
    } == {"SCRY-NETWORK-004"}


def test_linux_unit_file_context_requires_an_approved_monitoring_source_and_scope():
    policy = DetectionPolicy(
        hosts=[
            HostPolicy(
                operating_system="linux",
                hostname="policy-lab",
                service_unit_directories=["/etc/systemd/system"],
                approved_services=["approved.service"],
                task_config_directories=["/etc/cron.d"],
                approved_tasks=["approved-task"],
            )
        ]
    )
    service = event(
        "file_created",
        os="linux",
        source="file-integrity",
        details={"path": "/etc/systemd/system/unapproved.service"},
    )
    findings = DetectionEngine(load_rules(), policy=policy).analyse([service])
    assert "SCRY-SYSTEM-002" in {item.rule_id for item in findings}
    ordinary = service.model_copy(
        update={"details": {"path": "/etc/systemd/system/approved.service"}}
    )
    assert "SCRY-SYSTEM-002" not in {
        item.rule_id for item in DetectionEngine(load_rules(), policy=policy).analyse([ordinary])
    }
    outside = service.model_copy(update={"details": {"path": "/home/alice/unapproved.service"}})
    assert "SCRY-SYSTEM-002" not in {
        item.rule_id for item in DetectionEngine(load_rules(), policy=policy).analyse([outside])
    }
    task = service.model_copy(update={"details": {"path": "/etc/cron.d/unapproved-task"}})
    assert "SCRY-SYSTEM-003" in {
        item.rule_id for item in DetectionEngine(load_rules(), policy=policy).analyse([task])
    }
