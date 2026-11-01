"""Policy persistence, historical re-evaluation, immutable context and native parsing."""

from fastapi.testclient import TestClient

from scry_security.api.app import create_app
from scry_security.database.database import Database
from scry_security.database.repositories import Store
from scry_security.detection.loader import load_rules
from scry_security.detection.policy import DetectionPolicy, HostPolicy, policy_digest
from scry_security.parsers.linux_parser import parse_auth_line
from scry_security.parsers.windows_parser import parse_windows_xml


def test_policy_changes_reanalyse_without_reimporting_native_evidence(tmp_path):
    event = parse_auth_line(
        "2026-11-01T10:00:00Z linux-lab sudo[123]: alice : "
        "TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
        synthetic=True,
    ).event
    assert event.process.pid == 123
    database = Database(tmp_path / "policy.sqlite")
    store = Store(database)
    rules = load_rules()
    policy = DetectionPolicy(
        policy_id="lab-sudo",
        hosts=[
            HostPolicy(
                operating_system="linux",
                hostname="linux-lab",
                privileged_accounts=["root"],
                approved_sudo_users=["operator"],
            )
        ],
    )
    try:
        assert store.ingest([event], rules) == {"added_events": 1, "added_alerts": 0}
        assert store.ingest([], rules, policy=policy) == {"added_events": 0, "added_alerts": 1}
        alert = store.alerts()[0]
        assert alert.rule_id == "SCRY-PRIVILEGE-002"
        assert alert.context["policy_sha256"] == policy_digest(policy)
        assert store.supporting_events(alert.alert_id)[0].context == {}
        approved = policy.model_copy(
            update={
                "hosts": [policy.hosts[0].model_copy(update={"approved_sudo_users": ["alice"]})]
            }
        )
        store.ingest([], rules, policy=approved)
        assert store.alert(alert.alert_id).context["policy_sha256"] == policy_digest(policy)
        assert store.configuration(f"policy:{policy_digest(policy)}")["policy_id"] == "lab-sudo"
        token = "synthetic-policy-test-token-at-least-32-characters"
        with TestClient(create_app(store, token)) as client:
            assert client.get("/api/policy").status_code == 401
            assert client.get(f"/api/policies/{policy_digest(policy)}").status_code == 401
            headers = {"Authorization": f"Bearer {token}"}
            assert (
                client.get(f"/api/policies/{policy_digest(policy)}", headers=headers).status_code
                == 200
            )
            assert client.get("/api/policies/invalid", headers=headers).status_code == 422
            assert client.get("/api/policy", headers=headers).json()["hosts"][0][
                "approved_sudo_users"
            ] == ["alice"]
    finally:
        database.close()


def xml(event_id, fields):
    from xml.sax.saxutils import escape

    payload = "".join(f'<Data Name="{key}">{escape(value)}</Data>' for key, value in fields.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f"<EventID>{event_id}</EventID><Channel>Security</Channel><Computer>windows-lab</Computer>"
        '<TimeCreated SystemTime="2026-11-01T10:00:00Z"/></System>'
        f"<EventData>{payload}</EventData></Event>"
    )


def test_windows_process_actor_and_missing_member_name_are_normalised():
    event = parse_windows_xml(
        xml(
            "4688",
            {
                "SubjectUserName": "operator",
                "NewProcessId": "0x123",
                "NewProcessName": "C:\\lab\\watched.exe",
            },
        ),
        synthetic=True,
    ).event
    assert event.details["actor"] == "operator"
    assert event.process.pid == 0x123
    assert event.process.name == "watched.exe"
    membership = parse_windows_xml(
        xml(
            "4732",
            {
                "SubjectUserName": "operator",
                "MemberName": "-",
                "MemberSid": "S-1-5-21-123-1001",
                "TargetSid": "S-1-5-32-544",
            },
        )
    ).event
    assert membership.username == "S-1-5-21-123-1001"
    assert membership.details["group_id"] == "S-1-5-32-544"


def test_linux_membership_and_sudo_actor_fields():
    membership = parse_auth_line(
        "2026-11-01T10:00:00Z linux-lab usermod[123]: add 'alice' to group 'sudo'"
    ).event
    assert membership.event_type == "group_membership_added"
    assert membership.details["group_name"] == "sudo"
    logged = parse_auth_line(
        "2026-11-01T10:00:00Z linux-lab gpasswd[124]: user alice added by root to group sudo"
    ).event
    assert logged.details["actor"] == "root"
    assert logged.details["group_name"] == "sudo"


def test_linux_crontab_update_is_not_confused_with_job_execution():
    updated = parse_auth_line(
        "2026-11-01T10:00:00Z linux-lab crontab[125]: (operator) REPLACE (alice)"
    ).event
    assert updated.event_type == "scheduled_task_updated"
    assert updated.details["actor"] == "operator"
    assert updated.details["task_name"] == "crontab:alice"
    ordinary = parse_auth_line(
        "2026-11-01T10:00:00Z linux-lab CRON[126]: (alice) CMD (/usr/bin/true)"
    )
    assert ordinary.skipped
