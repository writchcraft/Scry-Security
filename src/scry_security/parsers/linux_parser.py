"""Parse selected OpenSSH, sudo and account-management messages, without I/O."""

import re
from datetime import datetime, tzinfo

from pydantic import ValidationError

from scry_security.core.event_schema import ProcessInfo, SecurityEvent
from scry_security.parsers.event_normaliser import ParseResult

_SYSLOG = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_ISOLOG = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+"
    r"(?P<program>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}


def parse_linux_message(
    message: str,
    *,
    timestamp: datetime,
    hostname: str,
    program: str,
    source: str,
    raw: dict,
    native_record_id: str | None = None,
    synthetic: bool = False,
    process_id: int | None = None,
) -> ParseResult:
    """Recognise messages only from their expected program to reduce false attribution."""
    event_type = None
    category = "authentication"
    outcome = "unknown"
    username = None
    source_ip = None
    details = {}
    program = program.rsplit("/", 1)[-1]
    if program in {"sshd", "sshd-session"}:
        auth = re.search(
            r"(?P<action>Failed|Accepted) (?:password|publickey|keyboard-interactive/pam) for "
            r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
            message,
        )
        invalid = re.search(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", message)
        if auth:
            outcome = "failure" if auth["action"] == "Failed" else "success"
            event_type = f"authentication_{outcome}"
            username, source_ip = auth["user"], auth["ip"]
            details = {"protocol": "ssh", "source_port": int(auth["port"])}
            details["authentication_channel"] = "network"
        elif invalid:
            # An invalid-user message can accompany a Failed line for the same
            # attempt. Keep distinct so brute-force rules do not double-count it.
            event_type = "invalid_username"
            outcome = "failure"
            username, source_ip = invalid["user"], invalid["ip"]
            details = {"protocol": "ssh"}
    elif program == "crontab":
        change = re.fullmatch(
            r"\((?P<actor>[^()\s]+)\) (?P<action>REPLACE|DELETE) \((?P<target>[^()\s]+)\)",
            message.strip(),
        )
        if change:
            event_type = (
                "scheduled_task_updated"
                if change["action"] == "REPLACE"
                else "scheduled_task_deleted"
            )
            category, username = "system", change["target"]
            details = {"actor": change["actor"], "task_name": f"crontab:{change['target']}"}
    elif program == "sudo":
        command = re.match(
            r"\s*(?P<user>\S+)\s*:\s*.*\bUSER=(?P<target>[^ ;]+).*;\s*COMMAND=", message
        )
        denied = re.match(r"\s*(?P<user>\S+)\s*:\s*.*(?:NOT in sudoers|not allowed)", message)
        if command or denied:
            match = denied or command
            event_type, category = "privilege_use", "privilege"
            username = match["user"]
            # A recorded command is evidence of an authorised attempt, not proof
            # that the invoked command completed successfully.
            outcome = "failure" if denied else "unknown"
            details = {"mechanism": "sudo"}
            if command:
                details["target_user"] = command["target"]
            details["actor"] = username
    elif program in {"useradd", "userdel", "usermod", "groupadd", "groupdel", "gpasswd"}:
        membership = re.search(
            r"(?P<action>add|delete) ['\"](?P<user>[\w.@$-]+)['\"] "
            r"(?:to|from) group ['\"](?P<group>[\w.@$-]+)['\"]",
            message,
        )
        account = re.search(r"(?:name=|user ['\"]?)([\w.@$-]+)", message)
        if membership:
            event_type = (
                "group_membership_added"
                if membership["action"] == "add"
                else "group_membership_removed"
            )
            category, username = "account", membership["user"]
            details["group_name"] = membership["group"]
        elif account:
            event_type = {
                "useradd": "account_created",
                "userdel": "account_deleted",
                "usermod": "account_modified",
                "groupadd": "group_created",
                "groupdel": "group_deleted",
                "gpasswd": "group_membership_changed",
            }[program]
            category, username = "account", account[1]
            group = re.search(r"\bgroup ['\"]?([\w.@$-]+)", message)
            actor = re.search(r"\bby ['\"]?([\w.@$-]+)", message)
            if group:
                details["group_name"] = group[1]
            if actor:
                details["actor"] = actor[1]
    if event_type is None:
        return ParseResult(skipped=True)
    try:
        return ParseResult(
            event=SecurityEvent(
                timestamp=timestamp,
                operating_system="linux",
                hostname=hostname,
                username=username,
                source_ip=source_ip,
                process=ProcessInfo(pid=process_id, name=program),
                category=category,
                event_type=event_type,
                outcome=outcome,
                source=source,
                native_event_id=program,
                native_record_id=native_record_id,
                raw=raw,
                details=details,
                synthetic=synthetic,
            )
        )
    except ValidationError:
        return ParseResult(error="Invalid Linux event fields")


def parse_auth_line(
    line: str,
    *,
    year: int | None = None,
    source_timezone: tzinfo | None = None,
    source: str = "auth.log",
    synthetic: bool = False,
) -> ParseResult:
    if len(line.encode("utf-8")) > 65_536:
        return ParseResult(error="Linux record exceeds 64 KiB")
    match = _ISOLOG.match(line) or _SYSLOG.match(line)
    if not match:
        return ParseResult(error="Unrecognised Linux log envelope")
    try:
        if match["stamp"][0].isdigit():
            timestamp = datetime.fromisoformat(match["stamp"])
        else:
            if year is None or source_timezone is None:
                return ParseResult(error="Legacy syslog requires explicit year and timezone")
            month, day, clock = match["stamp"].split()
            hour, minute, second = map(int, clock.split(":"))
            timestamp = datetime(
                year, _MONTHS[month], int(day), hour, minute, second, tzinfo=source_timezone
            )
        if timestamp.tzinfo is None:
            return ParseResult(error="Linux timestamp requires explicit UTC offset")
    except (ValueError, KeyError):
        return ParseResult(error="Invalid Linux timestamp")
    return parse_linux_message(
        match["message"],
        timestamp=timestamp,
        hostname=match["host"],
        program=match["program"],
        source=source,
        raw={"line": line.rstrip("\r\n")},
        synthetic=synthetic,
        process_id=int(match["pid"]) if match["pid"] and len(match["pid"]) < 11 else None,
    )
