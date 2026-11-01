"""Normalise selected Event Log XML using named fields rather than positional inserts."""

from datetime import datetime

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from pydantic import ValidationError

from scry_security.core.event_schema import ProcessInfo, SecurityEvent
from scry_security.parsers.event_normaliser import ParseResult

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
# Provider/channel checks prevent unrelated providers' reused numeric IDs being
# interpreted as Security events.
SECURITY_EVENTS = {
    "4624": ("authentication", "authentication_success", "success"),
    "4625": ("authentication", "authentication_failure", "failure"),
    "4634": ("authentication", "logoff", "success"),
    "4648": ("authentication", "explicit_credentials_used", "unknown"),
    "4672": ("privilege", "privileges_assigned", "success"),
    "4720": ("account", "account_created", "success"),
    "4726": ("account", "account_deleted", "success"),
    "4738": ("account", "account_modified", "success"),
    "4728": ("account", "group_membership_added", "success"),
    "4732": ("account", "group_membership_added", "success"),
    "4756": ("account", "group_membership_added", "success"),
    "4729": ("account", "group_membership_removed", "success"),
    "4733": ("account", "group_membership_removed", "success"),
    "4740": ("authentication", "account_locked", "success"),
    "4719": ("system", "audit_policy_changed", "success"),
    "4697": ("system", "service_installed", "success"),
    "4698": ("system", "scheduled_task_created", "success"),
    "4699": ("system", "scheduled_task_deleted", "success"),
    "4702": ("system", "scheduled_task_updated", "success"),
    "4688": ("process", "process_created", "success"),
}


def parse_windows_xml(xml: str, *, synthetic: bool = False) -> ParseResult:
    if len(xml.encode("utf-8")) > 262_144:
        return ParseResult(error="Windows XML record exceeds 256 KiB")
    try:
        root = ElementTree.fromstring(xml, forbid_dtd=True)
        system = root.find("e:System", NS)
        if system is None:
            raise ValueError
        event_id = system.findtext("e:EventID", namespaces=NS)
        channel = system.findtext("e:Channel", namespaces=NS)
        provider_node = system.find("e:Provider", NS)
        provider = provider_node.get("Name") if provider_node is not None else None
        fields = {}
        for node in root.findall("e:EventData/e:Data", NS):
            name = node.get("Name")
            if name:
                if name in fields:
                    raise ValueError
                fields[name] = node.text or ""
        # 1102 uses UserData rather than the usual EventData envelope.
        for node in root.findall("e:UserData//*", NS):
            if len(node) == 0:
                fields[node.tag.rsplit("}", 1)[-1]] = node.text or ""
        if channel == "Security" and provider == SECURITY_PROVIDER and event_id in SECURITY_EVENTS:
            category, event_type, outcome = SECURITY_EVENTS[event_id]
        elif (
            channel == "Security"
            and provider == "Microsoft-Windows-Eventlog"
            and event_id == "1102"
        ):
            category, event_type, outcome = "system", "audit_log_cleared", "success"
        elif channel == "System" and provider == "Service Control Manager" and event_id == "7045":
            category, event_type, outcome = "system", "service_installed", "success"
        elif (
            channel == "Microsoft-Windows-PowerShell/Operational"
            and provider == "Microsoft-Windows-PowerShell"
            and event_id == "4104"
        ):
            category, event_type, outcome = "process", "powershell_script_block", "unknown"
        elif (
            channel == "Microsoft-Windows-Windows Defender/Operational"
            and provider == "Microsoft-Windows-Windows Defender"
            and event_id in {"1116", "1117", "5007"}
        ):
            category, event_type, outcome = (
                "system",
                {
                    "1116": "defender_threat_detected",
                    "1117": "defender_action_taken",
                    "5007": "defender_configuration_changed",
                }[event_id],
                "unknown",
            )
        else:
            return ParseResult(skipped=True)
        created = system.find("e:TimeCreated", NS)
        if created is None:
            raise ValueError
        timestamp = datetime.fromisoformat(created.attrib["SystemTime"])
        hostname = system.findtext("e:Computer", namespaces=NS)
        username = fields.get("TargetUserName") or fields.get("SubjectUserName")
        if event_type.startswith("group_membership_"):
            username = next(
                (
                    fields.get(key)
                    for key in ("MemberSid", "MemberName")
                    if fields.get(key) not in {None, "", "-"}
                ),
                None,
            )
        source_ip = fields.get("IpAddress")
        if source_ip in {None, "", "-"}:
            source_ip = None
        details = {"provider": provider, "channel": channel, **fields}
        if event_type.startswith("authentication_"):
            channel_type = {
                "2": "local",
                "7": "local",
                "11": "local",
                "3": "network",
                "10": "remote_interactive",
            }.get(fields.get("LogonType"))
            if channel_type:
                details["authentication_channel"] = channel_type
        if event_type.startswith("group_membership_") and fields.get("TargetUserName"):
            details["group_name"] = fields["TargetUserName"]
        for native, normalised in [
            ("SubjectUserName", "actor"),
            ("TargetSid", "group_id"),
            ("ServiceName", "service_name"),
            ("TaskName", "task_name"),
        ]:
            if fields.get(native) not in {None, "", "-"}:
                details[normalised] = fields[native]
        executable = fields.get("NewProcessName") or fields.get("ProcessName")
        pid = fields.get("NewProcessId") or fields.get("ProcessId")
        try:
            pid = int(pid, 16 if pid.lower().startswith("0x") else 10) if pid else None
        except ValueError:
            pid = None
        process = (
            ProcessInfo(
                pid=pid,
                executable=executable,
                name=executable.replace("\\", "/").rsplit("/", 1)[-1],
            )
            if executable
            else None
        )
        # Keep native names so investigators can distinguish actor from target,
        # and use logon IDs, SIDs and failure status codes during correlation.
        return ParseResult(
            event=SecurityEvent(
                timestamp=timestamp,
                operating_system="windows",
                hostname=hostname,
                username=username if username not in {"", "-"} else None,
                source_ip=source_ip,
                process=process,
                category=category,
                event_type=event_type,
                outcome=outcome,
                source=f"windows-eventlog:{channel}",
                native_event_id=event_id,
                native_record_id=system.findtext("e:EventRecordID", namespaces=NS),
                raw={"xml": xml},
                details=details,
                synthetic=synthetic,
            )
        )
    except (ElementTree.ParseError, DefusedXmlException, ValidationError, ValueError, KeyError):
        return ParseResult(error="Invalid Windows XML event")
