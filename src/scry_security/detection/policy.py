"""Explicit host policy and derived detection context; native evidence stays untouched."""

import hashlib
import json
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyNetwork, field_validator, model_validator

from scry_security.core.event_schema import SecurityEvent

Name = Annotated[str, Field(min_length=1, max_length=1024)]
Names = Annotated[list[Name], Field(max_length=1000)]


class HostPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operating_system: Literal["windows", "linux"]
    hostname: Name
    privileged_accounts: Names = Field(default_factory=list)
    allowed_admin_sources: list[IPvAnyNetwork] | None = Field(default=None, max_length=256)
    approved_sudo_users: Names | None = None
    approved_privilege_users: Names | None = None
    approved_accounts: Names | None = None
    approved_account_deletions: Names | None = None
    protected_accounts: Names = Field(default_factory=list)
    approved_account_actors: Names = Field(default_factory=list)
    privileged_groups: Names = Field(default_factory=list)
    approved_group_actors: Names = Field(default_factory=list)
    approved_services: Names | None = None
    protected_services: Names = Field(default_factory=list)
    approved_tasks: Names | None = None
    protected_tasks: Names = Field(default_factory=list)
    service_unit_directories: Names = Field(default_factory=list)
    task_config_directories: Names = Field(default_factory=list)
    approved_change_actors: Names = Field(default_factory=list)
    review_security_changes: bool = False
    watched_processes: Names = Field(default_factory=list)
    watched_command_fragments: Names = Field(default_factory=list)
    watched_destinations: list[IPvAnyNetwork] = Field(default_factory=list, max_length=256)
    watched_dns_suffixes: Names = Field(default_factory=list)
    review_connection_bursts: bool = False

    @field_validator("watched_dns_suffixes")
    @classmethod
    def dns_suffixes(cls, values: list[str]) -> list[str]:
        canonical = []
        for value in values:
            value = value.casefold().rstrip(".")
            if len(value) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in value.split(".")
            ):
                raise ValueError(
                    "DNS watch suffixes must be valid ASCII domain names; use IDNA form if needed"
                )
            canonical.append(value)
        return canonical

    @model_validator(mode="after")
    def valid_file_scopes(self) -> "HostPolicy":
        directories = [*self.service_unit_directories, *self.task_config_directories]
        if directories and self.operating_system != "linux":
            raise ValueError("Unit/cron directory policy applies to Linux scopes")
        if any(
            not PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
            for path in directories
        ):
            raise ValueError("Unit/cron directories must be absolute normalised Linux paths")
        for name in type(self).model_fields:
            values = getattr(self, name)
            if isinstance(values, list) and any(
                isinstance(value, str) and not value.strip() for value in values
            ):
                raise ValueError("Policy list entries must not be blank")
        return self


class DetectionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    policy_id: str = Field(default="local-policy", min_length=1, max_length=100)
    hosts: list[HostPolicy] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_hosts(self) -> "DetectionPolicy":
        keys = [(host.operating_system, host.hostname) for host in self.hosts]
        if len(keys) != len(set(keys)):
            raise ValueError("Only one policy scope per OS and hostname is permitted")
        return self


def load_policy(path: Path) -> DetectionPolicy:
    with path.open("rb") as stream:
        raw = stream.read(262_145)
    if len(raw) > 262_144:
        raise ValueError("Detection policy exceeds 256 KiB")
    return DetectionPolicy.model_validate(tomllib.loads(raw.decode("utf-8")))


def policy_digest(policy: DetectionPolicy) -> str:
    return hashlib.sha256(
        json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode()
    ).hexdigest()


class PolicyEvaluator:
    def __init__(self, policy: DetectionPolicy):
        self.policy = policy
        self.scopes = {(host.operating_system, host.hostname): host for host in policy.hosts}
        self.digest = policy_digest(policy)

    def enrich(self, event: SecurityEvent) -> SecurityEvent:
        """Recompute context from trusted configuration, ignoring supplied context flags."""
        context = {}
        reasons = []
        details = event.details

        def flag(name: str, reason: str) -> None:
            context[name] = True
            reasons.append(reason)

        if event.event_type == "powershell_script_block":
            raw_script = details.get("ScriptBlockText")
            script = raw_script.casefold() if isinstance(raw_script, str) else ""
            if "frombase64string" in script and re.search(r"\b(?:iex|invoke-expression)\b", script):
                flag(
                    "powershell_indicators",
                    "Script block contains Base64 decoding and dynamic invocation indicators",
                )
        scope = self.scopes.get((event.operating_system.value, event.hostname))
        if scope is None:
            if reasons:
                context["reasons"] = reasons
            return event.model_copy(update={"context": context})
        context["policy_id"] = self.policy.policy_id
        context["policy_sha256"] = self.digest
        actor = details.get("actor")
        account_change = event.event_type in {
            "account_created",
            "account_deleted",
            "account_modified",
        }
        if account_change and actor not in scope.approved_account_actors:
            if (
                event.event_type == "account_created"
                and event.username is not None
                and scope.approved_accounts is not None
                and event.username not in scope.approved_accounts
            ):
                flag(
                    "account_change",
                    "Account creation falls outside the configured approved account inventory",
                )
            if (
                event.event_type == "account_deleted"
                and event.username is not None
                and scope.approved_account_deletions is not None
                and event.username not in scope.approved_account_deletions
            ):
                flag(
                    "account_change",
                    "Account deletion falls outside the configured approved deletion list",
                )
            if event.username in scope.protected_accounts:
                flag(
                    "protected_account",
                    "A configured protected account changed; verify authorisation",
                )
        if (
            event.event_type == "privilege_use"
            and details.get("mechanism") == "sudo"
            and scope.approved_sudo_users is not None
            and event.username is not None
            and event.username not in scope.approved_sudo_users
            and details.get("target_user") in scope.privileged_accounts
        ):
            flag(
                "sudo_use",
                "Sudo targeted a configured privileged account from an unapproved invoking account",
            )
        if (
            event.event_type == "privileges_assigned"
            and scope.approved_privilege_users is not None
            and event.username is not None
            and event.username not in scope.approved_privilege_users
        ):
            flag(
                "privilege_assignment",
                "Sensitive privileges were assigned outside the configured account allowlist",
            )
        if (
            event.event_type == "authentication_success"
            and event.username in scope.privileged_accounts
            and scope.allowed_admin_sources is not None
            and event.source_ip is not None
            and not any(event.source_ip in network for network in scope.allowed_admin_sources)
        ):
            if event.operating_system.value == "linux" or details.get("LogonType") in {"3", "10"}:
                flag(
                    "admin_logon",
                    "A configured privileged account logged on from outside approved networks",
                )
        groups = {
            value
            for value in (details.get("group_id"), details.get("group_name"))
            if isinstance(value, str)
        }
        if (
            event.event_type
            in {"group_membership_added", "group_membership_removed", "group_membership_changed"}
            and groups.intersection(scope.privileged_groups)
            and actor not in scope.approved_group_actors
        ):
            flag(
                "group_change",
                "Configured privileged group membership changed; actor approval is absent",
            )
        if actor not in scope.approved_change_actors:
            service = details.get("service_name")
            if (
                event.event_type == "service_installed"
                and isinstance(service, str)
                and (
                    (scope.approved_services is not None and service not in scope.approved_services)
                    or service in scope.protected_services
                )
            ):
                flag(
                    "service_change",
                    "Service installation falls outside the configured service inventory",
                )
            task = details.get("task_name")
            if (
                event.event_type
                in {"scheduled_task_created", "scheduled_task_updated", "scheduled_task_deleted"}
                and isinstance(task, str)
                and (
                    (scope.approved_tasks is not None and task not in scope.approved_tasks)
                    or task in scope.protected_tasks
                )
            ):
                flag(
                    "task_change",
                    "Scheduled task change falls outside the configured task inventory",
                )
            if scope.review_security_changes and event.event_type in {
                "audit_policy_changed",
                "defender_configuration_changed",
            }:
                flag(
                    "security_change", "A configured security/audit change requires approval review"
                )
            if (
                event.operating_system.value == "linux"
                and event.source == "file-integrity"
                and event.event_type in {"file_created", "file_modified", "file_deleted"}
                and isinstance(details.get("path"), str)
            ):
                path = PurePosixPath(details["path"])
                if path.is_absolute() and ".." not in path.parts:
                    unit_scope = any(
                        path.is_relative_to(PurePosixPath(root))
                        for root in scope.service_unit_directories
                    )
                    task_scope = any(
                        path.is_relative_to(PurePosixPath(root))
                        for root in scope.task_config_directories
                    )
                    if (
                        unit_scope
                        and path.suffix == ".service"
                        and (
                            path.name in scope.protected_services
                            or (
                                scope.approved_services is not None
                                and path.name not in scope.approved_services
                            )
                        )
                    ):
                        flag(
                            "service_change",
                            "A configured systemd service-unit file changed; "
                            "installation or activation is not inferred",
                        )
                        context["unit_path"] = str(path)
                    if (task_scope or (unit_scope and path.suffix == ".timer")) and (
                        path.name in scope.protected_tasks
                        or (
                            scope.approved_tasks is not None
                            and path.name not in scope.approved_tasks
                        )
                    ):
                        flag(
                            "task_change",
                            "A configured scheduling file changed; task execution is not inferred",
                        )
                        context["task_path"] = str(path)
        if event.event_type == "process_created":
            executable = event.process.executable if event.process else details.get("executable")
            command = event.process.command_line if event.process else None
            command = command or details.get("CommandLine")
            name = str(executable or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
            if name and name in {value.casefold() for value in scope.watched_processes}:
                flag(
                    "process_execution", "Process name matches the explicitly configured watch list"
                )
            if isinstance(command, str) and any(
                fragment.casefold() in command.casefold()
                for fragment in scope.watched_command_fragments
            ):
                flag(
                    "process_execution",
                    "Observed command line matches an explicitly configured watch fragment",
                )
        if event.event_type == "network_connection":
            if event.destination_ip is not None and any(
                event.destination_ip in network for network in scope.watched_destinations
            ):
                flag(
                    "network_destination",
                    "New connection observation targets an explicitly watched network",
                )
                if details.get("protocol") == "tcp" and details.get("status") == "SYN_SENT":
                    flag(
                        "outbound_initiation",
                        "TCP SYN_SENT indicates a locally initiated connection "
                        "to a watched network",
                    )
            if scope.review_connection_bursts:
                flag(
                    "connection_burst",
                    "Connection-frequency review is explicitly enabled for this host",
                )
        if event.event_type == "dns_query":
            raw_query = details.get("query")
            query = raw_query.casefold().rstrip(".") if isinstance(raw_query, str) else ""
            if query and any(
                query == suffix.casefold().strip(".")
                or query.endswith("." + suffix.casefold().strip("."))
                for suffix in scope.watched_dns_suffixes
            ):
                flag("dns_query", "DNS query matches an explicitly watched domain suffix")
                context["dns_name"] = query
        if reasons:
            context["reasons"] = reasons
        return event.model_copy(update={"context": context})
