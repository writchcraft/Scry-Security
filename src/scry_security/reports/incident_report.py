"""Validated, self-contained investigation snapshots."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scry_security.alerts.manager import Alert, AlertStatus
from scry_security.core.event_schema import SecurityEvent


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    report_version: Literal[1] = 1
    incident_id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=8000)
    analyst: str = Field(min_length=1, max_length=200)
    status: AlertStatus = AlertStatus.INVESTIGATING
    synthetic: bool
    affected_hosts: list[str]
    operating_systems: list[str]
    accounts: list[str]
    source_addresses: list[str]
    destination_addresses: list[str]
    alerts: list[Alert] = Field(min_length=1, max_length=100)
    timeline: list[SecurityEvent] = Field(min_length=1, max_length=10_000)
    observed_evidence: list[str]
    analyst_findings: str = Field(default="No analyst interpretation recorded.", max_length=16_000)
    possible_false_positives: list[str]
    recommended_actions: list[str]
    mitre_techniques: list[str]
    assessment: str = "Rule matches identify suspicious activity; they do not confirm compromise."

    @field_validator("created_at")
    @classmethod
    def utc_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Report creation time requires a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def consistent_evidence(self) -> "IncidentReport":
        ids = {event.event_id for event in self.timeline}
        if len(ids) != len(self.timeline):
            raise ValueError("Duplicate timeline event IDs")
        if any(not set(alert.event_ids).issubset(ids) for alert in self.alerts):
            raise ValueError("Report is missing supporting event evidence")
        if any(event.synthetic != self.synthetic for event in self.timeline):
            raise ValueError("Do not combine synthetic and real evidence in one incident")
        if any(alert.synthetic != self.synthetic for alert in self.alerts):
            raise ValueError("Incident alert labels must match evidence")
        if self.timeline != sorted(
            self.timeline, key=lambda event: (event.timestamp, str(event.event_id))
        ):
            raise ValueError("Incident timeline must be in event-time order")
        if len(self.model_dump_json().encode("utf-8")) > 8_388_608:
            raise ValueError("Incident snapshot exceeds 8 MiB")
        return self


def build_report(
    alerts: list[Alert],
    events: list[SecurityEvent],
    *,
    title: str,
    summary: str,
    analyst: str,
    analyst_findings: str = "No analyst interpretation recorded.",
    status: AlertStatus = AlertStatus.INVESTIGATING,
) -> IncidentReport:
    """Record facts separately from supplied interpretation; never invent findings."""
    if not alerts or not events:
        raise ValueError("An incident requires alerts and their supporting evidence")
    timeline = sorted(
        {event.event_id: event for event in events}.values(),
        key=lambda event: (event.timestamp, str(event.event_id)),
    )
    return IncidentReport(
        title=title,
        summary=summary,
        analyst=analyst,
        status=status,
        synthetic=alerts[0].synthetic,
        alerts=alerts,
        timeline=timeline,
        affected_hosts=sorted({event.hostname for event in timeline}),
        operating_systems=sorted({event.operating_system.value for event in timeline}),
        accounts=sorted({event.username for event in timeline if event.username}),
        source_addresses=sorted({str(event.source_ip) for event in timeline if event.source_ip}),
        destination_addresses=sorted(
            {str(event.destination_ip) for event in timeline if event.destination_ip}
        ),
        observed_evidence=[
            f"{len(timeline)} supporting events retained from {len(alerts)} alert(s).",
            f"Event times span {timeline[0].timestamp.isoformat()} "
            f"to {timeline[-1].timestamp.isoformat()}.",
            *[
                f"{alert.rule_id}: {alert.evidence_count} supporting event(s); "
                f"status {alert.status.value}."
                for alert in alerts
            ],
        ],
        analyst_findings=analyst_findings,
        possible_false_positives=sorted({alert.false_positives for alert in alerts}),
        recommended_actions=sorted({alert.defensive_actions for alert in alerts}),
        mitre_techniques=sorted(
            {technique for alert in alerts for technique in alert.mitre_techniques}
        ),
    )
