"""Validated alert state changes; no automated blocking or external notifications."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field

from scry_security.detection.engine import Finding


class AlertStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    previous: AlertStatus
    current: AlertStatus
    actor: str = Field(min_length=1, max_length=200)
    note: str = Field(min_length=1, max_length=4000)


class Alert(Finding):
    alert_id: UUID
    revision: int = Field(default=1, ge=1)
    status: AlertStatus = AlertStatus.NEW
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    history: list[StatusChange] = Field(default_factory=list)


def create_alert(finding: Finding) -> Alert:
    return Alert(
        **finding.model_dump(), alert_id=uuid5(NAMESPACE_URL, f"scry:alert:{finding.finding_id}")
    )


def change_status(alert: Alert, status: AlertStatus, *, actor: str, note: str) -> Alert:
    """Allow reopening, requiring a meaningful attribution and reason for every change."""
    if status == alert.status:
        raise ValueError("Alert already has that status")
    if not actor.strip() or not note.strip():
        raise ValueError("Status changes require an actor and investigation note")
    if len(alert.history) >= 1000:
        raise ValueError("Alert status history limit reached; archive the investigation")
    change = StatusChange(
        previous=alert.status, current=status, actor=actor.strip(), note=note.strip()
    )
    return alert.model_copy(
        update={
            "status": status,
            "updated_at": change.timestamp,
            "history": [*alert.history, change],
            "revision": alert.revision + 1,
        }
    )
