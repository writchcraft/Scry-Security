"""Atomic ingestion, durable investigation status, filtering and safe retention."""

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, func, select, update

from scry_security.alerts.manager import Alert, AlertStatus, change_status, create_alert
from scry_security.core.event_schema import SecurityEvent
from scry_security.database.database import Database
from scry_security.database.models import (
    AlertRecord,
    BaselineRecord,
    ConfigurationRecord,
    EventRecord,
    EvidenceLink,
    HostRecord,
    IncidentAlertLink,
    IncidentRecord,
    IntegrityScanRecord,
    RuleRecord,
)
from scry_security.detection.engine import DetectionEngine
from scry_security.detection.policy import DetectionPolicy, policy_digest
from scry_security.detection.rules import Rule, Severity
from scry_security.integrity.monitor import FileBaseline, IntegrityScan
from scry_security.reports.incident_report import IncidentReport


def utc_key(timestamp: datetime) -> str:
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Timezone-aware timestamp required")
    return timestamp.astimezone(UTC).isoformat(timespec="microseconds")


def fingerprint(event: SecurityEvent) -> str:
    payload = event.model_dump(mode="json", exclude={"event_id", "ingested_at", "context"})
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


class ConcurrentUpdateError(ValueError):
    """The investigation changed since the analyst opened it."""


class Store:
    def __init__(self, database: Database):
        self.database = database

    def ingest(
        self,
        events: tuple[SecurityEvent, ...] | list[SecurityEvent],
        rules: list[Rule],
        *,
        checkpoint_updates: dict[str, dict] | None = None,
        policy: DetectionPolicy | None = None,
    ) -> dict:
        """Recompute bounded chronological context atomically, preserving existing analyst state.

        Initial portfolio implementation rebuilds up to 100,000 stored events.
        Capacity errors roll back the import rather than drop earlier context.
        """
        added_events = added_alerts = 0
        with self.database.sessions.begin() as session:
            stored_policy = session.get(ConfigurationRecord, "detection-policy")
            policy_changed = policy is not None and (
                stored_policy is None or stored_policy.payload != policy.model_dump(mode="json")
            )
            effective_policy = policy or (
                DetectionPolicy.model_validate(stored_policy.payload)
                if stored_policy
                else DetectionPolicy()
            )
            if policy_changed:
                session.merge(
                    ConfigurationRecord(
                        key="detection-policy", payload=policy.model_dump(mode="json")
                    )
                )
                session.merge(
                    ConfigurationRecord(
                        key=f"policy:{policy_digest(policy)}",
                        payload=policy.model_dump(mode="json"),
                    )
                )
            rules_changed = False
            for rule in rules:
                payload = rule.model_dump(mode="json")
                existing_rule = session.get(RuleRecord, rule.rule_id)
                if existing_rule is None or existing_rule.payload != payload:
                    rules_changed = True
                    session.merge(RuleRecord(rule_id=rule.rule_id, payload=payload))
            session.flush()
            for event in events:
                # Imported context is not evidence and cannot assert policy findings.
                event = event.model_copy(update={"context": {}})
                digest = fingerprint(event)
                existing = session.scalar(
                    select(EventRecord).where(EventRecord.fingerprint == digest)
                )
                if existing is not None:
                    continue
                if session.get(EventRecord, str(event.event_id)) is not None:
                    raise ValueError("Event UUID reused with different evidence")
                host_id = f"{event.operating_system.value}:{int(event.synthetic)}:{event.hostname}"
                host = session.get(HostRecord, host_id)
                if host is None:
                    host = HostRecord(
                        host_id=host_id,
                        hostname=event.hostname,
                        operating_system=event.operating_system.value,
                        synthetic=event.synthetic,
                    )
                    session.add(host)
                session.add(
                    EventRecord(
                        event_id=str(event.event_id),
                        fingerprint=digest,
                        timestamp=utc_key(event.timestamp),
                        event_type=event.event_type,
                        host=host,
                        payload=event.model_dump(mode="json"),
                    )
                )
                session.flush()
                added_events += 1
            if added_events or rules_changed or policy_changed:
                count = session.scalar(select(func.count()).select_from(EventRecord))
                if count > 100_000:
                    raise BufferError("Stored replay context exceeds 100000 events")
                records = session.scalars(
                    select(EventRecord).order_by(EventRecord.timestamp, EventRecord.event_id)
                ).all()
                context = [SecurityEvent.model_validate(row.payload) for row in records]
                findings = DetectionEngine(
                    rules, max_events=100_000, policy=effective_policy
                ).analyse(context)
                for finding in findings:
                    if session.scalar(
                        select(AlertRecord).where(AlertRecord.finding_id == str(finding.finding_id))
                    ):
                        continue
                    alert = create_alert(finding)
                    row = AlertRecord(
                        alert_id=str(alert.alert_id),
                        finding_id=str(alert.finding_id),
                        rule_id=alert.rule_id,
                        timestamp=utc_key(alert.timestamp),
                        severity=alert.severity.value,
                        status=alert.status.value,
                        hostname=alert.hostname,
                        operating_system=alert.operating_system,
                        synthetic=alert.synthetic,
                        payload=alert.model_dump(mode="json"),
                    )
                    row.events = [
                        session.get(EventRecord, str(event_id)) for event_id in alert.event_ids
                    ]
                    session.add(row)
                    added_alerts += 1
            for key, payload in (checkpoint_updates or {}).items():
                session.merge(ConfigurationRecord(key=key, payload=payload))
        return {"added_events": added_events, "added_alerts": added_alerts}

    def configuration(self, key: str) -> dict | None:
        with self.database.sessions() as session:
            row = session.get(ConfigurationRecord, key)
            return row.payload if row else None

    def source_health(self) -> list[dict]:
        with self.database.sessions() as session:
            rows = session.scalars(
                select(ConfigurationRecord).where(ConfigurationRecord.key.like("source:%"))
            ).all()
            return [row.payload["health"] for row in rows if "health" in row.payload]

    def alerts(
        self,
        *,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        operating_system: str | None = None,
        hostname: str | None = None,
        rule_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        synthetic: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("Invalid alert page")
        query = select(AlertRecord)
        for field, value in {
            "severity": severity,
            "status": status,
            "operating_system": operating_system,
            "hostname": hostname,
            "rule_id": rule_id,
            "synthetic": synthetic,
        }.items():
            if value is not None:
                query = query.where(getattr(AlertRecord, field) == value)
        if since is not None:
            query = query.where(AlertRecord.timestamp >= utc_key(since))
        if until is not None:
            query = query.where(AlertRecord.timestamp <= utc_key(until))
        with self.database.sessions() as session:
            rows = session.scalars(
                query.order_by(AlertRecord.timestamp.desc(), AlertRecord.alert_id)
                .limit(limit)
                .offset(offset)
            ).all()
            return [Alert.model_validate(row.payload) for row in rows]

    def alert(self, alert_id: UUID) -> Alert | None:
        with self.database.sessions() as session:
            row = session.get(AlertRecord, str(alert_id))
            return Alert.model_validate(row.payload) if row else None

    def set_status(
        self,
        alert_id: UUID,
        status: AlertStatus,
        *,
        actor: str,
        note: str,
        expected_revision: int | None = None,
    ) -> Alert:
        with self.database.sessions.begin() as session:
            row = session.get(AlertRecord, str(alert_id))
            if row is None:
                raise KeyError("Alert not found")
            previous = Alert.model_validate(row.payload)
            if expected_revision is not None and previous.revision != expected_revision:
                raise ConcurrentUpdateError("Alert changed; reload the investigation")
            alert = change_status(previous, status, actor=actor, note=note)
            result = session.execute(
                update(AlertRecord)
                .where(
                    AlertRecord.alert_id == str(alert_id),
                    func.coalesce(AlertRecord.payload["revision"].as_integer(), 1)
                    == previous.revision,
                )
                .values(status=alert.status.value, payload=alert.model_dump(mode="json"))
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                raise ConcurrentUpdateError("Concurrent investigation update; reload and retry")
            return alert

    def supporting_events(self, alert_id: UUID) -> list[SecurityEvent]:
        with self.database.sessions() as session:
            row = session.get(AlertRecord, str(alert_id))
            return (
                sorted(
                    (SecurityEvent.model_validate(item.payload) for item in row.events),
                    key=lambda item: item.timestamp,
                )
                if row
                else []
            )

    def save_baseline(self, baseline: FileBaseline) -> None:
        with self.database.sessions.begin() as session:
            existing = session.get(BaselineRecord, str(baseline.baseline_id))
            payload = baseline.model_dump(mode="json")
            if existing is not None:
                if existing.payload != payload:
                    raise ValueError(
                        "Existing baselines are immutable; create a newly approved baseline"
                    )
                return
            session.add(
                BaselineRecord(
                    baseline_id=str(baseline.baseline_id),
                    hostname=baseline.hostname,
                    synthetic=baseline.synthetic,
                    payload=payload,
                )
            )

    def save_integrity_scan(self, scan: IntegrityScan) -> None:
        with self.database.sessions.begin() as session:
            if session.get(BaselineRecord, str(scan.baseline_id)) is None:
                raise KeyError("Integrity baseline is not stored")
            session.add(
                IntegrityScanRecord(
                    scan_id=str(scan.scan_id),
                    baseline_id=str(scan.baseline_id),
                    timestamp=utc_key(scan.timestamp),
                    payload=scan.model_dump(mode="json"),
                )
            )

    def integrity(self, *, synthetic: bool | None = None) -> list[dict]:
        query = select(BaselineRecord)
        if synthetic is not None:
            query = query.where(BaselineRecord.synthetic == synthetic)
        with self.database.sessions() as session:
            rows = session.scalars(query.order_by(BaselineRecord.hostname).limit(100)).all()
            result = []
            for row in rows:
                scan = session.scalar(
                    select(IntegrityScanRecord)
                    .where(IntegrityScanRecord.baseline_id == row.baseline_id)
                    .order_by(IntegrityScanRecord.timestamp.desc())
                    .limit(1)
                )
                result.append(
                    {
                        "baseline_id": row.baseline_id,
                        "hostname": row.hostname,
                        "synthetic": row.synthetic,
                        "created_at": row.payload["created_at"],
                        "roots": row.payload["roots"],
                        "approved_by": row.payload["approved_by"],
                        "approval_note": row.payload["approval_note"],
                        "file_count": len(row.payload["entries"]),
                        "latest_scan": scan.payload if scan else None,
                    }
                )
            return result

    def cleanup_unlinked(self, before: datetime) -> int:
        """Explicit maintenance only; alert-linked evidence is never removed by this operation."""
        with self.database.sessions.begin() as session:
            result = session.execute(
                delete(EventRecord).where(
                    EventRecord.timestamp < utc_key(before),
                    EventRecord.event_id.not_in(select(EvidenceLink.event_id)),
                )
            )
            return result.rowcount

    def create_incident(
        self,
        alert_ids: list[UUID],
        *,
        title: str,
        summary: str,
        analyst: str,
        analyst_findings: str = "No analyst interpretation recorded.",
        status: AlertStatus = AlertStatus.INVESTIGATING,
    ):
        from scry_security.reports.incident_report import build_report

        if not 1 <= len(alert_ids) <= 100 or len(set(alert_ids)) != len(alert_ids):
            raise ValueError("Select between 1 and 100 unique alerts")
        with self.database.sessions.begin() as session:
            alerts = []
            events = []
            for alert_id in alert_ids:
                row = session.get(AlertRecord, str(alert_id))
                if row is None:
                    raise KeyError("Incident alert not found")
                alerts.append(Alert.model_validate(row.payload))
                events.extend(SecurityEvent.model_validate(item.payload) for item in row.events)
            report = build_report(
                alerts,
                events,
                title=title,
                summary=summary,
                analyst=analyst,
                analyst_findings=analyst_findings,
                status=status,
            )
            session.add(
                IncidentRecord(
                    incident_id=str(report.incident_id),
                    title=report.title,
                    status=report.status.value,
                    payload=report.model_dump(mode="json"),
                )
            )
            session.flush()
            session.add_all(
                [
                    IncidentAlertLink(incident_id=str(report.incident_id), alert_id=str(alert_id))
                    for alert_id in alert_ids
                ]
            )
            return report

    def incident(self, incident_id: UUID) -> IncidentReport | None:
        with self.database.sessions() as session:
            row = session.get(IncidentRecord, str(incident_id))
            return IncidentReport.model_validate(row.payload) if row else None

    def incidents(
        self, *, synthetic: bool | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("Invalid incident page")
        query = select(IncidentRecord)
        if synthetic is not None:
            query = query.where(IncidentRecord.payload["synthetic"].as_boolean().is_(synthetic))
        with self.database.sessions() as session:
            rows = session.scalars(
                query.order_by(IncidentRecord.payload["created_at"].as_string().desc())
                .limit(limit)
                .offset(offset)
            ).all()
            return [
                {
                    "incident_id": row.incident_id,
                    "title": row.title,
                    "status": row.status,
                    "synthetic": row.payload["synthetic"],
                    "created_at": row.payload["created_at"],
                    "affected_hosts": row.payload["affected_hosts"],
                }
                for row in rows
            ]
