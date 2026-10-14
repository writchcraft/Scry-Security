"""Indexed investigation dimensions plus versioned canonical evidence payloads."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class HostRecord(Base):
    __tablename__ = "hosts"
    host_id: Mapped[str] = mapped_column(String(1100), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(1024), index=True)
    operating_system: Mapped[str] = mapped_column(String(16), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, index=True)
    events: Mapped[list[EventRecord]] = relationship(back_populates="host")


class EventRecord(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.host_id"), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    host: Mapped[HostRecord] = relationship(back_populates="events")


class RuleRecord(Base):
    __tablename__ = "rules"
    rule_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class AlertRecord(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(36), unique=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.rule_id"), index=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    hostname: Mapped[str] = mapped_column(String(1024), index=True)
    operating_system: Mapped[str] = mapped_column(String(16), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    events: Mapped[list[EventRecord]] = relationship(secondary="alert_evidence")


class EvidenceLink(Base):
    __tablename__ = "alert_evidence"
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.event_id"), primary_key=True)


class ConfigurationRecord(Base):
    __tablename__ = "configuration"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class IncidentRecord(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class IncidentAlertLink(Base):
    __tablename__ = "incident_alerts"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id"), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"), primary_key=True)


class BaselineRecord(Base):
    __tablename__ = "file_baselines"
    baseline_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(1024), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class IntegrityScanRecord(Base):
    __tablename__ = "integrity_scans"
    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    baseline_id: Mapped[str] = mapped_column(ForeignKey("file_baselines.baseline_id"), index=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
