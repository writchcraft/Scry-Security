"""Application factory: no database or web server is started at import time."""

import secrets
from datetime import UTC, datetime
from importlib.resources import files
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi import Path as ApiPath
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scry_security.alerts.manager import AlertStatus
from scry_security.api.security import RequestBudgetMiddleware
from scry_security.core.event_schema import SecurityEvent
from scry_security.database.models import AlertRecord, EventRecord, HostRecord, IncidentRecord
from scry_security.database.repositories import ConcurrentUpdateError, Store, utc_key
from scry_security.detection.loader import load_rules
from scry_security.detection.rules import Severity
from scry_security.reports.report_generator import export_report


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: AlertStatus
    actor: str = Field(min_length=1, max_length=200)
    note: str = Field(min_length=1, max_length=4000)
    expected_revision: int | None = Field(default=None, ge=1)


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    alert_ids: list[UUID] = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=8000)
    analyst: str = Field(min_length=1, max_length=200)
    analyst_findings: str = Field(default="No analyst interpretation recorded.", max_length=16_000)
    status: AlertStatus = AlertStatus.INVESTIGATING


def create_app(store: Store, token: str) -> FastAPI:
    if len(token) < 32:
        raise ValueError("API token must contain at least 32 characters")
    app = FastAPI(title="Scry-Security", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"]
    )
    bearer = HTTPBearer(auto_error=False)
    app.add_middleware(RequestBudgetMiddleware)

    def authenticate(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if credentials is None or not secrets.compare_digest(
            credentials.credentials.encode(), token.encode()
        ):
            raise HTTPException(
                401, "Valid bearer token required", headers={"WWW-Authenticate": "Bearer"}
            )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    assets = files("scry_security").joinpath("dashboard")
    app.mount("/static", StaticFiles(directory=str(assets.joinpath("static"))), name="static")

    @app.get("/")
    def dashboard():
        return FileResponse(str(assets.joinpath("index.html")))

    auth = [Depends(authenticate)]

    @app.get("/api/summary", dependencies=auth)
    def summary(synthetic: bool | None = None):
        with store.database.sessions() as session:
            event_query = select(EventRecord).join(HostRecord)
            alert_query = select(AlertRecord)
            if synthetic is not None:
                event_query = event_query.where(HostRecord.synthetic == synthetic)
                alert_query = alert_query.where(AlertRecord.synthetic == synthetic)
            events = event_query.subquery()
            alerts = alert_query.subquery()
            event_types = dict(
                session.execute(
                    select(events.c.event_type, func.count()).group_by(events.c.event_type)
                ).all()
            )
            severities = dict(
                session.execute(
                    select(alerts.c.severity, func.count()).group_by(alerts.c.severity)
                ).all()
            )
            statuses = dict(
                session.execute(
                    select(alerts.c.status, func.count()).group_by(alerts.c.status)
                ).all()
            )
            os_query = select(
                HostRecord.operating_system, func.count(func.distinct(HostRecord.host_id))
            )
            os_query = os_query.join(EventRecord)
            if synthetic is not None:
                os_query = os_query.where(HostRecord.synthetic == synthetic)
            hosts = dict(session.execute(os_query.group_by(HostRecord.operating_system)).all())
            timeline = session.execute(
                select(func.substr(events.c.timestamp, 1, 13), func.count())
                .where(
                    events.c.event_type.in_(["authentication_failure", "authentication_success"])
                )
                .group_by(func.substr(events.c.timestamp, 1, 13))
                .order_by(func.substr(events.c.timestamp, 1, 13).desc())
                .limit(24)
            ).all()
            source = alerts.c.payload["source_ip"].as_string()
            top_sources = session.execute(
                select(source, func.count())
                .where(source.is_not(None))
                .group_by(source)
                .order_by(func.count().desc())
                .limit(5)
            ).all()
            synthetic_count = session.scalar(
                select(func.count())
                .select_from(events)
                .where(events.c.payload["synthetic"].as_boolean().is_(True))
            )
            return {
                "total_events": sum(event_types.values()),
                "events_analysed": sum(event_types.values()),
                "total_alerts": sum(severities.values()),
                "severity": severities,
                "statuses": statuses,
                "hosts": hosts,
                "authentication_failures": event_types.get("authentication_failure", 0),
                "network_alerts": session.scalar(
                    select(func.count())
                    .select_from(alerts)
                    .where(alerts.c.rule_id.like("SCRY-NETWORK-%"))
                ),
                "synthetic_events": synthetic_count,
                "authentication_timeline": [
                    {"hour": hour + ":00Z", "count": count} for hour, count in reversed(timeline)
                ],
                "top_sources": [
                    {"address": address, "count": count} for address, count in top_sources
                ],
                "incident_count": session.scalar(
                    select(func.count())
                    .select_from(IncidentRecord)
                    .where(
                        IncidentRecord.payload["synthetic"].as_boolean().is_(synthetic)
                        if synthetic is not None
                        else True
                    )
                ),
            }

    @app.get("/api/events", dependencies=auth)
    def events(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        synthetic: bool | None = None,
        operating_system: Literal["windows", "linux"] | None = None,
        category: str | None = None,
        hostname: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ):
        query = select(EventRecord).join(HostRecord)
        for field, value in {
            "synthetic": synthetic,
            "operating_system": operating_system,
            "hostname": hostname,
        }.items():
            if value is not None:
                query = query.where(getattr(HostRecord, field) == value)
        if category is not None:
            query = query.where(EventRecord.payload["category"].as_string() == category)
        try:
            if since is not None:
                query = query.where(EventRecord.timestamp >= utc_key(since))
            if until is not None:
                query = query.where(EventRecord.timestamp <= utc_key(until))
        except ValueError as exc:
            raise HTTPException(422, "Dates require a UTC offset") from exc
        with store.database.sessions() as session:
            rows = session.scalars(
                query.order_by(EventRecord.timestamp.desc(), EventRecord.event_id)
                .limit(limit)
                .offset(offset)
            ).all()
            return [SecurityEvent.model_validate(row.payload) for row in rows]

    @app.get("/api/alerts", dependencies=auth)
    def alerts(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        operating_system: Literal["windows", "linux"] | None = None,
        hostname: str | None = None,
        rule_id: str | None = None,
        synthetic: bool | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ):
        try:
            return store.alerts(
                limit=limit,
                offset=offset,
                severity=severity,
                status=status,
                operating_system=operating_system,
                hostname=hostname,
                rule_id=rule_id,
                synthetic=synthetic,
                since=since,
                until=until,
            )
        except ValueError as exc:
            raise HTTPException(422, "Invalid alert filters; dates require UTC offsets") from exc

    @app.get("/api/alerts/{alert_id}", dependencies=auth)
    def alert(alert_id: UUID):
        record = store.alert(alert_id)
        if record is None:
            raise HTTPException(404, "Alert not found")
        return {"alert": record, "events": store.supporting_events(alert_id)}

    @app.patch("/api/alerts/{alert_id}/status", dependencies=auth)
    def status(alert_id: UUID, update: StatusUpdate):
        try:
            return store.set_status(
                alert_id,
                update.status,
                actor=update.actor,
                note=update.note,
                expected_revision=update.expected_revision,
            )
        except ConcurrentUpdateError as exc:
            raise HTTPException(409, "Alert changed; reopen the case before updating") from exc
        except KeyError as exc:
            raise HTTPException(404, "Alert not found") from exc
        except ValueError as exc:
            raise HTTPException(
                422, "A new status, actor and meaningful note are required"
            ) from exc

    @app.get("/api/rules", dependencies=auth)
    def rules():
        return load_rules()

    @app.get("/api/hosts", dependencies=auth)
    def hosts():
        with store.database.sessions() as session:
            rows = session.scalars(
                select(HostRecord).order_by(HostRecord.hostname).limit(1000)
            ).all()
            return [
                {
                    "hostname": row.hostname,
                    "operating_system": row.operating_system,
                    "synthetic": row.synthetic,
                }
                for row in rows
            ]

    @app.post("/api/incidents", dependencies=auth, status_code=201)
    def create_incident(request: IncidentCreate):
        try:
            return store.create_incident(**request.model_dump())
        except KeyError as exc:
            raise HTTPException(404, "Selected alert not found") from exc
        except ValueError as exc:
            raise HTTPException(422, "Invalid incident scope, evidence or report limits") from exc

    @app.get("/api/incidents", dependencies=auth)
    def incidents(
        synthetic: bool | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return store.incidents(synthetic=synthetic, limit=limit, offset=offset)

    @app.get("/api/incidents/{incident_id}", dependencies=auth)
    def incident(incident_id: UUID):
        report = store.incident(incident_id)
        if report is None:
            raise HTTPException(404, "Incident not found")
        return report

    @app.get("/api/incidents/{incident_id}/export", dependencies=auth)
    def incident_export(incident_id: UUID, format: Literal["json", "csv", "html"] = "json"):
        report = store.incident(incident_id)
        if report is None:
            raise HTTPException(404, "Incident not found")
        return Response(
            export_report(report, format),
            media_type={"json": "application/json", "csv": "text/csv", "html": "text/html"}[format],
            headers={"Content-Disposition": f'attachment; filename="scry-{incident_id}.{format}"'},
        )

    @app.get("/api/integrity", dependencies=auth)
    def integrity(synthetic: bool | None = None):
        return store.integrity(synthetic=synthetic)

    @app.get("/api/sources", dependencies=auth)
    def sources():
        records = store.source_health()
        for record in records:
            elapsed = (
                datetime.now(UTC) - datetime.fromisoformat(record["last_checked"])
            ).total_seconds()
            record["stale"] = elapsed > record["stale_after_seconds"]
        return records

    @app.get("/api/policy", dependencies=auth)
    def policy():
        return store.configuration("detection-policy") or {"policy_id": "unconfigured", "hosts": []}

    @app.get("/api/policies/{digest}", dependencies=auth)
    def policy_snapshot(digest: Annotated[str, ApiPath(pattern=r"^[0-9a-f]{64}$")]):
        snapshot = store.configuration(f"policy:{digest}")
        if snapshot is None:
            raise HTTPException(404, "Policy snapshot not found")
        return snapshot

    return app
