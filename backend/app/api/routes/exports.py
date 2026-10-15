"""CSV/JSON exports of alerts, events and the audit trail.

Each export applies exactly the same filters as its list endpoint, is capped, and is
recorded in the audit trail with its filters and row count. Registered before the
resource routers so `/alerts/export` is not taken for an alert id.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api.deps import AppSettings, AuthContext, DbSession, require
from app.api.routes.audit import AuditFilters
from app.api.routes.detection import AlertFilters
from app.api.routes.events import EventFilters
from app.core.permissions import Permission
from app.detection.registry import RULES
from app.models import Alert, AuditLog, Event, LogSource, User
from app.services import audit
from app.services.exports import ExportFormat, export_response, query_filters, write_export
from app.services.limits import enforce_export_rate

router = APIRouter(tags=["exports"])

ALERT_CAP = 50_000
EVENT_CAP = 100_000
AUDIT_CAP = 100_000
BATCH = 2_000

AlertExporter = Annotated[
    AuthContext, Depends(require(Permission.ALERTS_READ, Permission.REPORTS_EXPORT))
]
EventExporter = Annotated[
    AuthContext, Depends(require(Permission.EVENTS_READ, Permission.REPORTS_EXPORT))
]
AuditExporter = Annotated[
    AuthContext, Depends(require(Permission.AUDIT_READ, Permission.REPORTS_EXPORT))
]
Format = Annotated[ExportFormat, Query(description="csv or json")]

ALERT_COLUMNS = (
    "id", "rule_id", "rule_name", "title", "severity", "status", "confidence", "source_ip",
    "username", "endpoint", "first_seen", "last_seen", "event_count", "assignee",
    "created_at", "updated_at",
)  # fmt: skip
EVENT_COLUMNS = (
    "id", "event_time", "event_type", "source", "source_ip", "username", "http_method",
    "path", "query", "http_status", "bytes_sent", "user_agent", "host", "severity",
    "message", "raw_line",
)  # fmt: skip
AUDIT_COLUMNS = (
    "id", "occurred_at", "actor_username", "action", "target_type", "target_id", "ip",
    "request_id", "details",
)  # fmt: skip


def _record(db, request: Request, auth: AuthContext, kind: str, fmt: str, result) -> None:
    audit.record(
        db,
        f"export.{kind}",
        actor=auth.user,
        target_type="export",
        target_id=kind,
        request=request,
        details={
            "format": fmt,
            "rows": result.rows,
            "truncated": result.truncated,
            "filters": query_filters(request.query_params.multi_items(), lambda k: k == "format"),
        },
    )
    db.commit()


@router.get("/alerts/export", response_class=StreamingResponse)
def export_alerts(
    auth: AlertExporter,
    request: Request,
    db: DbSession,
    settings: AppSettings,
    conds: AlertFilters,
    format: Format = "csv",  # noqa: A002
) -> StreamingResponse:
    """Alerts matching the queue filters, newest first (at most 50,000)."""
    enforce_export_rate(db, auth.user, settings)
    stmt = (
        select(
            Alert.id,
            Alert.rule_id,
            Alert.title,
            Alert.severity,
            Alert.status,
            Alert.confidence,
            Alert.source_ip,
            Alert.username,
            Alert.endpoint,
            Alert.first_seen,
            Alert.last_seen,
            Alert.event_count,
            User.username,
            Alert.created_at,
            Alert.updated_at,
        )  # fmt: skip
        .outerjoin(User, User.id == Alert.assigned_to)
        .where(*conds)
        .order_by(Alert.id.desc())
        .limit(ALERT_CAP + 1)
    )
    rows = (
        (r[0], r[1], RULES[r[1]].name if r[1] in RULES else r[1], *r[2:])
        for r in db.execute(stmt).yield_per(BATCH)
    )
    result = write_export(format, ALERT_COLUMNS, rows, ALERT_CAP)
    _record(db, request, auth, "alerts", format, result)
    return export_response(result, format, "alerts")


@router.get("/events/export", response_class=StreamingResponse)
def export_events(
    auth: EventExporter,
    request: Request,
    db: DbSession,
    settings: AppSettings,
    conds: EventFilters,
    format: Format = "csv",  # noqa: A002
) -> StreamingResponse:
    """Events matching the explorer filters, newest first (at most 100,000)."""
    enforce_export_rate(db, auth.user, settings)
    stmt = (
        select(
            Event.id,
            Event.event_time,
            Event.event_type,
            LogSource.name,
            Event.source_ip,
            Event.username,
            Event.http_method,
            Event.path,
            Event.query,
            Event.http_status,
            Event.bytes_sent,
            Event.user_agent,
            Event.host,
            Event.severity,
            Event.message,
            Event.raw_line,
        )  # fmt: skip
        .join(LogSource, LogSource.id == Event.source_id)
        .where(*conds)
        .order_by(Event.event_time.desc(), Event.id.desc())
        .limit(EVENT_CAP + 1)
    )
    result = write_export(format, EVENT_COLUMNS, db.execute(stmt).yield_per(BATCH), EVENT_CAP)
    _record(db, request, auth, "events", format, result)
    return export_response(result, format, "events")


@router.get("/audit/export", response_class=StreamingResponse)
def export_audit(
    auth: AuditExporter,
    request: Request,
    db: DbSession,
    settings: AppSettings,
    conds: AuditFilters,
    format: Format = "csv",  # noqa: A002
) -> StreamingResponse:
    """Audit entries matching the audit log filters, newest first (at most 100,000)."""
    enforce_export_rate(db, auth.user, settings)
    stmt = (
        select(
            AuditLog.id,
            AuditLog.occurred_at,
            AuditLog.actor_username,
            AuditLog.action,
            AuditLog.target_type,
            AuditLog.target_id,
            AuditLog.ip,
            AuditLog.request_id,
            AuditLog.details,
        )  # fmt: skip
        .where(*conds)
        .order_by(AuditLog.id.desc())
        .limit(AUDIT_CAP + 1)
    )
    result = write_export(format, AUDIT_COLUMNS, db.execute(stmt).yield_per(BATCH), AUDIT_CAP)
    _record(db, request, auth, "audit", format, result)
    return export_response(result, format, "audit-log")
