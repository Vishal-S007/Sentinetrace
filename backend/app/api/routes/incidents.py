"""Incidents: group related alerts, track ownership and status, record notes and actions,
review the timeline and export a report."""

import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, DbSession, require
from app.api.routes.detection import alerts_out
from app.core.permissions import Permission
from app.models import Alert, Incident, IncidentAlert
from app.models.detection import SEVERITIES
from app.models.incidents import CLOSED_INCIDENT_STATUSES
from app.schemas.detection import NoteCreate, NoteOut, Severity
from app.schemas.incidents import (
    IncidentCreate,
    IncidentDetailOut,
    IncidentPage,
    IncidentStatus,
    IncidentUpdate,
    LinkAlerts,
)
from app.services import audit
from app.services.incident_report import build_timeline, render_markdown, report_data
from app.services.notes import add_note, list_notes, note_out
from app.services.people import assignee as validate_assignee
from app.services.people import usernames

router = APIRouter(prefix="/incidents", tags=["incidents"])
Reader = Annotated[AuthContext, Depends(require(Permission.INCIDENTS_READ))]
Manager = Annotated[AuthContext, Depends(require(Permission.INCIDENTS_MANAGE))]
Exporter = Annotated[
    AuthContext, Depends(require(Permission.INCIDENTS_READ, Permission.REPORTS_EXPORT))
]
MAX_ALERTS_PER_INCIDENT = 1000


def _get(db: Session, incident_id: int, *, lock: bool = False) -> Incident:
    stmt = select(Incident).where(Incident.id == incident_id)
    if lock:
        stmt = stmt.with_for_update()
    inc = db.scalar(stmt)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return inc


def _alert_counts(db: Session, ids: list[int]) -> dict[int, int]:
    if not ids:
        return {}
    return dict(
        db.execute(
            select(IncidentAlert.incident_id, func.count())
            .where(IncidentAlert.incident_id.in_(ids))
            .group_by(IncidentAlert.incident_id)
        ).all()
    )


def _out(inc: Incident, names: dict[int, str], alert_count: int) -> dict[str, Any]:
    return {
        "id": inc.id,
        "title": inc.title,
        "summary": inc.summary,
        "status": inc.status,
        "severity": inc.severity,
        "assigned_to": inc.assigned_to,
        "assignee": names.get(inc.assigned_to) if inc.assigned_to else None,
        "created_by": names.get(inc.created_by, "unknown"),
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "closed_at": inc.closed_at,
        "alert_count": alert_count,
    }


def _load_alerts(db: Session, ids: list[int]) -> list[Alert]:
    unique = sorted(set(ids))
    found = list(db.scalars(select(Alert).where(Alert.id.in_(unique))).all()) if unique else []
    missing = sorted(set(unique) - {a.id for a in found})
    if missing:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Unknown alert id(s): {', '.join(map(str, missing[:20]))}",
        )
    return found


def _link(db: Session, inc: Incident, alerts: list[Alert], user_id: int) -> list[int]:
    """Link alerts not already linked; returns the newly linked ids."""
    existing = set(
        db.scalars(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == inc.id)).all()
    )
    new = [a.id for a in alerts if a.id not in existing]
    if len(existing) + len(new) > MAX_ALERTS_PER_INCIDENT:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"An incident can hold at most {MAX_ALERTS_PER_INCIDENT} alerts",
        )
    for alert_id in new:
        db.add(IncidentAlert(incident_id=inc.id, alert_id=alert_id, linked_by=user_id))
    return new


def _detail(db: Session, inc: Incident) -> dict[str, Any]:
    alerts = list(
        db.scalars(
            select(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == inc.id)
            .order_by(Alert.first_seen, Alert.id)
        ).all()
    )
    names = usernames(db, [inc.assigned_to, inc.created_by])
    alert_items = alerts_out(db, alerts)
    notes = list_notes(db, incident_id=inc.id)
    return {
        **_out(inc, names, len(alerts)),
        "alerts": alert_items,
        "notes": notes,
        "timeline": build_timeline(db, inc, alert_items, notes),
    }


@router.get("", response_model=IncidentPage)
def list_incidents(
    auth: Reader,
    db: DbSession,
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    assigned_to: Annotated[
        str | None, Query(max_length=12, pattern=r"^(me|none|[1-9][0-9]*)$")
    ] = None,
    q: Annotated[str | None, Query(min_length=2, max_length=200)] = None,
    open_only: Annotated[bool, Query(description="Exclude resolved and closed")] = False,
    before_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    stmt = select(Incident).order_by(Incident.id.desc())
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if open_only:
        stmt = stmt.where(Incident.status.not_in(CLOSED_INCIDENT_STATUSES))
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if assigned_to == "me":
        stmt = stmt.where(Incident.assigned_to == auth.user.id)
    elif assigned_to == "none":
        stmt = stmt.where(Incident.assigned_to.is_(None))
    elif assigned_to:
        stmt = stmt.where(Incident.assigned_to == int(assigned_to))
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(Incident.title.ilike(f"%{escaped}%", escape="\\"))
    if before_id:
        stmt = stmt.where(Incident.id < before_id)
    rows = list(db.scalars(stmt.limit(limit + 1)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    names = usernames(db, [u for r in rows for u in (r.assigned_to, r.created_by)])
    counts = _alert_counts(db, [r.id for r in rows])
    return {
        "items": [_out(r, names, counts.get(r.id, 0)) for r in rows],
        "next_before_id": rows[-1].id if has_more else None,
    }


@router.post("", response_model=IncidentDetailOut, status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate, auth: Manager, request: Request, db: DbSession
) -> dict[str, Any]:
    alerts = _load_alerts(db, body.alert_ids)
    owner = validate_assignee(db, body.assigned_to)
    severity = body.severity
    if severity is None:
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        severity = max((a.severity for a in alerts), key=rank.__getitem__, default="medium")
    inc = Incident(
        title=body.title,
        summary=body.summary,
        severity=severity,
        assigned_to=owner.id if owner else None,
        created_by=auth.user.id,
    )
    db.add(inc)
    db.flush()
    linked = _link(db, inc, alerts, auth.user.id)
    audit.record(
        db,
        "incident.create",
        actor=auth.user,
        target_type="incident",
        target_id=inc.id,
        request=request,
        details={
            "title": inc.title,
            "severity": inc.severity,
            "alert_ids": linked,
            "assignee": owner.username if owner else None,
        },
    )
    db.commit()
    db.refresh(inc)
    return _detail(db, inc)


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident(incident_id: int, _: Reader, db: DbSession) -> dict[str, Any]:
    return _detail(db, _get(db, incident_id))


@router.patch("/{incident_id}", response_model=IncidentDetailOut)
def update_incident(
    incident_id: int, body: IncidentUpdate, auth: Manager, request: Request, db: DbSession
) -> dict[str, Any]:
    inc = _get(db, incident_id, lock=True)
    changes: dict[str, dict[str, Any]] = {}
    for field in ("title", "summary", "status", "severity"):
        new = getattr(body, field)
        if new is not None and getattr(inc, field) != new:
            old = getattr(inc, field)
            changes[field] = (
                {"from": None, "to": None} if field == "summary" else {"from": old, "to": new}
            )
            setattr(inc, field, new)
    if "assigned_to" in body.model_fields_set and inc.assigned_to != body.assigned_to:
        owner = validate_assignee(db, body.assigned_to)
        before = usernames(db, [inc.assigned_to]).get(inc.assigned_to) if inc.assigned_to else None
        changes["assignee"] = {"from": before, "to": owner.username if owner else None}
        inc.assigned_to = body.assigned_to
    if "status" in changes:
        if inc.status in CLOSED_INCIDENT_STATUSES and inc.closed_at is None:
            inc.closed_at = func.now()
        elif inc.status not in CLOSED_INCIDENT_STATUSES:
            inc.closed_at = None
    if changes:
        inc.updated_at = func.now()
        audit.record(
            db,
            "incident.update",
            actor=auth.user,
            target_type="incident",
            target_id=inc.id,
            request=request,
            details={"changes": changes, "note": body.note},
        )
        db.commit()
        db.refresh(inc)
    return _detail(db, inc)


@router.post("/{incident_id}/alerts", response_model=IncidentDetailOut)
def link_alerts(
    incident_id: int, body: LinkAlerts, auth: Manager, request: Request, db: DbSession
) -> dict[str, Any]:
    inc = _get(db, incident_id, lock=True)
    linked = _link(db, inc, _load_alerts(db, body.alert_ids), auth.user.id)
    if linked:
        inc.updated_at = func.now()
        audit.record(
            db,
            "incident.link_alerts",
            actor=auth.user,
            target_type="incident",
            target_id=inc.id,
            request=request,
            details={"alert_ids": linked},
        )
        db.commit()
        db.refresh(inc)
    return _detail(db, inc)


@router.delete("/{incident_id}/alerts/{alert_id}", response_model=IncidentDetailOut)
def unlink_alert(
    incident_id: int, alert_id: int, auth: Manager, request: Request, db: DbSession
) -> dict[str, Any]:
    inc = _get(db, incident_id, lock=True)
    link = db.get(IncidentAlert, (inc.id, alert_id))
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert is not linked to this incident")
    db.delete(link)
    inc.updated_at = func.now()
    audit.record(
        db,
        "incident.unlink_alert",
        actor=auth.user,
        target_type="incident",
        target_id=inc.id,
        request=request,
        details={"alert_id": alert_id},
    )
    db.commit()
    db.refresh(inc)
    return _detail(db, inc)


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def create_incident_note(
    incident_id: int, body: NoteCreate, auth: Manager, request: Request, db: DbSession
) -> NoteOut:
    inc = _get(db, incident_id, lock=True)
    note = add_note(db, body, auth.user, incident_id=inc.id)
    inc.updated_at = func.now()
    audit.record(
        db,
        "incident.note",
        actor=auth.user,
        target_type="incident",
        target_id=inc.id,
        request=request,
        details={"note_id": note.id, "kind": note.kind},
    )
    db.commit()
    return note_out(note, {auth.user.id: auth.user.username})


@router.get(
    "/{incident_id}/report",
    responses={200: {"content": {"text/markdown": {}, "application/json": {}}}},
)
def export_report(
    incident_id: int,
    auth: Exporter,
    request: Request,
    db: DbSession,
    format: Annotated[Literal["markdown", "json"], Query()] = "markdown",  # noqa: A002
) -> Response:
    """Download a report: details, linked alerts with evidence samples, timeline and notes."""
    inc = _get(db, incident_id)
    data = report_data(db, _detail(db, inc), auth.user.username)
    audit.record(
        db,
        "incident.export",
        actor=auth.user,
        target_type="incident",
        target_id=inc.id,
        request=request,
        details={"format": format},
    )
    db.commit()
    if format == "json":
        body = json.dumps(data, default=str, indent=2, ensure_ascii=False)
        media, ext = "application/json", "json"
    else:
        body, media, ext = render_markdown(data), "text/markdown; charset=utf-8", "md"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="incident-{inc.id}-report.{ext}"'},
    )
