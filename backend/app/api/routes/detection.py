"""Detection rules (view, versioned configuration changes), alerts with evidence, and runs."""

import ipaddress
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, DbSession, require
from app.core.permissions import Permission
from app.detection.registry import RULES
from app.detection.runs import enqueue_manual
from app.models import (
    Alert,
    AlertEvent,
    AuditLog,
    DetectionRule,
    DetectionRuleVersion,
    DetectionRun,
    Event,
    Incident,
    IncidentAlert,
    User,
)
from app.schemas.detection import (
    AlertActivityOut,
    AlertDetailOut,
    AlertOut,
    AlertPage,
    AlertStatus,
    AlertUpdate,
    AssignableUser,
    DetectionRunCreate,
    DetectionRunOut,
    EvidenceEventOut,
    EvidencePage,
    HistoryEntryOut,
    IncidentRef,
    NoteCreate,
    NoteOut,
    RuleDetailOut,
    RuleOut,
    RuleUpdate,
    RuleVersionOut,
    Severity,
)
from app.services import audit
from app.services.notes import add_note, list_notes, note_out
from app.services.people import assignee as validate_assignee
from app.services.people import can_be_assigned, usernames

router = APIRouter(tags=["detection"])
RuleReader = Annotated[AuthContext, Depends(require(Permission.RULES_READ))]
RuleManager = Annotated[AuthContext, Depends(require(Permission.RULES_MANAGE))]
AlertReader = Annotated[AuthContext, Depends(require(Permission.ALERTS_READ))]
AlertTriager = Annotated[AuthContext, Depends(require(Permission.ALERTS_TRIAGE))]


# --- Rules ------------------------------------------------------------------------------


def _usernames(db: Session, ids: set[int | None]) -> dict[int, str]:
    ids = {i for i in ids if i is not None}
    if not ids:
        return {}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all())


def _rule_out(
    db: Session, row: DetectionRule, open_alerts: int, names: dict[int, str]
) -> dict[str, Any]:
    cls = RULES[row.rule_id]
    return {
        "rule_id": row.rule_id,
        "name": cls.name,
        "category": cls.category,
        "description": cls.description,
        "severity": row.severity,
        "default_severity": cls.default_severity,
        "enabled": row.enabled,
        "version": row.version,
        "config": row.config,
        "default_config": cls.default_config(),
        "config_schema": cls.config_model.model_json_schema(),
        "recommended_steps": cls.recommended_steps,
        "updated_at": row.updated_at,
        "updated_by": names.get(row.updated_by) if row.updated_by else None,
        "open_alerts": open_alerts,
    }


def _open_alert_counts(db: Session) -> dict[str, int]:
    return dict(
        db.execute(
            select(Alert.rule_id, func.count())
            .where(Alert.status.in_(("new", "investigating")))
            .group_by(Alert.rule_id)
        ).all()
    )


def _get_rule(db: Session, rule_id: str) -> DetectionRule:
    row = db.get(DetectionRule, rule_id)
    if row is None or rule_id not in RULES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    return row


@router.get("/rules", response_model=list[RuleOut])
def list_rules(_: RuleReader, db: DbSession) -> list[dict[str, Any]]:
    rows = [
        r
        for r in db.scalars(select(DetectionRule).order_by(DetectionRule.rule_id)).all()
        if r.rule_id in RULES
    ]
    counts = _open_alert_counts(db)
    names = _usernames(db, {r.updated_by for r in rows})
    return [_rule_out(db, r, counts.get(r.rule_id, 0), names) for r in rows]


@router.get("/rules/{rule_id}", response_model=RuleDetailOut)
def get_rule(rule_id: str, _: RuleReader, db: DbSession) -> dict[str, Any]:
    row = _get_rule(db, rule_id)
    versions = db.scalars(
        select(DetectionRuleVersion)
        .where(DetectionRuleVersion.rule_id == rule_id)
        .order_by(DetectionRuleVersion.version.desc())
    ).all()
    names = _usernames(db, {row.updated_by, *(v.changed_by for v in versions)})
    out = _rule_out(db, row, _open_alert_counts(db).get(rule_id, 0), names)
    out["versions"] = [
        RuleVersionOut(
            version=v.version,
            enabled=v.enabled,
            severity=v.severity,  # type: ignore[arg-type]
            config=v.config,
            note=v.note,
            changed_at=v.changed_at,
            changed_by=names.get(v.changed_by) if v.changed_by else None,
        )
        for v in versions
    ]
    return out


@router.patch("/rules/{rule_id}", response_model=RuleDetailOut)
def update_rule(
    rule_id: str, body: RuleUpdate, auth: RuleManager, request: Request, db: DbSession
) -> dict[str, Any]:
    row = _get_rule(db, rule_id)
    cls = RULES[rule_id]
    new_config = row.config
    if body.config is not None:
        try:
            # Partial updates merge onto the current config; the result is fully validated.
            new_config = cls.config_model.model_validate({**row.config, **body.config}).model_dump()
        except ValidationError as exc:
            errors = [{"loc": ["body", "config", *e["loc"]], "msg": e["msg"]} for e in exc.errors()]
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, errors) from exc
    new_enabled = row.enabled if body.enabled is None else body.enabled
    new_severity = row.severity if body.severity is None else body.severity
    if (new_enabled, new_severity, new_config) == (row.enabled, row.severity, row.config):
        return get_rule(rule_id, auth, db)

    changes = {
        k: {"from": old, "to": new}
        for k, old, new in (
            ("enabled", row.enabled, new_enabled),
            ("severity", row.severity, new_severity),
            ("config", row.config, new_config),
        )
        if old != new
    }
    row.version += 1
    row.enabled, row.severity, row.config = new_enabled, new_severity, new_config
    row.updated_by = auth.user.id
    row.updated_at = func.now()
    db.add(
        DetectionRuleVersion(
            rule_id=rule_id,
            version=row.version,
            enabled=new_enabled,
            severity=new_severity,
            config=new_config,
            note=body.note,
            changed_by=auth.user.id,
        )
    )
    audit.record(
        db,
        "rule.update",
        actor=auth.user,
        target_type="detection_rule",
        target_id=rule_id,
        request=request,
        details={"version": row.version, "changes": changes, "note": body.note},
    )
    db.commit()
    return get_rule(rule_id, auth, db)


# --- Detection runs -----------------------------------------------------------------------


@router.post(
    "/detection/runs", response_model=DetectionRunOut, status_code=status.HTTP_202_ACCEPTED
)
def create_run(
    body: DetectionRunCreate, auth: RuleManager, request: Request, db: DbSession
) -> DetectionRun:
    run = enqueue_manual(db, auth.user.id, body.since, body.until)
    db.flush()
    audit.record(
        db,
        "detection.run",
        actor=auth.user,
        target_type="detection_run",
        target_id=run.id,
        request=request,
        details={
            "since": body.since.isoformat() if body.since else None,
            "until": body.until.isoformat() if body.until else None,
        },
    )
    db.commit()
    db.refresh(run)
    return run


@router.get("/detection/runs", response_model=list[DetectionRunOut])
def list_runs(
    _: RuleReader, db: DbSession, limit: Annotated[int, Query(ge=1, le=100)] = 20
) -> list[DetectionRun]:
    return list(
        db.scalars(select(DetectionRun).order_by(DetectionRun.id.desc()).limit(limit)).all()
    )


# --- Alerts ---------------------------------------------------------------------------------


def alerts_out(db: Session, rows: list[Alert]) -> list[AlertOut]:
    names = usernames(db, (a.assigned_to for a in rows))
    out = []
    for a in rows:
        item = AlertOut.model_validate(a)
        item.rule_name = RULES[a.rule_id].name if a.rule_id in RULES else a.rule_id
        item.assignee = names.get(a.assigned_to) if a.assigned_to else None
        out.append(item)
    return out


def alert_filters(
    auth: AlertReader,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    rule_id: Annotated[str | None, Query(max_length=32)] = None,
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    q: Annotated[
        str | None, Query(min_length=2, max_length=200, description="Substring of the alert title")
    ] = None,
    assigned_to: Annotated[
        str | None,
        Query(
            max_length=12, pattern=r"^(me|none|[1-9][0-9]*)$", description="me, none or a user id"
        ),
    ] = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Any]:
    """Shared by the alert queue and the alert export."""
    conds: list[Any] = []
    if status_filter:
        conds.append(Alert.status == status_filter)
    if severity:
        conds.append(Alert.severity == severity)
    if rule_id:
        conds.append(Alert.rule_id == rule_id)
    if source_ip:
        try:
            ip = str(ipaddress.ip_address(source_ip))
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "source_ip must be a valid IP address"
            ) from exc
        conds.append(Alert.source_ip == ip)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds.append(Alert.title.ilike(f"%{escaped}%", escape="\\"))
    if assigned_to == "me":
        conds.append(Alert.assigned_to == auth.user.id)
    elif assigned_to == "none":
        conds.append(Alert.assigned_to.is_(None))
    elif assigned_to:
        conds.append(Alert.assigned_to == int(assigned_to))
    if since:
        conds.append(Alert.last_seen >= since)
    if until:
        conds.append(Alert.first_seen < until)
    return conds


AlertFilters = Annotated[list[Any], Depends(alert_filters)]


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    _: AlertReader,
    db: DbSession,
    conds: AlertFilters,
    before_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AlertPage:
    stmt = select(Alert).where(*conds).order_by(Alert.id.desc())
    if before_id:
        stmt = stmt.where(Alert.id < before_id)
    rows = list(db.scalars(stmt.limit(limit + 1)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AlertPage(items=alerts_out(db, rows), next_before_id=rows[-1].id if has_more else None)


def _get_alert(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@router.get("/alerts/{alert_id}", response_model=AlertDetailOut)
def get_alert(alert_id: int, _: AlertReader, db: DbSession) -> AlertDetailOut:
    a = _get_alert(db, alert_id)
    out = AlertDetailOut.model_validate(a)
    out.rule_name = RULES[a.rule_id].name if a.rule_id in RULES else a.rule_id
    out.assignee = usernames(db, [a.assigned_to]).get(a.assigned_to) if a.assigned_to else None
    out.recommended_steps = RULES[a.rule_id].recommended_steps if a.rule_id in RULES else []
    out.evidence_count = (
        db.scalar(select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == a.id))
        or 0
    )
    return out


@router.get("/alerts/{alert_id}/evidence", response_model=EvidencePage)
def get_alert_evidence(
    alert_id: int,
    _: AlertReader,
    db: DbSession,
    after_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> EvidencePage:
    """Supporting events in time order, including each event's original log line."""
    a = _get_alert(db, alert_id)
    stmt = (
        select(Event, AlertEvent.indicator)
        .join(AlertEvent, AlertEvent.event_id == Event.id)
        .where(AlertEvent.alert_id == a.id)
        .order_by(Event.id)
    )
    if after_id:
        stmt = stmt.where(Event.id > after_id)
    rows = db.execute(stmt.limit(limit + 1)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    total = (
        db.scalar(select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == a.id))
        or 0
    )
    return EvidencePage(
        items=[
            EvidenceEventOut(
                event_id=e.id,
                indicator=ind,
                event_time=e.event_time,
                event_type=e.event_type,
                source_ip=str(e.source_ip) if e.source_ip else None,
                username=e.username,
                http_method=e.http_method,
                path=e.path,
                query=e.query,
                http_status=e.http_status,
                user_agent=e.user_agent,
                source_id=e.source_id,
                file_id=e.file_id,
                line_number=e.line_number,
                raw_line=e.raw_line,
            )
            for e, ind in rows
        ],
        next_after_id=rows[-1][0].id if has_more else None,
        total_linked=total,
        total_events=a.event_count,
        truncated=a.evidence_truncated,
    )


@router.patch("/alerts/{alert_id}", response_model=AlertDetailOut)
def update_alert(
    alert_id: int, body: AlertUpdate, auth: AlertTriager, request: Request, db: DbSession
) -> AlertDetailOut:
    """Change an alert's status and/or assignee. Every change is recorded in the audit trail."""
    a = _get_alert(db, alert_id)
    changed = False
    if body.status is not None and a.status != body.status:
        previous = a.status
        a.status = body.status
        audit.record(
            db,
            "alert.status_change",
            actor=auth.user,
            target_type="alert",
            target_id=a.id,
            request=request,
            details={"from": previous, "to": body.status, "note": body.note, "rule_id": a.rule_id},
        )
        changed = True
    if "assigned_to" in body.model_fields_set and a.assigned_to != body.assigned_to:
        new_owner = validate_assignee(db, body.assigned_to)
        names = usernames(db, [a.assigned_to])
        audit.record(
            db,
            "alert.assign",
            actor=auth.user,
            target_type="alert",
            target_id=a.id,
            request=request,
            details={
                "from": names.get(a.assigned_to) if a.assigned_to else None,
                "to": new_owner.username if new_owner else None,
                "note": body.note,
            },
        )
        a.assigned_to = body.assigned_to
        changed = True
    if changed:
        db.commit()
        db.refresh(a)
    return get_alert(alert_id, auth, db)


@router.get("/alerts/{alert_id}/activity", response_model=AlertActivityOut)
def get_alert_activity(alert_id: int, _: AlertReader, db: DbSession) -> AlertActivityOut:
    """Notes, the alert's change history (from the audit trail) and incidents that include it."""
    a = _get_alert(db, alert_id)
    history = db.scalars(
        select(AuditLog)
        .where(AuditLog.target_type == "alert", AuditLog.target_id == str(a.id))
        .order_by(AuditLog.id)
        .limit(1000)
    ).all()
    incidents = db.scalars(
        select(Incident)
        .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
        .where(IncidentAlert.alert_id == a.id)
        .order_by(Incident.id)
    ).all()
    return AlertActivityOut(
        notes=list_notes(db, alert_id=a.id),
        history=[
            HistoryEntryOut(
                id=h.id,
                occurred_at=h.occurred_at,
                actor=h.actor_username,
                action=h.action,
                details=h.details,
            )
            for h in history
        ],
        incidents=[
            IncidentRef(id=i.id, title=i.title, status=i.status, severity=i.severity)  # type: ignore[arg-type]
            for i in incidents
        ],
    )


@router.post(
    "/alerts/{alert_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED
)
def create_alert_note(
    alert_id: int, body: NoteCreate, auth: AlertTriager, request: Request, db: DbSession
) -> NoteOut:
    a = _get_alert(db, alert_id)
    note = add_note(db, body, auth.user, alert_id=a.id)
    audit.record(
        db,
        "alert.note",
        actor=auth.user,
        target_type="alert",
        target_id=a.id,
        request=request,
        details={"note_id": note.id, "kind": note.kind},
    )
    db.commit()
    return note_out(note, {auth.user.id: auth.user.username})


@router.get("/assignees", response_model=list[AssignableUser])
def list_assignees(_: AlertTriager, db: DbSession) -> list[AssignableUser]:
    """Active users who may own alerts and incidents."""
    users = db.scalars(
        select(User).where(User.is_active.is_(True)).order_by(User.username).limit(1000)
    ).all()
    return [
        AssignableUser(id=u.id, username=u.username, role=u.role.name)
        for u in users
        if can_be_assigned(u)
    ]
