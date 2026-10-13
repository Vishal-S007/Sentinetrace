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
    DetectionRule,
    DetectionRuleVersion,
    DetectionRun,
    Event,
    User,
)
from app.schemas.detection import (
    AlertDetailOut,
    AlertOut,
    AlertPage,
    AlertStatus,
    DetectionRunCreate,
    DetectionRunOut,
    EvidenceEventOut,
    EvidencePage,
    RuleDetailOut,
    RuleOut,
    RuleUpdate,
    RuleVersionOut,
    Severity,
)
from app.services import audit

router = APIRouter(tags=["detection"])
RuleReader = Annotated[AuthContext, Depends(require(Permission.RULES_READ))]
RuleManager = Annotated[AuthContext, Depends(require(Permission.RULES_MANAGE))]
AlertReader = Annotated[AuthContext, Depends(require(Permission.ALERTS_READ))]


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


def _alert_out(a: Alert) -> AlertOut:
    out = AlertOut.model_validate(a)
    out.rule_name = RULES[a.rule_id].name if a.rule_id in RULES else a.rule_id
    return out


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    _: AlertReader,
    db: DbSession,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    rule_id: Annotated[str | None, Query(max_length=32)] = None,
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    before_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AlertPage:
    stmt = select(Alert).order_by(Alert.id.desc())
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if source_ip:
        try:
            ip = str(ipaddress.ip_address(source_ip))
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "source_ip must be a valid IP address"
            ) from exc
        stmt = stmt.where(Alert.source_ip == ip)
    if since:
        stmt = stmt.where(Alert.last_seen >= since)
    if until:
        stmt = stmt.where(Alert.first_seen < until)
    if before_id:
        stmt = stmt.where(Alert.id < before_id)
    rows = list(db.scalars(stmt.limit(limit + 1)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AlertPage(
        items=[_alert_out(a) for a in rows], next_before_id=rows[-1].id if has_more else None
    )


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
