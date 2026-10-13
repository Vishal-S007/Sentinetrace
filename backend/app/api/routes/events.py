"""Event explorer: server-side filtering, text search and keyset pagination."""

import base64
import ipaddress
import re
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, case, exists, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, DbSession, require
from app.core.permissions import Permission
from app.ingestion.types import EVENT_TYPES
from app.models import Alert, AlertEvent, Event, ImportedFile, LogSource
from app.schemas.explorer import EventDetail, EventPage

router = APIRouter(prefix="/events", tags=["events"])
Reader = Annotated[AuthContext, Depends(require(Permission.EVENTS_READ))]

COUNT_CAP = 10_000
SEVERITIES = ("low", "medium", "high", "critical")
_STATUS_CLASS = re.compile(r"^([1-5])xx$")


def _bad(msg: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, msg)


def encode_cursor(ts: datetime, event_id: int) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{event_id}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, eid = raw.rsplit("|", 1)
        return datetime.fromisoformat(ts), int(eid)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _bad("invalid cursor") from exc


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_filters(
    q: str | None,
    since: datetime | None,
    until: datetime | None,
    source_ip: str | None,
    event_type: str | None,
    http_status: str | None,
    method: str | None,
    username: str | None,
    source_id: int | None,
    flagged: bool | None,
    alert_severity: str | None,
    alert_id: int | None,
) -> list[Any]:
    conds: list[Any] = []
    if q:
        conds.append(Event.raw_line.ilike(f"%{_like_escape(q)}%", escape="\\"))
    if since:
        conds.append(Event.event_time >= since)
    if until:
        conds.append(Event.event_time < until)
    if source_ip:
        try:
            if "/" in source_ip:
                net = ipaddress.ip_network(source_ip, strict=False)
                conds.append(Event.source_ip.op("<<=")(str(net)))
            else:
                conds.append(Event.source_ip == str(ipaddress.ip_address(source_ip)))
        except ValueError as exc:
            raise _bad("source_ip must be an IP address or CIDR network") from exc
    if event_type:
        if event_type not in EVENT_TYPES:
            raise _bad(f"event_type must be one of {', '.join(EVENT_TYPES)}")
        conds.append(Event.event_type == event_type)
    if http_status:
        m = _STATUS_CLASS.match(http_status.lower())
        if m:
            base = int(m.group(1)) * 100
            conds.append(Event.http_status.between(base, base + 99))
        elif http_status.isdigit() and 100 <= int(http_status) <= 599:
            conds.append(Event.http_status == int(http_status))
        else:
            raise _bad("http_status must be a code (e.g. 404) or a class (e.g. 4xx)")
    if method:
        conds.append(Event.http_method == method.upper())
    if username:
        conds.append(Event.username == username)
    if source_id:
        conds.append(Event.source_id == source_id)
    linked = select(AlertEvent.event_id).where(AlertEvent.event_id == Event.id)
    if flagged is True:
        conds.append(exists(linked))
    elif flagged is False:
        conds.append(~exists(linked))
    if alert_severity:
        if alert_severity not in SEVERITIES:
            raise _bad(f"alert_severity must be one of {', '.join(SEVERITIES)}")
        conds.append(
            exists(
                select(AlertEvent.event_id)
                .join(Alert, Alert.id == AlertEvent.alert_id)
                .where(AlertEvent.event_id == Event.id, Alert.severity == alert_severity)
            )
        )
    if alert_id:
        conds.append(
            exists(
                select(AlertEvent.event_id).where(
                    AlertEvent.event_id == Event.id, AlertEvent.alert_id == alert_id
                )
            )
        )
    return conds


def _alert_summary(db: Session, ids: list[int]) -> dict[int, tuple[int, str | None]]:
    if not ids:
        return {}
    rank = case({s: i for i, s in enumerate(SEVERITIES)}, value=Alert.severity)
    rows = db.execute(
        select(AlertEvent.event_id, func.count(), func.max(rank))
        .join(Alert, Alert.id == AlertEvent.alert_id)
        .where(AlertEvent.event_id.in_(ids))
        .group_by(AlertEvent.event_id)
    ).all()
    return {eid: (n, SEVERITIES[r] if r is not None else None) for eid, n, r in rows}


def _item(e: Event, source_name: str, summary: tuple[int, str | None]) -> dict[str, Any]:
    return {
        "id": e.id,
        "event_time": e.event_time,
        "ingested_at": e.ingested_at,
        "event_type": e.event_type,
        "source_ip": str(e.source_ip) if e.source_ip else None,
        "username": e.username,
        "http_method": e.http_method,
        "path": e.path,
        "query": e.query,
        "http_status": e.http_status,
        "bytes_sent": e.bytes_sent,
        "user_agent": e.user_agent,
        "host": e.host,
        "severity": e.severity,
        "message": e.message,
        "source_id": e.source_id,
        "source_name": source_name,
        "raw_line": e.raw_line,
        "alert_count": summary[0],
        "max_alert_severity": summary[1],
    }


@router.get("", response_model=EventPage)
def list_events(
    _: Reader,
    db: DbSession,
    q: Annotated[
        str | None,
        Query(
            min_length=2, max_length=200, description="Case-insensitive substring of the raw line"
        ),
    ] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    source_ip: Annotated[str | None, Query(max_length=64, description="IP or CIDR")] = None,
    event_type: Annotated[str | None, Query(max_length=32)] = None,
    http_status: Annotated[str | None, Query(max_length=3, description="e.g. 404 or 4xx")] = None,
    method: Annotated[str | None, Query(max_length=32)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
    source_id: Annotated[int | None, Query(gt=0)] = None,
    flagged: Annotated[bool | None, Query(description="Linked to any alert")] = None,
    alert_severity: Annotated[str | None, Query(max_length=16)] = None,
    alert_id: Annotated[int | None, Query(gt=0)] = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    with_count: bool = False,
) -> dict[str, Any]:
    """Newest first. Results are always bounded by `limit`; totals are capped at 10,000."""
    for v in (since, until):
        if v is not None and v.tzinfo is None:
            raise _bad("since/until must include a time zone (e.g. ...Z)")
    conds = build_filters(
        q,
        since,
        until,
        source_ip,
        event_type,
        http_status,
        method,
        username,
        source_id,
        flagged,
        alert_severity,
        alert_id,
    )
    page_conds = list(conds)
    if cursor:
        ts, eid = decode_cursor(cursor)
        page_conds.append(or_(Event.event_time < ts, and_(Event.event_time == ts, Event.id < eid)))

    rows = db.execute(
        select(Event, LogSource.name)
        .join(LogSource, LogSource.id == Event.source_id)
        .where(*page_conds)
        .order_by(Event.event_time.desc(), Event.id.desc())
        .limit(limit + 1)
    ).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    summary = _alert_summary(db, [e.id for e, _ in rows])
    out: dict[str, Any] = {
        "items": [_item(e, name, summary.get(e.id, (0, None))) for e, name in rows],
        "next_cursor": encode_cursor(rows[-1][0].event_time, rows[-1][0].id) if has_more else None,
    }
    if with_count:
        n = db.scalar(
            select(func.count()).select_from(
                select(Event.id).where(*conds).limit(COUNT_CAP + 1).subquery()
            )
        )
        out["count"] = min(n or 0, COUNT_CAP)
        out["count_capped"] = (n or 0) > COUNT_CAP
    return out


@router.get("/{event_id}", response_model=EventDetail)
def get_event(event_id: int, _: Reader, db: DbSession) -> dict[str, Any]:
    row = db.execute(
        select(Event, LogSource.name, ImportedFile.original_filename)
        .join(LogSource, LogSource.id == Event.source_id)
        .join(ImportedFile, ImportedFile.id == Event.file_id)
        .where(Event.id == event_id)
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    e, source_name, filename = row
    links = db.execute(
        select(Alert, AlertEvent.indicator)
        .join(AlertEvent, AlertEvent.alert_id == Alert.id)
        .where(AlertEvent.event_id == e.id)
        .order_by(Alert.id)
    ).all()
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    worst = max((a.severity for a, _ in links), key=rank.__getitem__, default=None)
    return {
        **_item(e, source_name, (len(links), worst)),
        "referrer": e.referrer,
        "http_version": e.http_version,
        "attributes": e.attributes or {},
        "file_id": e.file_id,
        "filename": filename,
        "line_number": e.line_number,
        "job_id": e.job_id,
        "alerts": [
            {
                "id": a.id,
                "rule_id": a.rule_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "indicator": ind,
            }
            for a, ind in links
        ],
    }
