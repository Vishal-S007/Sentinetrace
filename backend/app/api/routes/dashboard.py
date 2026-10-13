"""Security overview: every figure is computed from database records at request time."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, DbSession, require
from app.api.routes.detection import _alert_out
from app.core.permissions import Permission
from app.detection.registry import RULES
from app.models import Alert, Event, ImportedFile, IngestionJob, LogSource
from app.schemas.explorer import DashboardOut, DashboardRange

router = APIRouter(tags=["dashboard"])
Reader = Annotated[AuthContext, Depends(require(Permission.EVENTS_READ, Permission.ALERTS_READ))]

RANGES = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
OPEN = ("new", "investigating")


def _bucket_for(span: timedelta) -> str:
    if span <= timedelta(days=7):
        return "hour"
    if span <= timedelta(days=180):
        return "day"
    return "week"


def _floor(ts: datetime, unit: str) -> datetime:
    ts = ts.astimezone(UTC)
    if unit == "hour":
        return ts.replace(minute=0, second=0, microsecond=0)
    day = ts.replace(hour=0, minute=0, second=0, microsecond=0)
    return day if unit == "day" else day - timedelta(days=day.weekday())  # ISO week (Monday)


def _step(unit: str) -> timedelta:
    return {"hour": timedelta(hours=1), "day": timedelta(days=1), "week": timedelta(weeks=1)}[unit]


def _series(start: datetime, end: datetime, unit: str) -> list[datetime]:
    out, cur = [], _floor(start, unit)
    while cur <= end:
        out.append(cur)
        cur += _step(unit)
    return out


def _alerts_in(start: datetime | None, end: datetime):
    """Alerts whose activity overlaps [start, end]."""
    cond = Alert.first_seen <= end
    return cond if start is None else and_(cond, Alert.last_seen >= start)


def compute_dashboard(db: Session, rng: str, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    first, last = db.execute(select(func.min(Event.event_time), func.max(Event.event_time))).one()
    if rng == "all":
        start: datetime | None = first
        end = last or now
    else:
        start, end = now - RANGES[rng], now
    span = (end - start) if start else timedelta(hours=1)
    unit = _bucket_for(span)

    ev_cond = Event.event_time <= end if start is None else Event.event_time.between(start, end)
    al_cond = _alerts_in(start, end)

    totals = {
        "events": db.scalar(select(func.count()).select_from(Event).where(ev_cond)) or 0,
        "alerts": db.scalar(select(func.count()).select_from(Alert).where(al_cond)) or 0,
        "open_alerts": db.scalar(
            select(func.count()).select_from(Alert).where(al_cond, Alert.status.in_(OPEN))
        )
        or 0,
        "high_open_alerts": db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(al_cond, Alert.status.in_(OPEN), Alert.severity.in_(("high", "critical")))
        )
        or 0,
        "sources": db.scalar(select(func.count()).select_from(LogSource)) or 0,
        "files": db.scalar(select(func.count()).select_from(ImportedFile)) or 0,
    }

    by_sev = dict(
        db.execute(
            select(Alert.severity, func.count()).where(al_cond).group_by(Alert.severity)
        ).all()
    )
    by_status = dict(
        db.execute(select(Alert.status, func.count()).where(al_cond).group_by(Alert.status)).all()
    )

    events_over_time: list[dict[str, Any]] = []
    alerts_over_time: list[dict[str, Any]] = []
    if start is not None:
        trunc_e = func.date_trunc(unit, func.timezone("UTC", Event.event_time))
        counts = {
            b.replace(tzinfo=UTC): c
            for b, c in db.execute(select(trunc_e, func.count()).where(ev_cond).group_by(trunc_e))
        }
        trunc_a = func.date_trunc(unit, func.timezone("UTC", Alert.first_seen))
        sev_counts: dict[datetime, dict[str, int]] = {}
        for b, sev, c in db.execute(
            select(trunc_a, Alert.severity, func.count())
            .where(Alert.first_seen.between(start, end))
            .group_by(trunc_a, Alert.severity)
        ):
            sev_counts.setdefault(b.replace(tzinfo=UTC), {})[sev] = c
        for b in _series(start, end, unit):
            events_over_time.append({"bucket_start": b, "count": counts.get(b, 0)})
            alerts_over_time.append({"bucket_start": b, **sev_counts.get(b, {})})

    sev_rank = case({s: i for i, s in enumerate(SEVERITY_ORDER)}, value=Alert.severity)
    top_ips = db.execute(
        select(
            func.host(Alert.source_ip),
            func.count(),
            func.sum(Alert.event_count),
            func.max(sev_rank),
        )
        .where(al_cond, Alert.source_ip.is_not(None))
        .group_by(Alert.source_ip)
        .order_by(func.count().desc(), func.max(sev_rank).desc(), func.host(Alert.source_ip))
        .limit(10)
    ).all()
    top_rules = db.execute(
        select(Alert.rule_id, func.count())
        .where(al_cond)
        .group_by(Alert.rule_id)
        .order_by(func.count().desc(), Alert.rule_id)
        .limit(10)
    ).all()
    jobs = db.execute(
        select(IngestionJob, ImportedFile.original_filename, LogSource.name)
        .join(ImportedFile, ImportedFile.id == IngestionJob.file_id)
        .join(LogSource, LogSource.id == IngestionJob.source_id)
        .order_by(IngestionJob.id.desc())
        .limit(5)
    ).all()
    recent_high = db.scalars(
        select(Alert)
        .where(al_cond, Alert.severity.in_(("high", "critical")))
        .order_by(Alert.last_seen.desc(), Alert.id.desc())
        .limit(8)
    ).all()

    return {
        "range": rng,
        "start": start,
        "end": end,
        "bucket": unit,
        "totals": totals,
        "alerts_by_severity": [{"key": s, "count": by_sev.get(s, 0)} for s in SEVERITY_ORDER],
        "alerts_by_status": [
            {"key": s, "count": by_status.get(s, 0)}
            for s in ("new", "investigating", "resolved", "false_positive")
        ],
        "events_over_time": events_over_time,
        "alerts_over_time": alerts_over_time,
        "top_source_ips": [
            {
                "source_ip": ip,
                "alert_count": n,
                "event_count": int(ev or 0),
                "max_severity": SEVERITY_ORDER[rank],
            }
            for ip, n, ev, rank in top_ips
        ],
        "top_rules": [
            {"rule_id": r, "name": RULES[r].name if r in RULES else r, "alert_count": n}
            for r, n in top_rules
        ],
        "recent_jobs": [
            {
                "id": j.id,
                "status": j.status,
                "filename": fname,
                "source_name": sname,
                "parsed_count": j.parsed_count,
                "rejected_count": j.rejected_count,
                "created_at": j.created_at,
            }
            for j, fname, sname in jobs
        ],
        "recent_high_alerts": [_alert_out(a) for a in recent_high],
        "data_range": {"first_event": first, "last_event": last},
    }


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(
    _: Reader, db: DbSession, range_: Annotated[DashboardRange, Query(alias="range")] = "7d"
) -> dict[str, Any]:
    return compute_dashboard(db, range_)
