"""Runs rules over a time range and upserts grouped, evidence-linked alerts.

Idempotent: re-running the same range with the same data and configuration produces the
same alerts and evidence (and reports zero updates). Alerts are keyed by
(rule_id, group_key), where group_key = entity + bucket start. Analyst-owned fields
(status, assignee) are never touched by re-detection.
"""

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, insert, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.detection.base import EventRow, Finding, Rule, buckets_between, fmt_time
from app.detection.registry import CORRELATION_RULE_ID, RULES
from app.models import Alert, AlertEvent, DetectionRule, Event


@dataclass
class RunStats:
    created: int = 0
    updated: int = 0
    unchanged: int = 0

    def add(self, other: "RunStats") -> None:
        self.created += other.created
        self.updated += other.updated
        self.unchanged += other.unchanged


# Only the columns rules need. The IP is returned as text (host()) and only the one
# attribute rules use is extracted, which avoids parsing every INET and JSONB value.
_EVENT_COLUMNS = (
    Event.id,
    Event.event_time,
    Event.event_type,
    func.host(Event.source_ip).label("source_ip"),
    Event.username,
    Event.http_method,
    Event.path,
    Event.query,
    Event.http_status,
    Event.user_agent,
    Event.referrer,
    Event.attributes["malformed_request"].as_boolean().label("malformed"),
)
_MALFORMED: dict[str, Any] = {"malformed_request": True}
_NONE: dict[str, Any] = {}


def fetch_events(db: Session, rule: Rule, start: datetime, end: datetime) -> list[EventRow]:
    stmt = (
        select(*_EVENT_COLUMNS)
        .where(Event.event_time >= start, Event.event_time < end)
        .order_by(Event.event_time, Event.id)
        .execution_options(yield_per=10_000)
    )
    if rule.event_types:
        stmt = stmt.where(Event.event_type.in_(rule.event_types))
    if rule.statuses:
        stmt = stmt.where(Event.http_status.in_(rule.statuses))
    return [
        EventRow(
            r[0],
            r[1],
            r[2],
            r[3],
            r[4],
            r[5],
            r[6],
            r[7],
            r[8],
            r[9],
            r[10],
            _MALFORMED if r[11] else _NONE,
        )
        for r in db.execute(stmt)
    ]


class EventCache:
    """Rules with the same SQL prefilter share one fetch (the widest lookback wins).

    Extra lookback is harmless: window rules only use earlier events to decide which
    events an earlier bucket already claimed.
    """

    def __init__(
        self, db: Session, rules: list[Rule], range_start: datetime, range_end: datetime
    ) -> None:
        self.db, self.range_end = db, range_end
        self.starts: dict[tuple, datetime] = {}
        for rule in rules:
            key = self.key(rule)
            start = range_start - timedelta(seconds=rule.lookback_seconds())
            self.starts[key] = min(start, self.starts.get(key, start))
        self.data: dict[tuple, list[EventRow]] = {}

    @staticmethod
    def key(rule: Rule) -> tuple:
        return (rule.event_types, rule.statuses)

    def get(self, rule: Rule) -> list[EventRow]:
        key = self.key(rule)
        if key not in self.data:
            self.data[key] = fetch_events(self.db, rule, self.starts[key], self.range_end)
        return self.data[key]


def group_key(entity_key: str, bucket_start: datetime) -> str:
    entity = (
        entity_key
        if len(entity_key) <= 180
        else ("h=" + hashlib.sha256(entity_key.encode()).hexdigest()[:40])
    )
    return f"{entity}|{bucket_start.isoformat()}"


def upsert_alert(
    db: Session,
    rule_row: DetectionRule,
    rule_cls: type[Rule],
    f: Finding,
    window_seconds: int,
    settings: Settings,
) -> str:
    """Create or refresh the alert for a finding. Returns 'created', 'updated' or 'unchanged'."""
    key = group_key(f.entity_key, f.bucket_start)
    evidence = f.event_ids[: settings.max_evidence_per_alert]
    values = {
        "rule_version": rule_row.version,
        "bucket_start": f.bucket_start,
        "title": f.title[:255],
        "reason": f.reason,
        "severity": rule_row.severity,
        "confidence": f.confidence,
        "confidence_reason": f.confidence_reason,
        "recommended_action": rule_cls.recommended_steps[0],
        "source_ip": f.source_ip,
        "username": f.username[:256] if f.username else None,
        "endpoint": f.endpoint,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "event_count": len(f.event_ids),
        "window_seconds": window_seconds,
        "evidence_truncated": len(f.event_ids) > len(evidence),
        "details": f.details,
    }
    alert = db.scalar(
        select(Alert)
        .where(Alert.rule_id == rule_row.rule_id, Alert.group_key == key)
        .with_for_update()
    )
    if alert is None:
        alert = Alert(rule_id=rule_row.rule_id, group_key=key, **values)
        db.add(alert)
        db.flush()
        outcome = "created"
    else:
        current_ids = set(
            db.scalars(select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id)).all()
        )
        changed = current_ids != set(evidence) or any(
            _differs(getattr(alert, k), v) for k, v in values.items()
        )
        if not changed:
            return "unchanged"
        for k, v in values.items():
            setattr(alert, k, v)
        db.execute(delete(AlertEvent).where(AlertEvent.alert_id == alert.id))
        outcome = "updated"
    if evidence:
        db.execute(
            insert(AlertEvent),
            [
                {"alert_id": alert.id, "event_id": eid, "indicator": f.indicators.get(eid)}
                for eid in evidence
            ],
        )
    return outcome


def _differs(current: object, new: object) -> bool:
    if current is None or new is None:
        return current is not new
    return str(current) != str(new) if not isinstance(new, dict) else current != new


def _load_rules(db: Session, only: Sequence[str] | None) -> list[DetectionRule]:
    stmt = select(DetectionRule).where(DetectionRule.enabled.is_(True))
    if only:
        stmt = stmt.where(DetectionRule.rule_id.in_(only))
    return [r for r in db.scalars(stmt.order_by(DetectionRule.rule_id)).all() if r.rule_id in RULES]


def run_detection(
    db: Session,
    settings: Settings,
    start: datetime,
    end: datetime,
    only: Sequence[str] | None = None,
) -> RunStats:
    """Evaluate enabled rules for every bucket overlapping [start, end]. Commits."""
    size = timedelta(minutes=settings.alert_group_minutes)
    bucket_list = buckets_between(start, end, size)
    buckets = set(bucket_list)
    range_start, range_end = bucket_list[0], bucket_list[-1] + size
    stats = RunStats()

    rows = _load_rules(db, only)
    rules = [
        (row, RULES[row.rule_id](row.config)) for row in rows if row.rule_id != CORRELATION_RULE_ID
    ]
    cache = EventCache(db, [r for _, r in rules], range_start, range_end)
    for row, rule in rules:
        events = cache.get(rule)
        for finding in rule.evaluate(events, size, buckets):
            outcome = upsert_alert(
                db,
                row,
                type(rule),
                finding,
                rule.window_seconds() or int(size.total_seconds()),
                settings,
            )
            setattr(stats, outcome, getattr(stats, outcome) + 1)
        db.commit()

    corr = next((r for r in rows if r.rule_id == CORRELATION_RULE_ID), None)
    if corr is not None:
        stats.add(correlate(db, settings, corr, buckets))
        db.commit()
    return stats


def correlate(
    db: Session, settings: Settings, row: DetectionRule, buckets: set[datetime]
) -> RunStats:
    rule_cls = RULES[CORRELATION_RULE_ID]
    cfg = rule_cls(row.config).config
    stats = RunStats()
    members = db.scalars(
        select(Alert)
        .where(
            Alert.rule_id.in_(cfg.rule_ids),
            Alert.bucket_start.in_(buckets),
            Alert.source_ip.is_not(None),
        )
        .order_by(Alert.source_ip, Alert.bucket_start, Alert.first_seen, Alert.id)
    ).all()
    groups: dict[tuple[str, datetime], list[Alert]] = {}
    for a in members:
        groups.setdefault((str(a.source_ip), a.bucket_start), []).append(a)

    for (ip, b), alerts in sorted(groups.items()):
        rule_ids = sorted({a.rule_id for a in alerts})
        if len(rule_ids) < cfg.min_distinct_rules:
            continue
        links = db.execute(
            select(AlertEvent.event_id, Alert.rule_id, Event.event_time)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .join(Event, Event.id == AlertEvent.event_id)
            .where(AlertEvent.alert_id.in_([a.id for a in alerts]))
            .order_by(Event.event_time, AlertEvent.event_id)
        ).all()
        indicators: dict[int, str] = {}
        for event_id, member_rule, _ in links:
            indicators.setdefault(event_id, member_rule)
        ordered = list(indicators)
        first = min(a.first_seen for a in alerts)
        last = max(a.last_seen for a in alerts)
        names = [f"{RULES[r].name} ({r})" for r in rule_ids]
        total_events = sum(a.event_count for a in alerts)
        finding = Finding(
            entity_key=f"ip={ip}",
            bucket_start=b,
            event_ids=ordered,
            first_seen=first,
            last_seen=last,
            title=f"Multi-stage suspicious activity from {ip} ({len(rule_ids)} rules)",
            reason=(
                f"{len(rule_ids)} different detection rules fired for {ip} between "
                f"{fmt_time(first)} and {fmt_time(last)}: {'; '.join(names)}. "
                f"{len(alerts)} member alert(s) covering {total_events} event(s). Combined "
                "behaviour from one source is a stronger signal than any single alert, but "
                "it is still an indicator, not confirmation of compromise."
            ),
            confidence="high",
            confidence_reason=(
                f"Independent rules agree: {', '.join(rule_ids)} all fired for the same IP "
                "in the same window."
            ),
            source_ip=ip,
            indicators=indicators,
            details={
                "member_alert_ids": [a.id for a in alerts],
                "member_rules": rule_ids,
                "member_event_count": total_events,
            },
        )
        outcome = upsert_alert(
            db,
            row,
            rule_cls,
            finding,
            int(timedelta(minutes=settings.alert_group_minutes).total_seconds()),
            settings,
        )
        setattr(stats, outcome, getattr(stats, outcome) + 1)
    return stats
