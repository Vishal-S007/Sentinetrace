"""Data retention: preview and purge data older than a cutoff, safely.

What is eligible (all conditions must hold):

* **Alerts:** status resolved or false positive, last seen before the cutoff, not linked
  to any incident, and without investigation notes. Their evidence links go with them.
* **Events:** occurred before the cutoff, not evidence for any alert that is kept, and
  not referenced by an investigation note.
* **Rejected-line records:** belong to ingestion jobs that finished before the cutoff.
* **Stored uploads:** uploaded before the cutoff, every job for them has finished, and no
  other upload that is not eligible shares the same stored content. The file metadata
  stays (marked `content_purged_at`); only the stored bytes are removed.

Never purged: open alerts, incidents, investigation notes, users, sources, job and file
metadata, rule versions, and the audit log (append-only by design).

Deletes run in batches, each in its own transaction, so a purge of millions of rows does
not hold long locks; an interrupted purge can simply be run again.
"""

import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, exists, func, select, update
from sqlalchemy.orm import Session, aliased

from app.core.config import Settings
from app.ingestion.storage import resolve_storage_path
from app.models import (
    Alert,
    AlertEvent,
    Event,
    ImportedFile,
    IncidentAlert,
    IngestionError,
    IngestionJob,
    InvestigationNote,
    User,
)
from app.services import audit

logger = logging.getLogger("sentineltrace.retention")

CLOSED_ALERT_STATUSES = ("resolved", "false_positive")
FINAL_JOB_STATUSES = ("completed", "completed_with_errors", "failed")


class RetentionError(ValueError):
    """The request is unsafe (e.g. a retention period below the configured minimum)."""


@dataclass
class RetentionCounts:
    cutoff: datetime
    older_than_days: int
    alerts: int = 0
    evidence_links: int = 0
    events: int = 0
    ingestion_errors: int = 0
    stored_files: int = 0
    stored_bytes: int = 0

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["cutoff"] = self.cutoff.isoformat()
        return d


def cutoff_for(days: int, settings: Settings, now: datetime | None = None) -> datetime:
    if days < settings.retention_min_days:
        raise RetentionError(
            f"Retention must be at least {settings.retention_min_days} days "
            f"(ST_RETENTION_MIN_DAYS); got {days}"
        )
    return (now or datetime.now(UTC)) - timedelta(days=days)


def _alert_purgeable(cutoff: datetime) -> list[Any]:
    return [
        Alert.status.in_(CLOSED_ALERT_STATUSES),
        Alert.last_seen < cutoff,
        ~exists().where(IncidentAlert.alert_id == Alert.id),
        ~exists().where(InvestigationNote.alert_id == Alert.id),
    ]


def _event_purgeable(cutoff: datetime, *, after_alert_purge: bool) -> list[Any]:
    """Events eligible for deletion. For a preview, alerts that would be purged first are
    treated as already gone (their evidence does not keep events alive)."""
    if after_alert_purge:
        no_kept_alert = ~exists().where(AlertEvent.event_id == Event.id)
    else:
        kept = aliased(Alert)
        no_kept_alert = ~exists(
            select(AlertEvent.event_id)
            .join(kept, kept.id == AlertEvent.alert_id)
            .where(
                AlertEvent.event_id == Event.id,
                ~and_(
                    kept.status.in_(CLOSED_ALERT_STATUSES),
                    kept.last_seen < cutoff,
                    ~exists().where(IncidentAlert.alert_id == kept.id),
                    ~exists().where(InvestigationNote.alert_id == kept.id),
                ),
            )
        )
    return [
        Event.event_time < cutoff,
        no_kept_alert,
        ~exists().where(InvestigationNote.event_id == Event.id),
    ]


def _errors_purgeable(cutoff: datetime) -> list[Any]:
    return [
        IngestionError.job_id.in_(
            select(IngestionJob.id).where(
                IngestionJob.status.in_(FINAL_JOB_STATUSES), IngestionJob.finished_at < cutoff
            )
        )
    ]


def _file_eligible(f: Any, cutoff: datetime) -> Any:
    """SQL condition: this imported_files row could have its content removed."""
    return and_(
        f.uploaded_at < cutoff,
        ~exists().where(
            IngestionJob.file_id == f.id, IngestionJob.status.not_in(FINAL_JOB_STATUSES)
        ),
    )


def _purgeable_storage(db: Session, cutoff: datetime) -> list[tuple[str, int]]:
    """(storage_key, size) for stored content whose every referencing upload is eligible."""
    f = aliased(ImportedFile)
    other = aliased(ImportedFile)
    rows = db.execute(
        select(f.storage_key, func.max(f.size_bytes))
        .where(
            f.content_purged_at.is_(None),
            _file_eligible(f, cutoff),
            ~exists().where(other.storage_key == f.storage_key, ~_file_eligible(other, cutoff)),
        )
        .group_by(f.storage_key)
        .order_by(f.storage_key)
    ).all()
    return [(k, int(n or 0)) for k, n in rows]


def _count(db: Session, model: Any, conds: list[Any]) -> int:
    return db.scalar(select(func.count()).select_from(model).where(*conds)) or 0


def preview(
    db: Session, settings: Settings, older_than_days: int, now: datetime | None = None
) -> RetentionCounts:
    cutoff = cutoff_for(older_than_days, settings, now)
    alert_ids = select(Alert.id).where(*_alert_purgeable(cutoff))
    storage = _purgeable_storage(db, cutoff)
    return RetentionCounts(
        cutoff=cutoff,
        older_than_days=older_than_days,
        alerts=_count(db, Alert, _alert_purgeable(cutoff)),
        evidence_links=_count(db, AlertEvent, [AlertEvent.alert_id.in_(alert_ids)]),
        events=_count(db, Event, _event_purgeable(cutoff, after_alert_purge=False)),
        ingestion_errors=_count(db, IngestionError, _errors_purgeable(cutoff)),
        stored_files=len(storage),
        stored_bytes=sum(n for _, n in storage),
    )


def purge(
    db: Session,
    settings: Settings,
    older_than_days: int,
    *,
    actor: User | None = None,
    actor_username: str | None = None,
    request: Any = None,
    now: datetime | None = None,
) -> RetentionCounts:
    """Delete eligible data in batches and record one audit entry with the totals."""
    cutoff = cutoff_for(older_than_days, settings, now)
    batch = settings.retention_batch_size
    result = RetentionCounts(cutoff=cutoff, older_than_days=older_than_days)

    # 1. Alerts first, so their evidence no longer keeps events alive.
    while ids := list(db.scalars(select(Alert.id).where(*_alert_purgeable(cutoff)).limit(batch))):
        result.evidence_links += (
            db.execute(delete(AlertEvent).where(AlertEvent.alert_id.in_(ids))).rowcount or 0
        )
        result.alerts += db.execute(delete(Alert).where(Alert.id.in_(ids))).rowcount or 0
        db.commit()

    # 2. Events.
    event_conds = _event_purgeable(cutoff, after_alert_purge=True)
    while ids := list(db.scalars(select(Event.id).where(*event_conds).limit(batch))):
        result.events += db.execute(delete(Event).where(Event.id.in_(ids))).rowcount or 0
        db.commit()

    # 3. Rejected-line records of old jobs.
    while ids := list(
        db.scalars(select(IngestionError.id).where(*_errors_purgeable(cutoff)).limit(batch))
    ):
        result.ingestion_errors += (
            db.execute(delete(IngestionError).where(IngestionError.id.in_(ids))).rowcount or 0
        )
        db.commit()

    # 4. Stored uploads (bytes on disk); metadata rows stay and are marked.
    for key, size in _purgeable_storage(db, cutoff):
        path = resolve_storage_path(settings.storage_dir, key)
        try:
            path.unlink()
        except FileNotFoundError:
            pass  # already gone (e.g. an earlier interrupted purge)
        db.execute(
            update(ImportedFile)
            .where(ImportedFile.storage_key == key, ImportedFile.content_purged_at.is_(None))
            .values(content_purged_at=func.now())
        )
        db.commit()
        result.stored_files += 1
        result.stored_bytes += size

    audit.record(
        db,
        "retention.purge",
        actor=actor,
        actor_username=actor_username,
        target_type="retention",
        request=request,
        details=result.as_dict(),
    )
    db.commit()
    logger.info("Retention purge done: %s", result.as_dict())
    return result
