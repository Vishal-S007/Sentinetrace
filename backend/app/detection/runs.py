"""Detection runs: queued work items processed by the worker.

A run is queued automatically when an ingestion job completes (covering that job's event
time range) and can be requested manually (e.g. after changing a rule's thresholds).
Large ranges are processed in chunks to bound memory.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.detection.engine import RunStats, run_detection
from app.models import DetectionRun, Event, IngestionJob

logger = logging.getLogger("sentineltrace.detection")


def utcnow() -> datetime:
    return datetime.now(UTC)


def enqueue_for_job(db: Session, job: IngestionJob) -> DetectionRun | None:
    lo, hi = db.execute(
        select(func.min(Event.event_time), func.max(Event.event_time)).where(Event.job_id == job.id)
    ).one()
    if lo is None:
        return None
    run = DetectionRun(
        trigger="ingestion",
        job_id=job.id,
        range_start=lo,
        range_end=hi,
        requested_by=job.created_by,
    )
    db.add(run)
    return run


def enqueue_manual(
    db: Session, user_id: int | None, start: datetime | None, end: datetime | None
) -> DetectionRun:
    run = DetectionRun(trigger="manual", range_start=start, range_end=end, requested_by=user_id)
    db.add(run)
    return run


def claim_next_run(db: Session) -> DetectionRun | None:
    run = db.scalar(
        select(DetectionRun)
        .where(DetectionRun.status == "queued")
        .order_by(DetectionRun.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if run is None:
        return None
    run.status = "running"
    run.started_at = utcnow()
    db.commit()
    return run


def process_run(db: Session, run: DetectionRun, settings: Settings) -> DetectionRun:
    try:
        start, end = run.range_start, run.range_end
        if start is None or end is None:  # manual run without a range: all events
            lo, hi = db.execute(
                select(func.min(Event.event_time), func.max(Event.event_time))
            ).one()
            start, end = start or lo, end or hi
        stats = RunStats()
        if start is not None and end is not None and start <= end:
            chunk = timedelta(hours=settings.detection_chunk_hours)
            cursor = start
            while cursor <= end:
                stats.add(run_detection(db, settings, cursor, min(cursor + chunk, end)))
                cursor += chunk
        run.range_start, run.range_end = start, end
        run.alerts_created, run.alerts_updated = stats.created, stats.updated
        run.status = "completed"
    except Exception:
        logger.exception("Detection run %s failed", run.id)
        db.rollback()
        run.status = "failed"
        run.error_message = "Detection failed unexpectedly; see server logs."
    run.finished_at = utcnow()
    db.commit()
    return run
