"""Ingestion job processing: read a stored file, parse, normalize and persist events.

Jobs live in the ingestion_jobs table and are claimed with SELECT ... FOR UPDATE
SKIP LOCKED, so several workers can run safely. Events are inserted in batches with
ON CONFLICT (fingerprint) DO NOTHING; each committed batch updates the job's counters,
so progress is visible while a large file is processing.

Duplicate detection: an event's fingerprint is SHA-256(source id, raw line, n), where
n counts earlier identical lines in the same file. Re-importing an overlapping file
(e.g. a rotated log) therefore counts the overlapping lines as duplicates, while
genuinely repeated identical requests inside one file are all kept. The per-file
counter keeps the most recent distinct lines (LRU), bounding memory on large files.
"""

import hashlib
import logging
from collections import OrderedDict
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from psycopg import sql
from psycopg.types.json import Jsonb
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.detection.runs import enqueue_for_job
from app.ingestion.detect import detect_format
from app.ingestion.parsers import PatternError, build_parser
from app.ingestion.storage import file_sha256, resolve_storage_path
from app.ingestion.types import ParseContext, ParsedEvent, ParseError
from app.models import AlertEvent, Event, IngestionError, IngestionJob, LogSource

logger = logging.getLogger("sentineltrace.ingestion")

OCCURRENCE_CACHE = 200_000
# Bulk load path: COPY rows into a per-connection temp table, then one
# INSERT ... SELECT ... ON CONFLICT (fingerprint) DO NOTHING. The insert's row count is the
# number of new events; the remainder of the batch are duplicates.
EVENT_COLUMNS = (
    "source_id",
    "file_id",
    "job_id",
    "line_number",
    "fingerprint",
    "event_time",
    "event_type",
    "source_ip",
    "username",
    "http_method",
    "path",
    "query",
    "http_version",
    "http_status",
    "bytes_sent",
    "referrer",
    "user_agent",
    "host",
    "severity",
    "message",
    "raw_line",
    "attributes",
)
# Composed with psycopg.sql (quoted identifiers), never with string formatting.
_COLS = sql.SQL(", ").join(sql.Identifier(c) for c in EVENT_COLUMNS)
_STAGE = sql.Identifier("st_stage_events")
_DROP_STAGE = sql.SQL("DROP TABLE IF EXISTS {}").format(_STAGE)
_CREATE_STAGE = sql.SQL("CREATE TEMP TABLE {} AS SELECT {} FROM events WITH NO DATA").format(
    _STAGE, _COLS
)
_COPY_STAGE = sql.SQL("COPY {} ({}) FROM STDIN").format(_STAGE, _COLS)
_MERGE_STAGE = sql.SQL(
    "INSERT INTO events ({cols}) SELECT {cols} FROM {stage} ON CONFLICT (fingerprint) DO NOTHING"
).format(cols=_COLS, stage=_STAGE)
_TRUNCATE_STAGE = sql.SQL("TRUNCATE {}").format(_STAGE)
MAX_ERROR_LINE = 2000


def utcnow() -> datetime:
    return datetime.now(UTC)


# --- Queue ---------------------------------------------------------------------------


def claim_next_job(db: Session) -> IngestionJob | None:
    """Atomically move the oldest queued job to 'running' and return it."""
    job = db.scalar(
        select(IngestionJob)
        .where(IngestionJob.status == "queued")
        .order_by(IngestionJob.id)
        .limit(1)
        .with_for_update(skip_locked=True, of=IngestionJob)
    )
    if job is None:
        return None
    now = utcnow()
    job.status = "running"
    job.started_at = now
    job.heartbeat_at = now
    job.attempts += 1
    db.commit()
    return job


def recover_stale_jobs(db: Session, settings: Settings) -> int:
    """Requeue jobs whose worker died (no heartbeat), or fail them after max attempts."""
    cutoff = utcnow() - timedelta(minutes=settings.job_stale_minutes)
    stale = db.scalars(
        select(IngestionJob)
        .where(IngestionJob.status == "running", IngestionJob.heartbeat_at < cutoff)
        .with_for_update(skip_locked=True, of=IngestionJob)
    ).all()
    for job in stale:
        if job.attempts >= settings.max_job_attempts:
            job.status = "failed"
            job.finished_at = utcnow()
            job.error_message = "Worker stopped responding; maximum attempts reached."
        else:
            reset_job_for_retry(db, job)
    db.commit()
    return len(stale)


def reset_job_for_retry(db: Session, job: IngestionJob) -> None:
    """Delete this job's partial results and queue it again (idempotent reprocessing)."""
    # Evidence links to this job's partial events go first (re-detection recreates them).
    db.execute(
        delete(AlertEvent).where(
            AlertEvent.event_id.in_(select(Event.id).where(Event.job_id == job.id))
        )
    )
    db.execute(delete(Event).where(Event.job_id == job.id))
    db.execute(delete(IngestionError).where(IngestionError.job_id == job.id))
    job.status = "queued"
    job.total_lines = job.parsed_count = job.rejected_count = job.duplicate_count = 0
    job.errors_truncated = False
    job.error_message = None
    job.started_at = job.finished_at = job.heartbeat_at = None


# --- Processing ----------------------------------------------------------------------


class JobFailed(Exception):
    """A job-level failure with a user-facing message."""


def _iter_lines(path: Path, max_line_bytes: int) -> Iterator[tuple[int, str | None, str]]:
    """Yield (line_number, text_or_None_if_too_long, raw_preview) for non-blank lines."""
    with path.open("rb") as fh:
        for number, raw in enumerate(fh, start=1):
            stripped = raw.rstrip(b"\r\n")
            if number == 1 and stripped.startswith(b"\xef\xbb\xbf"):
                stripped = stripped[3:]
            if not stripped.strip():
                continue
            if len(stripped) > max_line_bytes:
                preview = stripped[:MAX_ERROR_LINE].decode("utf-8", errors="replace")
                yield number, None, preview
                continue
            yield number, stripped.decode("utf-8", errors="replace"), ""


def _sample(path: Path, max_line_bytes: int, n: int = 50) -> list[str]:
    out: list[str] = []
    for _, text, _ in _iter_lines(path, max_line_bytes):
        if text is not None:
            out.append(text)
        if len(out) >= n:
            break
    return out


def _fingerprint(source_id: int, line: str, occurrence: int) -> str:
    h = hashlib.sha256()
    h.update(f"{source_id}\x00{occurrence}\x00".encode())
    h.update(line.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _event_row(job: IngestionJob, number: int, line: str, fp: str, ev: ParsedEvent) -> tuple:
    """A row in EVENT_COLUMNS order, ready for COPY."""
    attrs = dict(ev.attributes)
    if "\ufffd" in line:
        attrs["encoding_replaced"] = True
    return (
        job.source_id,
        job.file_id,
        job.id,
        number,
        fp,
        ev.event_time,
        ev.event_type,
        ev.source_ip,
        ev.username,
        ev.http_method,
        ev.path,
        ev.query,
        ev.http_version,
        ev.http_status,
        ev.bytes_sent,
        ev.referrer,
        ev.user_agent,
        ev.host,
        ev.severity,
        ev.message,
        line,
        Jsonb(attrs),
    )


def _raw_connection(db: Session):
    """The psycopg connection underneath the session's current transaction."""
    return db.connection().connection.driver_connection


def _prepare_stage(db: Session) -> None:
    with _raw_connection(db).cursor() as cur:
        cur.execute(_DROP_STAGE)
        cur.execute(_CREATE_STAGE)


def _bulk_insert(db: Session, rows: list[tuple]) -> int:
    """Insert rows, skipping fingerprints that already exist; returns how many were new."""
    with _raw_connection(db).cursor() as cur:
        with cur.copy(_COPY_STAGE) as copy:
            for row in rows:
                copy.write_row(row)
        cur.execute(_MERGE_STAGE)
        inserted = cur.rowcount
        cur.execute(_TRUNCATE_STAGE)
    return inserted


def process_job(db: Session, job: IngestionJob, settings: Settings) -> IngestionJob:
    """Process a job already claimed (status 'running'). Always leaves a final status."""
    try:
        _run(db, job, settings)
    except JobFailed as exc:
        db.rollback()
        _finish(db, job, "failed", str(exc))
    except Exception:
        logger.exception("Ingestion job %s crashed", job.id)
        db.rollback()
        _finish(db, job, "failed", "Unexpected error while processing; see server logs.")
    return job


def _finish(db: Session, job: IngestionJob, status: str, message: str | None = None) -> None:
    job.status = status
    job.error_message = message
    job.finished_at = utcnow()
    job.heartbeat_at = job.finished_at
    if status in ("completed", "completed_with_errors"):
        # Detection runs over the new events' time range (picked up by the worker).
        enqueue_for_job(db, job)
    db.commit()


def _run(db: Session, job: IngestionJob, settings: Settings) -> None:
    source = db.get(LogSource, job.source_id)
    file = job.file
    if source is None:
        raise JobFailed("The log source no longer exists.")
    try:
        path = resolve_storage_path(settings.storage_dir, file.storage_key)
    except ValueError as exc:
        raise JobFailed("Stored file path is invalid.") from exc
    if not path.is_file():
        raise JobFailed("The uploaded file is missing from storage.")
    if file_sha256(path) != file.sha256:
        raise JobFailed("The stored file failed its integrity check (hash mismatch).")

    try:
        tz = ZoneInfo(source.timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise JobFailed(f"Unknown time zone '{source.timezone}' on the log source.") from exc
    ctx = ParseContext(timezone=tz, reference_time=file.uploaded_at or utcnow())

    fmt = job.requested_format or source.format
    if fmt == "auto":
        detection = detect_format(_sample(path, settings.max_line_bytes), ctx)
        if detection.format is None:
            raise JobFailed(
                "Could not detect the log format reliably. Choose the format explicitly."
            )
        fmt = detection.format
    try:
        parser = build_parser(fmt, source.custom_pattern)
    except (PatternError, ValueError) as exc:
        raise JobFailed(f"Cannot build parser: {exc}") from exc
    job.format = fmt
    db.commit()
    _prepare_stage(db)

    occurrences: OrderedDict[str, int] = OrderedDict()
    batch: list[dict] = []
    errors: list[dict] = []
    total = parsed = rejected = duplicates = errors_stored = 0
    truncated = False

    def flush() -> None:
        nonlocal parsed, duplicates, errors_stored, truncated
        if batch:
            inserted = _bulk_insert(db, batch)
            parsed += inserted
            duplicates += len(batch) - inserted
            batch.clear()
        if errors:
            room = settings.max_errors_per_job - errors_stored
            if room > 0:
                db.execute(insert(IngestionError), errors[:room])
                errors_stored += min(room, len(errors))
            if len(errors) > room:
                truncated = True
            errors.clear()
        db.execute(
            update(IngestionJob)
            .where(IngestionJob.id == job.id)
            .values(
                total_lines=total,
                parsed_count=parsed,
                rejected_count=rejected,
                duplicate_count=duplicates,
                errors_truncated=truncated,
                heartbeat_at=utcnow(),
            )
        )
        db.commit()

    for number, text, preview in _iter_lines(path, settings.max_line_bytes):
        total += 1
        if total > settings.max_lines_per_file:
            total -= 1
            flush()
            raise JobFailed(
                f"File exceeds the limit of {settings.max_lines_per_file:,} lines; "
                f"the first {total:,} lines were processed."
            )
        if text is None:
            rejected += 1
            errors.append(
                {
                    "job_id": job.id,
                    "line_number": number,
                    "raw_line": preview,
                    "reason": f"line longer than {settings.max_line_bytes} bytes",
                }
            )
        else:
            try:
                ev = parser.parse(text, ctx)
            except ParseError as exc:
                rejected += 1
                errors.append(
                    {
                        "job_id": job.id,
                        "line_number": number,
                        "reason": str(exc)[:255],
                        "raw_line": text[:MAX_ERROR_LINE],
                    }
                )
            else:
                seen = occurrences.pop(text, 0)
                occurrences[text] = seen + 1
                if len(occurrences) > OCCURRENCE_CACHE:
                    occurrences.popitem(last=False)
                batch.append(_event_row(job, number, text, _fingerprint(source.id, text, seen), ev))
        if len(batch) >= settings.ingest_batch_size or len(errors) >= settings.ingest_batch_size:
            flush()
    flush()
    db.refresh(job)

    if total == 0:
        _finish(db, job, "failed", "The file contains no log lines.")
    elif parsed == 0 and duplicates == 0:
        _finish(db, job, "failed", f"No lines could be parsed as {fmt}. Check the format.")
    elif rejected:
        _finish(db, job, "completed_with_errors")
    else:
        _finish(db, job, "completed")
