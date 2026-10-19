"""Background worker: processes queued ingestion jobs, then queued detection runs.

uv run python -m app.worker          # run until stopped (Ctrl+C / SIGTERM)
uv run python -m app.worker --once   # process everything queued, then exit
uv run python -m app.worker --check-health   # exit 0 if the heartbeat is recent
"""

import argparse
import logging
import signal
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_sessionmaker
from app.detection.runs import claim_next_run, process_run
from app.ingestion.processor import claim_next_job, process_job, recover_stale_jobs
from app.models import AppConfig
from app.services import privacy, retention

logger = logging.getLogger("sentineltrace.worker")
_stop = False


def _request_stop(signum, frame) -> None:  # noqa: ARG001
    global _stop
    _stop = True
    logger.info("Stop requested; finishing the current job")


def heartbeat_max_age(poll_seconds: float) -> float:
    """How old the heartbeat may be before the worker counts as unhealthy."""
    return max(30.0, 5 * poll_seconds)


def _beat(path: Path | None) -> None:
    if path is not None:
        path.touch()


def check_health(path: Path | None, poll_seconds: float, now: float | None = None) -> bool:
    """True if the heartbeat file exists and was touched recently.

    A long-running job holds the loop, so the heartbeat is also touched before each job
    starts; very large imports can still exceed the limit, which only marks the
    container unhealthy (it is not restarted for that).
    """
    if path is None:
        return False
    try:
        age = (time.time() if now is None else now) - path.stat().st_mtime
    except OSError:
        return False
    return age <= heartbeat_max_age(poll_seconds)


RETENTION_CHECK_SECONDS = 3600
RETENTION_INTERVAL = timedelta(hours=24)
RETENTION_KEY = "retention.last_auto_run"
MAX_BACKOFF_SECONDS = 60.0
_sleep = time.sleep  # replaced in tests


def maybe_auto_purge(db: Session, settings: Settings, now: datetime | None = None) -> bool:
    """If ST_RETENTION_AUTO_DAYS is set, purge once per 24 hours. Returns True if it ran."""
    if settings.retention_auto_days is None:
        return False
    now = now or datetime.now(UTC)
    row = db.get(AppConfig, RETENTION_KEY)
    if row is not None and isinstance(row.value, str):
        if now - datetime.fromisoformat(row.value) < RETENTION_INTERVAL:
            return False
    counts = retention.purge(db, settings, settings.retention_auto_days, actor_username="worker")
    if row is None:
        db.add(AppConfig(key=RETENTION_KEY, value=now.isoformat()))
    else:
        row.value = now.isoformat()
    db.commit()
    logger.info("Automatic retention purge: %s", counts.as_dict())
    return True


class _State:
    def __init__(self) -> None:
        self.last_recovery = 0.0
        self.last_retention_check = 0.0


def _tick(db: Session, settings: Settings, state: _State) -> bool:
    """One unit of work. Returns True if something was processed."""
    if time.monotonic() - state.last_recovery > 60:
        if recovered := recover_stale_jobs(db, settings):
            logger.warning("Recovered %d stale job(s)", recovered)
        state.last_recovery = time.monotonic()
    job = claim_next_job(db)
    _beat(settings.worker_heartbeat_file)  # the database answered
    if job is not None:
        logger.info("Processing job %s (file %s)", job.id, job.file_id)
        process_job(db, job, settings)
        logger.info(
            "Job %s finished: %s (parsed=%s rejected=%s duplicates=%s)",
            job.id,
            job.status,
            job.parsed_count,
            job.rejected_count,
            job.duplicate_count,
        )
        return True
    run_item = claim_next_run(db)
    if run_item is not None:
        logger.info("Detection run %s (%s)", run_item.id, run_item.trigger)
        process_run(db, run_item, settings)
        logger.info(
            "Detection run %s %s: %s alert(s) created, %s updated",
            run_item.id,
            run_item.status,
            run_item.alerts_created,
            run_item.alerts_updated,
        )
        return True
    if time.monotonic() - state.last_retention_check > RETENTION_CHECK_SECONDS:
        state.last_retention_check = time.monotonic()
        maybe_auto_purge(db, settings)
        pruned = privacy.prune_sign_in_records(db, settings)
        if pruned.login_attempts or pruned.sessions:
            logger.info(
                "Deleted %d old login attempt(s) and %d finished session(s)",
                pruned.login_attempts,
                pruned.sessions,
            )
    return False


def run(once: bool = False) -> int:
    """Process work until stopped. A failed iteration (e.g. the database is unreachable)
    is logged and retried with exponential backoff instead of crashing the worker."""
    settings = get_settings()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    session_factory = get_sessionmaker()
    logger.info("Worker started (poll every %ss)", settings.worker_poll_seconds)
    state = _State()
    processed = 0
    failures = 0
    while not _stop:
        try:
            with session_factory() as db:
                worked = _tick(db, settings, state)
            failures = 0
        except Exception:
            failures += 1
            delay = min(MAX_BACKOFF_SECONDS, settings.worker_poll_seconds * 2 ** min(failures, 8))
            logger.exception(
                "Worker iteration failed (%d in a row); retrying in %.0fs", failures, delay
            )
            if once:
                break
            _sleep(delay)
            continue
        if worked:
            processed += 1
            continue
        if once:
            break
        _sleep(settings.worker_poll_seconds)
    return processed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.worker")
    parser.add_argument("--once", action="store_true", help="drain the queue and exit")
    parser.add_argument(
        "--check-health", action="store_true", help="exit 0 if the heartbeat file is recent"
    )
    args = parser.parse_args(argv)
    if args.check_health:
        settings = get_settings()
        return (
            0 if check_health(settings.worker_heartbeat_file, settings.worker_poll_seconds) else 1
        )
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    count = run(once=args.once)
    logger.info("Worker exiting after %d job(s)", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
