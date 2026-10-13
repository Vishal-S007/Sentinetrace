"""Background worker: processes queued ingestion jobs, then queued detection runs.

uv run python -m app.worker          # run until stopped (Ctrl+C / SIGTERM)
uv run python -m app.worker --once   # process everything queued, then exit
"""

import argparse
import logging
import signal
import sys
import time

from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.detection.runs import claim_next_run, process_run
from app.ingestion.processor import claim_next_job, process_job, recover_stale_jobs

logger = logging.getLogger("sentineltrace.worker")
_stop = False


def _request_stop(signum, frame) -> None:  # noqa: ARG001
    global _stop
    _stop = True
    logger.info("Stop requested; finishing the current job")


def run(once: bool = False) -> int:
    settings = get_settings()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    session_factory = get_sessionmaker()
    processed = 0
    last_recovery = 0.0
    while not _stop:
        with session_factory() as db:
            if time.monotonic() - last_recovery > 60:
                if recovered := recover_stale_jobs(db, settings):
                    logger.warning("Recovered %d stale job(s)", recovered)
                last_recovery = time.monotonic()
            job = claim_next_job(db)
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
                processed += 1
                continue
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
                processed += 1
                continue
        if once:
            break
        time.sleep(settings.worker_poll_seconds)
    return processed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.worker")
    parser.add_argument("--once", action="store_true", help="drain the queue and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    count = run(once=args.once)
    logger.info("Worker exiting after %d job(s)", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
