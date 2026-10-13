"""Helpers to build events directly in the database for detection tests."""

import hashlib
import itertools
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.detection.engine import RunStats, run_detection
from app.models import Alert, Event, ImportedFile, IngestionJob, LogSource

# A fixed, bucket-aligned base time keeps tests deterministic (and well in the past).
T0 = datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
_counter = itertools.count(1)


class EventFactory:
    def __init__(self, db: Session) -> None:
        self.db = db
        n = next(_counter)
        self.source = LogSource(name=f"det-src-{n}-{id(self)}", format="auto")
        db.add(self.source)
        db.flush()
        self.file = ImportedFile(
            source_id=self.source.id,
            original_filename="t.log",
            sha256=hashlib.sha256(f"{n}-{id(self)}".encode()).hexdigest(),
            size_bytes=1,
            encoding="utf-8",
            storage_key="files/x",
        )
        db.add(self.file)
        db.flush()
        self.job = IngestionJob(file_id=self.file.id, source_id=self.source.id, status="completed")
        db.add(self.job)
        db.flush()
        self.line = 0

    def add(self, at: datetime | float, **fields: Any) -> Event:
        """Add one event. `at` is a datetime or seconds after T0."""
        self.line += 1
        when = at if isinstance(at, datetime) else T0 + timedelta(seconds=at)
        defaults: dict[str, Any] = {
            "event_type": "http_request",
            "http_method": "GET",
            "path": "/",
            "http_status": 200,
            "attributes": {},
        }
        defaults.update(fields)
        raw = defaults.pop("raw_line", None) or f"line {self.line} {defaults}"
        e = Event(
            source_id=self.source.id,
            file_id=self.file.id,
            job_id=self.job.id,
            line_number=self.line,
            event_time=when,
            raw_line=raw,
            fingerprint=hashlib.sha256(f"{self.source.id}-{self.line}-{raw}".encode()).hexdigest(),
            **defaults,
        )
        self.db.add(e)
        return e

    def many(self, count: int, start: float, step: float, **fields: Any) -> list[Event]:
        out = [self.add(start + i * step, **fields) for i in range(count)]
        self.db.flush()
        return out

    def flush(self) -> None:
        self.db.flush()


def detect(
    db: Session,
    settings: Settings,
    start: datetime | None = None,
    end: datetime | None = None,
    only: list[str] | None = None,
) -> RunStats:
    db.flush()
    return run_detection(
        db, settings, start or T0 - timedelta(hours=1), end or T0 + timedelta(hours=3), only=only
    )


def alerts(db: Session, rule_id: str | None = None) -> list[Alert]:
    stmt = select(Alert).order_by(Alert.rule_id, Alert.bucket_start, Alert.group_key)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    return list(db.scalars(stmt).all())


AlertFilter = Callable[[Alert], bool]
