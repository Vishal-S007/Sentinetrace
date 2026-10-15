"""Log sources, imported files, ingestion jobs and normalized events."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

# Formats a source can be configured with. "auto" detects per file.
SOURCE_FORMATS = (
    "auto",
    "apache_combined",
    "nginx_combined",
    "nginx_common",
    "nginx_custom",
    "json",
    "auth_log",
)
JOB_STATUSES = ("queued", "running", "completed", "completed_with_errors", "failed")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class LogSource(Base):
    __tablename__ = "log_sources"
    __table_args__ = (
        CheckConstraint(_in("format", SOURCE_FORMATS), name="ck_log_sources_format"),
        CheckConstraint(
            "format <> 'nginx_custom' OR custom_pattern IS NOT NULL",
            name="ck_log_sources_custom_pattern",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(500), server_default="")
    format: Mapped[str] = mapped_column(String(32))
    custom_pattern: Mapped[str | None] = mapped_column(Text)
    # Used for timestamps that carry no UTC offset (e.g. syslog auth.log).
    timezone: Mapped[str] = mapped_column(String(64), server_default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ImportedFile(Base):
    """An uploaded file. Stored on disk under its SHA-256, never under the client's filename."""

    __tablename__ = "imported_files"
    __table_args__ = (UniqueConstraint("source_id", "sha256", name="uq_imported_files_source_sha"),)

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("log_sources.id"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))  # display only, sanitized
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    # "utf-8", or "utf-8 (invalid bytes replaced)" when some bytes weren't valid UTF-8.
    encoding: Mapped[str] = mapped_column(String(48))
    storage_key: Mapped[str] = mapped_column(String(128))
    # Set when retention removed the stored upload; metadata and events are kept.
    content_purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    source: Mapped[LogSource] = relationship(lazy="joined")


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        CheckConstraint(_in("status", JOB_STATUSES), name="ck_ingestion_jobs_status"),
        Index("ix_ingestion_jobs_status_id", "status", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("imported_files.id"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("log_sources.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), server_default="queued")
    requested_format: Mapped[str | None] = mapped_column(String(32))  # per-upload override
    format: Mapped[str | None] = mapped_column(String(32))  # format actually used
    total_lines: Mapped[int] = mapped_column(Integer, server_default="0")
    parsed_count: Mapped[int] = mapped_column(Integer, server_default="0")
    rejected_count: Mapped[int] = mapped_column(Integer, server_default="0")
    duplicate_count: Mapped[int] = mapped_column(Integer, server_default="0")
    errors_truncated: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    error_message: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, server_default="0")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    file: Mapped[ImportedFile] = relationship(lazy="joined")


class IngestionError(Base):
    """A rejected line. raw_line is truncated; it is untrusted data shown as plain text."""

    __tablename__ = "ingestion_errors"
    __table_args__ = (Index("ix_ingestion_errors_job_line", "job_id", "line_number"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("ingestion_jobs.id", ondelete="CASCADE"))
    line_number: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String(255))
    raw_line: Mapped[str] = mapped_column(Text)


class Event(Base):
    """A normalized security event. event_time = when it happened; ingested_at = when stored."""

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_event_time_brin", "event_time", postgresql_using="brin"),
        Index("ix_events_source_ip_time", "source_ip", "event_time"),
        Index("ix_events_type_time", "event_type", "event_time"),
        Index("ix_events_status_time", "http_status", "event_time"),
        Index("ix_events_source_time", "source_id", "event_time"),
        Index("ix_events_job", "job_id"),
        # Substring search over the original line (event explorer); needs pg_trgm.
        Index(
            "ix_events_raw_line_trgm",
            "raw_line",
            postgresql_using="gin",
            postgresql_ops={"raw_line": "gin_trgm_ops"},
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("log_sources.id"))
    file_id: Mapped[int] = mapped_column(ForeignKey("imported_files.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("ingestion_jobs.id"))
    line_number: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    event_type: Mapped[str] = mapped_column(String(32))
    source_ip: Mapped[str | None] = mapped_column(INET)
    username: Mapped[str | None] = mapped_column(String(256))
    http_method: Mapped[str | None] = mapped_column(String(32))
    path: Mapped[str | None] = mapped_column(Text)
    query: Mapped[str | None] = mapped_column(Text)
    http_version: Mapped[str | None] = mapped_column(String(16))
    http_status: Mapped[int | None] = mapped_column(SmallInteger)
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger)
    referrer: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str | None] = mapped_column(String(16))
    message: Mapped[str | None] = mapped_column(Text)
    raw_line: Mapped[str] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")
