"""Administration: effective settings and system health, data retention (admin only)."""

import shutil
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text

from app.api.deps import AppSettings, AuthContext, DbSession, require
from app.core.config import Settings
from app.core.permissions import Permission
from app.models import DetectionRun, IngestionJob
from app.services import retention

router = APIRouter(prefix="/admin", tags=["admin"])
SettingsAdmin = Annotated[AuthContext, Depends(require(Permission.SETTINGS_MANAGE))]


class RetentionOut(BaseModel):
    cutoff: str
    older_than_days: int
    alerts: int
    evidence_links: int
    events: int
    ingestion_errors: int
    stored_files: int
    stored_bytes: int
    min_days: int
    auto_days: int | None


class PurgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    older_than_days: int = Field(ge=1, le=36500)
    confirm: Literal["PURGE"] = Field(description='Must be the literal string "PURGE"')


def _out(counts: retention.RetentionCounts, settings: Any) -> dict[str, Any]:
    return {
        **counts.as_dict(),
        "min_days": settings.retention_min_days,
        "auto_days": settings.retention_auto_days,
    }


@router.get("/retention", response_model=RetentionOut)
def retention_preview(
    _: SettingsAdmin,
    db: DbSession,
    settings: AppSettings,
    older_than_days: Annotated[int, Query(ge=1, le=36500)] = 90,
) -> dict[str, Any]:
    """What a purge with this retention period would remove. Changes nothing."""
    try:
        counts = retention.preview(db, settings, older_than_days)
    except retention.RetentionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return _out(counts, settings)


@router.post("/retention/purge", response_model=RetentionOut)
def retention_purge(
    body: PurgeRequest, auth: SettingsAdmin, request: Request, db: DbSession, settings: AppSettings
) -> dict[str, Any]:
    """Delete eligible data older than the retention period. Recorded in the audit log."""
    try:
        counts = retention.purge(
            db, settings, body.older_than_days, actor=auth.user, request=request
        )
    except retention.RetentionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return _out(counts, settings)


# --- Effective settings and system health ---------------------------------------------

SETTING_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("General", [("environment", "Runtime environment"), ("version", "Application version")]),
    (
        "Uploads and ingestion",
        [
            ("max_upload_bytes", "Largest accepted upload (bytes)"),
            ("max_line_bytes", "Longest accepted log line (bytes)"),
            ("max_lines_per_file", "Most lines processed per file"),
            ("max_errors_per_job", "Rejected lines stored per import"),
            ("ingest_batch_size", "Events written per batch"),
            ("job_stale_minutes", "A running import is considered stuck after (minutes)"),
            ("max_job_attempts", "Automatic attempts per import"),
            ("worker_poll_seconds", "Worker polling interval (seconds)"),
        ],
    ),
    (
        "Detection",
        [
            ("alert_group_minutes", "Alert grouping bucket (minutes)"),
            ("max_evidence_per_alert", "Evidence events linked per alert"),
            ("detection_chunk_hours", "Detection processes time in chunks of (hours)"),
        ],
    ),
    (
        "Sessions and sign-in",
        [
            ("session_idle_minutes", "Session idle timeout (minutes)"),
            ("session_absolute_hours", "Session absolute lifetime (hours)"),
            ("cookie_secure", "Cookies sent over HTTPS only"),
            ("login_window_seconds", "Failed-login window (seconds)"),
            ("login_max_failures_per_user", "Failed logins allowed per account in the window"),
            ("login_max_failures_per_ip", "Failed logins allowed per IP in the window"),
            ("cors_origins", "Allowed cross-origin browser origins"),
        ],
    ),
    (
        "Retention and limits",
        [
            ("retention_auto_days", "Automatic purge of data older than (days)"),
            ("retention_min_days", "Shortest retention period allowed (days)"),
            ("export_rate_per_minute", "Exports and reports per user per minute"),
        ],
    ),
]


class SettingOut(BaseModel):
    group: str
    key: str
    env: str
    value: Any
    description: str


class SystemOut(BaseModel):
    settings: list[SettingOut]
    database: dict[str, Any]
    queue: dict[str, Any]
    storage: dict[str, Any]


def _effective(settings: Settings, key: str) -> Any:
    value = getattr(settings, key)
    if key == "cookie_secure" and value is None:
        return settings.environment == "production"
    if key == "cors_origins":
        return settings.cors_origin_list
    return value


def _table_rows(db: Any) -> dict[str, int]:
    """Row counts from planner statistics (cheap on large tables), exact when unknown."""
    tables = ["events", "alerts", "incidents", "imported_files", "audit_log", "users"]
    estimates = dict(
        db.execute(
            text("SELECT relname, reltuples::bigint FROM pg_class WHERE relname = ANY(:t)"),
            {"t": tables},
        ).all()
    )
    out = {}
    for t in tables:
        n = estimates.get(t, -1)
        if n is None or n < 0:  # never analysed: count exactly (tables like this are small)
            n = db.execute(text(f"SELECT count(*) FROM {t}")).scalar_one()  # noqa: S608
        out[t] = int(n)
    return out


def _storage_usage(root: Path) -> dict[str, Any]:
    files = size = 0
    if root.exists():
        for path in root.rglob("*"):
            if path.is_file():
                files += 1
                size += path.stat().st_size
    usage = shutil.disk_usage(root if root.exists() else root.parent)
    return {"files": files, "bytes": size, "free_bytes": usage.free, "total_bytes": usage.total}


@router.get("/system", response_model=SystemOut)
def system(_: SettingsAdmin, db: DbSession, settings: AppSettings) -> dict[str, Any]:
    """Effective configuration (secrets omitted) and the state of the database, the work
    queue and upload storage. Settings come from ST_* environment variables."""
    items = [
        SettingOut(
            group=group,
            key=key,
            env=f"ST_{key.upper()}",
            value=_effective(settings, key),
            description=desc,
        )
        for group, keys in SETTING_GROUPS
        for key, desc in keys
    ]
    url = settings.database_url
    host = url.hosts()[0] if url.hosts() else {}
    jobs = dict(
        db.execute(select(IngestionJob.status, func.count()).group_by(IngestionJob.status)).all()
    )
    runs = dict(
        db.execute(select(DetectionRun.status, func.count()).group_by(DetectionRun.status)).all()
    )
    last_job: datetime | None = db.scalar(select(func.max(IngestionJob.finished_at)))
    last_run: datetime | None = db.scalar(select(func.max(DetectionRun.finished_at)))
    return {
        "settings": items,
        "database": {
            # Never the password or full URL.
            "host": f"{host.get('host')}:{host.get('port') or 5432}",
            "name": (url.path or "").lstrip("/"),
            "server_version": db.execute(text("SHOW server_version")).scalar_one(),
            "size_bytes": db.execute(
                text("SELECT pg_database_size(current_database())")
            ).scalar_one(),
            "rows": _table_rows(db),
        },
        "queue": {
            "jobs_queued": jobs.get("queued", 0),
            "jobs_running": jobs.get("running", 0),
            "jobs_failed": jobs.get("failed", 0),
            "runs_queued": runs.get("queued", 0),
            "runs_running": runs.get("running", 0),
            "last_import_finished_at": last_job,
            "last_detection_finished_at": last_run,
        },
        "storage": _storage_usage(settings.storage_dir),
    }
