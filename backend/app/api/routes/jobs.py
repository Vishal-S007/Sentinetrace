"""Ingestion jobs: status, error details (JSON and CSV) and retry."""

import csv
import io
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, DbSession, require
from app.core.permissions import Permission
from app.ingestion.processor import reset_job_for_retry
from app.models import IngestionError, IngestionJob, LogSource, User
from app.schemas.ingestion import ErrorPage, IngestionErrorOut, JobOut, JobPage, JobStatus
from app.services import audit

router = APIRouter(prefix="/jobs", tags=["ingestion"])
Reader = Annotated[AuthContext, Depends(require(Permission.EVENTS_READ))]
Importer = Annotated[AuthContext, Depends(require(Permission.LOGS_IMPORT))]


def job_out(
    db: Session, job: IngestionJob, source_name: str | None = None, creator: str | None = None
) -> JobOut:
    if source_name is None:
        source_name = db.scalar(select(LogSource.name).where(LogSource.id == job.source_id)) or ""
    if creator is None and job.created_by is not None:
        creator = db.scalar(select(User.username).where(User.id == job.created_by))
    f = job.file
    return JobOut(
        id=job.id,
        status=job.status,
        source_id=job.source_id,  # type: ignore[arg-type]
        source_name=source_name,
        file_id=job.file_id,
        filename=f.original_filename,
        size_bytes=f.size_bytes,
        encoding=f.encoding,
        requested_format=job.requested_format,
        format=job.format,
        total_lines=job.total_lines,
        parsed_count=job.parsed_count,
        rejected_count=job.rejected_count,
        duplicate_count=job.duplicate_count,
        errors_truncated=job.errors_truncated,
        error_message=job.error_message,
        attempts=job.attempts,
        created_by=creator,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
    )


def _get_job(db: Session, job_id: int) -> IngestionJob:
    job = db.get(IngestionJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    return job


@router.get("", response_model=JobPage)
def list_jobs(
    _: Reader,
    db: DbSession,
    status_filter: Annotated[JobStatus | None, Query(alias="status")] = None,
    source_id: Annotated[int | None, Query(gt=0)] = None,
    before_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> JobPage:
    stmt = (
        select(IngestionJob, LogSource.name, User.username)
        .join(LogSource, LogSource.id == IngestionJob.source_id)
        .outerjoin(User, User.id == IngestionJob.created_by)
        .order_by(IngestionJob.id.desc())
    )
    if status_filter:
        stmt = stmt.where(IngestionJob.status == status_filter)
    if source_id:
        stmt = stmt.where(IngestionJob.source_id == source_id)
    if before_id:
        stmt = stmt.where(IngestionJob.id < before_id)
    rows = db.execute(stmt.limit(limit + 1)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return JobPage(
        items=[job_out(db, j, name, user) for j, name, user in rows],
        next_before_id=rows[-1][0].id if has_more else None,
    )


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: int, _: Reader, db: DbSession) -> JobOut:
    return job_out(db, _get_job(db, job_id))


@router.get("/{job_id}/errors", response_model=ErrorPage)
def list_job_errors(
    job_id: int,
    _: Reader,
    db: DbSession,
    after_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> ErrorPage:
    job = _get_job(db, job_id)
    stmt = select(IngestionError).where(IngestionError.job_id == job.id).order_by(IngestionError.id)
    if after_id:
        stmt = stmt.where(IngestionError.id > after_id)
    rows = list(db.scalars(stmt.limit(limit + 1)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    stored = db.scalar(
        select(func.count()).select_from(IngestionError).where(IngestionError.job_id == job.id)
    )
    return ErrorPage(
        items=[IngestionErrorOut.model_validate(r) for r in rows],
        next_after_id=rows[-1].id if has_more else None,
        total_rejected=job.rejected_count,
        stored=stored or 0,
        truncated=job.errors_truncated,
    )


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection (cells starting with = + - @ tab CR)."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


@router.get(
    "/{job_id}/errors.csv", response_class=Response, responses={200: {"content": {"text/csv": {}}}}
)
def download_job_errors(job_id: int, _: Reader, db: DbSession) -> Response:
    """All stored errors for a job as CSV (bounded by ST_MAX_ERRORS_PER_JOB)."""
    job = _get_job(db, job_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["line_number", "reason", "raw_line"])
    for e in db.scalars(
        select(IngestionError).where(IngestionError.job_id == job.id).order_by(IngestionError.id)
    ):
        writer.writerow([e.line_number, _csv_safe(e.reason), _csv_safe(e.raw_line)])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="job-{job.id}-errors.csv"'},
    )


@router.post("/{job_id}/retry", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
def retry_job(job_id: int, auth: Importer, request: Request, db: DbSession) -> JobOut:
    job = _get_job(db, job_id)
    if job.status != "failed":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only failed jobs can be retried")
    reset_job_for_retry(db, job)
    audit.record(
        db,
        "job.retry",
        actor=auth.user,
        target_type="ingestion_job",
        target_id=job.id,
        request=request,
    )
    db.commit()
    db.refresh(job)
    return job_out(db, job)
