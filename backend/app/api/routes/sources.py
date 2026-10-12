"""Log sources and file uploads."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import AppSettings, AuthContext, DbSession, require
from app.api.routes.jobs import job_out
from app.core.permissions import Permission
from app.ingestion import storage
from app.ingestion.parsers import DETECTABLE, FORMAT_INFO
from app.models import ImportedFile, IngestionJob, LogSource
from app.schemas.ingestion import (
    FileOut,
    FormatOut,
    SourceCreate,
    SourceOut,
    SourceUpdate,
    UploadFormat,
    UploadResult,
)
from app.services import audit

router = APIRouter(tags=["sources"])
Reader = Annotated[AuthContext, Depends(require(Permission.EVENTS_READ))]
Importer = Annotated[AuthContext, Depends(require(Permission.LOGS_IMPORT))]


def _with_stats(db: DbSession, sources: list[LogSource]) -> list[SourceOut]:
    ids = [s.id for s in sources]
    stats: dict[int, tuple[int, int, object]] = {}
    if ids:
        rows = db.execute(
            select(
                ImportedFile.source_id,
                func.count(func.distinct(ImportedFile.id)),
                func.coalesce(func.sum(IngestionJob.parsed_count), 0),
                func.max(ImportedFile.uploaded_at),
            )
            .outerjoin(IngestionJob, IngestionJob.file_id == ImportedFile.id)
            .where(ImportedFile.source_id.in_(ids))
            .group_by(ImportedFile.source_id)
        ).all()
        stats = {r[0]: (r[1], int(r[2]), r[3]) for r in rows}
    out = []
    for s in sources:
        files, events, last = stats.get(s.id, (0, 0, None))
        item = SourceOut.model_validate(s)
        item.file_count, item.event_count, item.last_upload_at = files, events, last
        out.append(item)
    return out


def _get_source(db: DbSession, source_id: int) -> LogSource:
    source = db.get(LogSource, source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Log source not found")
    return source


@router.get("/formats", response_model=list[FormatOut])
def list_formats(_: Reader) -> list[FormatOut]:
    return [
        FormatOut(id=k, label=v["label"], example=v["example"], detectable=k in DETECTABLE)
        for k, v in FORMAT_INFO.items()
    ]


@router.get("/sources", response_model=list[SourceOut])
def list_sources(_: Reader, db: DbSession) -> list[SourceOut]:
    sources = list(db.scalars(select(LogSource).order_by(LogSource.name).limit(500)).all())
    return _with_stats(db, sources)


@router.post("/sources", response_model=SourceOut, status_code=status.HTTP_201_CREATED)
def create_source(body: SourceCreate, auth: Importer, request: Request, db: DbSession) -> SourceOut:
    source = LogSource(
        name=body.name,
        description=body.description,
        format=body.format,
        custom_pattern=body.custom_pattern if body.format == "nginx_custom" else None,
        timezone=body.timezone,
        created_by=auth.user.id,
    )
    db.add(source)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A source with this name already exists"
        ) from exc
    audit.record(
        db,
        "source.create",
        actor=auth.user,
        target_type="log_source",
        target_id=source.id,
        request=request,
        details={"name": source.name, "format": source.format},
    )
    db.commit()
    db.refresh(source)
    return _with_stats(db, [source])[0]


@router.patch("/sources/{source_id}", response_model=SourceOut)
def update_source(
    source_id: int, body: SourceUpdate, auth: Importer, request: Request, db: DbSession
) -> SourceOut:
    source = _get_source(db, source_id)
    changes = body.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] is not None:
        changes["name"] = changes["name"].strip()
        if not changes["name"]:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "name must not be blank")
    for key in ("name", "format", "timezone", "enabled"):
        if key in changes and changes[key] is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"{key} cannot be null")
    new_format = changes.get("format", source.format)
    new_pattern = changes.get("custom_pattern", source.custom_pattern)
    if new_format == "nginx_custom" and not new_pattern:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "custom_pattern is required for nginx_custom"
        )
    if new_format != "nginx_custom":
        changes["custom_pattern"] = None
    recorded = {k: v for k, v in changes.items() if getattr(source, k) != v}
    for key, value in changes.items():
        setattr(source, key, value)
    if not recorded:
        return _with_stats(db, [source])[0]
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A source with this name already exists"
        ) from exc
    audit.record(
        db,
        "source.update",
        actor=auth.user,
        target_type="log_source",
        target_id=source.id,
        request=request,
        details={"changed": sorted(recorded)},
    )
    db.commit()
    db.refresh(source)
    return _with_stats(db, [source])[0]


@router.post(
    "/sources/{source_id}/files",
    response_model=UploadResult,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"description": "Duplicate file or disabled source"},
        413: {"description": "File too large"},
        415: {"description": "Not a text log"},
    },
)
def upload_file(
    source_id: int,
    auth: Importer,
    request: Request,
    db: DbSession,
    settings: AppSettings,
    file: Annotated[UploadFile, File(description="Uncompressed text log file")],
    format: Annotated[UploadFormat | None, Form(description="Override the source format")] = None,
) -> UploadResult:
    source = _get_source(db, source_id)
    if not source.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "This log source is disabled")
    if format == "nginx_custom" and not source.custom_pattern:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "nginx_custom needs a log_format pattern on the source",
        )

    display_name = storage.sanitize_filename(file.filename)
    try:
        staged = storage.stage_upload(
            file.file, display_name, settings.storage_dir, settings.max_upload_bytes
        )
    except storage.UploadRejected as exc:
        raise HTTPException(exc.status_code, exc.message) from exc

    existing = db.scalar(
        select(ImportedFile).where(
            ImportedFile.source_id == source.id, ImportedFile.sha256 == staged.sha256
        )
    )
    if existing is not None:
        storage.discard(staged)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This exact file was already imported into this source "
            f"(as '{existing.original_filename}', file #{existing.id}).",
        )

    key = storage.commit_upload(staged, settings.storage_dir)
    imported = ImportedFile(
        source_id=source.id,
        original_filename=display_name,
        sha256=staged.sha256,
        size_bytes=staged.size,
        encoding=staged.encoding,
        storage_key=key,
        uploaded_by=auth.user.id,
    )
    db.add(imported)
    db.flush()
    job = IngestionJob(
        file_id=imported.id, source_id=source.id, requested_format=format, created_by=auth.user.id
    )
    db.add(job)
    db.flush()
    audit.record(
        db,
        "file.upload",
        actor=auth.user,
        target_type="imported_file",
        target_id=imported.id,
        request=request,
        details={
            "source_id": source.id,
            "filename": display_name,
            "sha256": staged.sha256,
            "size_bytes": staged.size,
            "job_id": job.id,
        },
    )
    db.commit()
    db.refresh(job)
    return UploadResult(file=FileOut.model_validate(imported), job=job_out(db, job))
