"""Administration: data retention preview and purge (admin only, audited)."""

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import AppSettings, AuthContext, DbSession, require
from app.core.permissions import Permission
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
