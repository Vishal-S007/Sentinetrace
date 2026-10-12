"""Read-only access to the audit trail (admin only). There is no write or delete endpoint."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.deps import AuthContext, DbSession, require
from app.core.permissions import Permission
from app.models import AuditLog
from app.schemas.auth import AuditEntryOut, AuditPage

router = APIRouter(prefix="/audit", tags=["audit"])
Auditor = Annotated[AuthContext, Depends(require(Permission.AUDIT_READ))]


@router.get("", response_model=AuditPage)
def list_audit(
    _: Auditor,
    db: DbSession,
    action: Annotated[str | None, Query(max_length=64)] = None,
    actor: Annotated[str | None, Query(max_length=64, description="Actor username")] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    before_id: Annotated[int | None, Query(gt=0)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AuditPage:
    """Newest first, keyset-paginated by id (stable even while new entries arrive)."""
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor_username == actor)
    if since:
        stmt = stmt.where(AuditLog.occurred_at >= since)
    if until:
        stmt = stmt.where(AuditLog.occurred_at < until)
    if before_id:
        stmt = stmt.where(AuditLog.id < before_id)

    rows = list(db.scalars(stmt.limit(limit + 1)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(
        items=[AuditEntryOut.model_validate(r) for r in rows],
        next_before_id=rows[-1].id if has_more else None,
    )
