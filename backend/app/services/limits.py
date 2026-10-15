"""Per-user limits on expensive read endpoints (exports and incident reports).

Counted from the audit log, which records every export, so the limit is shared by all
API processes and survives restarts without extra state.
"""

from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuditLog, User

WINDOW = timedelta(minutes=1)


def enforce_export_rate(db: Session, user: User, settings: Settings) -> None:
    since = datetime.now(UTC) - WINDOW
    recent = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.actor_user_id == user.id,
            AuditLog.occurred_at >= since,
            or_(AuditLog.action.like("export.%"), AuditLog.action == "incident.export"),
        )
    )
    if (recent or 0) >= settings.export_rate_per_minute:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Export limit reached ({settings.export_rate_per_minute} per minute). "
            "Try again in a minute.",
            headers={"Retry-After": str(int(WINDOW.total_seconds()))},
        )
