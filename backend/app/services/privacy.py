"""Personal data about the people who use SentinelTrace: housekeeping and erasure.

- Sign-in records (login attempts, finished sessions) are deleted once they are no
  longer needed for rate limiting or security review.
- A user can ask for their account data to be deleted; an admin then erases it. The
  account row stays (alerts, notes and incidents point at it) but is anonymized.
- The audit log is append-only and is not changed by erasure: it is kept for
  accountability, and later entries refer to the user only by id.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import hash_password
from app.models import AuditLog, LoginAttempt, User, UserSession
from app.services import audit
from app.services.auth import normalize_username, utcnow

ERASED_PREFIX = "erased-user-"
DELETION_REQUEST = "user.deletion_request"
ERASE = "user.erase"


@dataclass
class PruneResult:
    login_attempts: int
    sessions: int


def prune_sign_in_records(
    db: Session, settings: Settings, now: datetime | None = None
) -> PruneResult:
    """Delete login attempts and finished sessions older than their retention periods."""
    now = now or utcnow()
    attempts_cutoff = now - timedelta(days=settings.login_attempt_retention_days)
    # The rate limiter only looks back login_window_seconds; never delete inside it.
    attempts_cutoff = min(attempts_cutoff, now - timedelta(seconds=settings.login_window_seconds))
    attempts = db.execute(
        delete(LoginAttempt).where(LoginAttempt.attempted_at < attempts_cutoff)
    ).rowcount
    session_cutoff = now - timedelta(days=settings.session_retention_days)
    sessions = db.execute(
        delete(UserSession).where(
            or_(
                UserSession.expires_at < session_cutoff,
                UserSession.revoked_at < session_cutoff,
                UserSession.last_seen_at
                < session_cutoff - timedelta(minutes=settings.session_idle_minutes),
            )
        )
    ).rowcount
    db.commit()
    return PruneResult(login_attempts=attempts or 0, sessions=sessions or 0)


def pending_deletion_requests(db: Session) -> dict[int, datetime]:
    """User id -> time of their latest deletion request not yet followed by an erasure."""
    rows = db.execute(
        select(
            AuditLog.target_id,
            func.max(AuditLog.id).filter(AuditLog.action == DELETION_REQUEST),
            func.max(AuditLog.id).filter(AuditLog.action == ERASE),
            func.max(AuditLog.occurred_at).filter(AuditLog.action == DELETION_REQUEST),
        )
        .where(AuditLog.target_type == "user", AuditLog.action.in_((DELETION_REQUEST, ERASE)))
        .group_by(AuditLog.target_id)
    ).all()
    pending: dict[int, datetime] = {}
    for target_id, request_id, erase_id, requested_at in rows:
        if request_id is not None and (erase_id is None or request_id > erase_id):
            pending[int(target_id)] = requested_at
    return pending


def request_deletion(db: Session, user: User, request: Request | None) -> datetime:
    """Record the user's request. A repeat while one is pending returns the first."""
    existing = pending_deletion_requests(db).get(user.id)
    if existing is not None:
        return existing
    entry = audit.record(
        db, DELETION_REQUEST, actor=user, target_type="user", target_id=user.id, request=request
    )
    db.flush()
    db.refresh(entry)
    requested_at = entry.occurred_at
    db.commit()
    return requested_at


def is_erased(user: User) -> bool:
    return user.username.startswith(ERASED_PREFIX)


def erase_user(db: Session, user: User, actor: User, request: Request | None) -> dict[str, int]:
    """Anonymize the account and delete its sign-in records. The caller checks permissions."""
    old_username = user.username
    user.username = f"{ERASED_PREFIX}{user.id}"
    user.email = None
    user.password_hash = hash_password(secrets.token_urlsafe(32))
    user.password_changed_at = utcnow()
    user.is_active = False
    user.last_login_at = None
    sessions = db.execute(delete(UserSession).where(UserSession.user_id == user.id)).rowcount
    attempts = db.execute(
        delete(LoginAttempt).where(LoginAttempt.username == normalize_username(old_username))
    ).rowcount
    counts = {"sessions_deleted": sessions or 0, "login_attempts_deleted": attempts or 0}
    # No personal data in the entry: it outlives the erasure.
    audit.record(
        db, ERASE, actor=actor, target_type="user", target_id=user.id, request=request,
        details=counts,
    )  # fmt: skip
    db.commit()
    db.refresh(user)
    return counts
