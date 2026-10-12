"""Authentication: credential checks, rate limiting and server-side sessions."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import (
    hash_password,
    needs_rehash,
    new_token,
    token_digest,
    verify_password,
)
from app.models import LoginAttempt, User, UserSession

# Only write last_seen_at when it is older than this, to avoid a write per request.
_TOUCH_INTERVAL = timedelta(minutes=1)


def utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_username(username: str) -> str:
    return username.strip().lower()


def find_user(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.username) == normalize_username(username)))


# --- Rate limiting -----------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitStatus:
    limited: bool
    retry_after_seconds: int = 0


def check_login_rate_limit(
    db: Session, settings: Settings, username: str, ip: str | None
) -> RateLimitStatus:
    """Sliding window over recent *failed* attempts, per username and per IP."""
    window_start = utcnow() - timedelta(seconds=settings.login_window_seconds)
    checks = [
        (
            LoginAttempt.username == normalize_username(username),
            settings.login_max_failures_per_user,
        )
    ]
    if ip:
        checks.append((LoginAttempt.ip == ip, settings.login_max_failures_per_ip))

    for condition, limit in checks:
        row = db.execute(
            select(func.count(), func.min(LoginAttempt.attempted_at)).where(
                condition,
                LoginAttempt.succeeded.is_(False),
                LoginAttempt.attempted_at >= window_start,
            )
        ).one()
        count, oldest = row
        if count >= limit:
            retry = int((oldest - window_start).total_seconds()) + 1 if oldest else 1
            return RateLimitStatus(True, max(retry, 1))
    return RateLimitStatus(False)


def record_login_attempt(db: Session, username: str, ip: str | None, succeeded: bool) -> None:
    db.add(LoginAttempt(username=normalize_username(username)[:64], ip=ip, succeeded=succeeded))


# --- Credentials -------------------------------------------------------------------


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Return the active user for valid credentials, else None.

    Always performs one Argon2 verification so timing doesn't reveal valid usernames.
    """
    user = find_user(db, username)
    valid = verify_password(user.password_hash if user else None, password)
    if not valid or user is None or not user.is_active:
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user


# --- Sessions ----------------------------------------------------------------------


@dataclass(frozen=True)
class IssuedSession:
    session: UserSession
    token: str  # goes in the HttpOnly cookie; never stored
    csrf_token: str  # goes in the readable CSRF cookie; never stored


def create_session(
    db: Session, settings: Settings, user: User, ip: str | None, user_agent: str | None
) -> IssuedSession:
    token, csrf = new_token(), new_token()
    now = utcnow()
    session = UserSession(
        token_hash=token_digest(token),
        csrf_hash=token_digest(csrf),
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=settings.session_absolute_hours),
        ip=ip,
        user_agent=(user_agent or "")[:512] or None,
    )
    db.add(session)
    db.flush()
    return IssuedSession(session, token, csrf)


def resolve_session(db: Session, settings: Settings, token: str) -> UserSession | None:
    """Return the live session for a cookie token, or None if missing/expired/revoked."""
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_digest(token)))
    if session is None or session.revoked_at is not None:
        return None
    now = utcnow()
    idle_limit = session.last_seen_at + timedelta(minutes=settings.session_idle_minutes)
    if now >= session.expires_at or now >= idle_limit or not session.user.is_active:
        return None
    if now - session.last_seen_at >= _TOUCH_INTERVAL:
        session.last_seen_at = now
        db.commit()
    return session


def revoke_session(db: Session, session: UserSession) -> None:
    session.revoked_at = utcnow()


def revoke_user_sessions(db: Session, user_id: int, except_session_id: int | None = None) -> int:
    stmt = update(UserSession).where(
        UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
    )
    if except_session_id is not None:
        stmt = stmt.where(UserSession.id != except_session_id)
    result = db.execute(stmt.values(revoked_at=utcnow()))
    return result.rowcount or 0
