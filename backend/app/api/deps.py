"""Shared FastAPI dependencies: authentication, CSRF and permission checks."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.permissions import Permission, permissions_for
from app.core.security import digests_match
from app.db.session import get_db
from app.models import User, UserSession
from app.services.auth import resolve_session

SESSION_COOKIE = "st_session"
CSRF_COOKIE = "st_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


@dataclass(frozen=True)
class AuthContext:
    user: User
    session: UserSession
    permissions: frozenset[Permission]


def _unauthorized() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")


def get_auth(request: Request, db: DbSession, settings: AppSettings) -> AuthContext:
    """Require a valid session; for state-changing methods also require a valid CSRF token."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise _unauthorized()
    session = resolve_session(db, settings, token)
    if session is None:
        raise _unauthorized()

    if request.method not in SAFE_METHODS:
        header = request.headers.get(CSRF_HEADER, "")
        cookie = request.cookies.get(CSRF_COOKIE, "")
        # Header must match the cookie (double submit) AND the token bound to this session.
        if not header or header != cookie or not digests_match(header, session.csrf_hash):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")

    user = session.user
    return AuthContext(user=user, session=session, permissions=permissions_for(user.role.name))


Auth = Annotated[AuthContext, Depends(get_auth)]


def require(*needed: Permission) -> Callable[..., AuthContext]:
    """Dependency factory: the current user must hold every listed permission."""

    def checker(auth: Auth) -> AuthContext:
        if not set(needed) <= auth.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return auth

    return checker
