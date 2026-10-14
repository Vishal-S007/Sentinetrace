"""User lookups shared by alert and incident endpoints."""

from collections.abc import Iterable

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.permissions import Permission, permissions_for
from app.models import User


def usernames(db: Session, ids: Iterable[int | None]) -> dict[int, str]:
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(wanted))).all())


def can_be_assigned(user: User) -> bool:
    """Only active users who can act on alerts and incidents may own them."""
    perms = permissions_for(user.role.name)
    return user.is_active and Permission.ALERTS_TRIAGE in perms


def assignee(db: Session, user_id: int | None) -> User | None:
    """Validate an assignee id (None clears the assignment)."""
    if user_id is None:
        return None
    user = db.get(User, user_id)
    if user is None or not can_be_assigned(user):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "assigned_to must be an active analyst or admin",
        )
    return user
