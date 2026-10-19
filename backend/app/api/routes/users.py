"""User and role administration (admin only)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import AuthContext, DbSession, require
from app.core.permissions import Permission, permissions_for
from app.core.security import hash_password
from app.models import Role, User
from app.schemas.auth import EraseRequest, RoleOut, UserCreate, UserOut, UserUpdate
from app.services import audit, privacy
from app.services.auth import find_user, revoke_user_sessions, utcnow

router = APIRouter(tags=["users"])
Admin = Annotated[AuthContext, Depends(require(Permission.USERS_MANAGE))]


def _role(db: DbSession, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:  # roles are seeded by migration; missing means a broken database
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Role not configured")
    return role


@router.get("/roles", response_model=list[RoleOut])
def list_roles(_: Admin, db: DbSession) -> list[RoleOut]:
    roles = db.scalars(select(Role).order_by(Role.id)).all()
    return [
        RoleOut(
            name=r.name,
            description=r.description,  # type: ignore[arg-type]
            permissions=sorted(permissions_for(r.name)),
        )
        for r in roles
    ]


@router.get("/users", response_model=list[UserOut])
def list_users(_: Admin, db: DbSession) -> list[UserOut]:
    # Bounded: user counts are small; capped defensively.
    users = db.scalars(select(User).order_by(User.username).limit(1000)).all()
    pending = privacy.pending_deletion_requests(db)
    return [
        UserOut.model_validate(u).model_copy(update={"deletion_requested_at": pending.get(u.id)})
        for u in users
    ]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, auth: Admin, request: Request, db: DbSession) -> User:
    if body.username.lower().startswith(privacy.ERASED_PREFIX):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This username prefix is reserved")
    if find_user(db, body.username) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
    user = User(
        username=body.username,
        email=str(body.email) if body.email else None,
        password_hash=hash_password(body.password),
        role=_role(db, body.role),
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        "user.create",
        actor=auth.user,
        target_type="user",
        target_id=user.id,
        request=request,
        details={"username": user.username, "role": body.role},
    )
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int, body: UserUpdate, auth: Admin, request: Request, db: DbSession
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if privacy.is_erased(user):
        raise HTTPException(status.HTTP_409_CONFLICT, "Erased accounts cannot be changed")

    changes = body.model_dump(exclude_unset=True)
    is_self = user.id == auth.user.id
    # Guard against admins locking themselves (and possibly everyone) out.
    if is_self and changes.get("is_active") is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot deactivate your own account")
    if is_self and "role" in changes and changes["role"] != "admin":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot remove your own admin role")

    recorded: dict[str, object] = {}
    revoke = False
    if "email" in changes:
        user.email = str(changes["email"]) if changes["email"] else None
        recorded["email"] = "changed"
    if "role" in changes and changes["role"] != user.role.name:
        recorded["role"] = {"from": user.role.name, "to": changes["role"]}
        user.role = _role(db, changes["role"])
        revoke = True  # permissions changed: force a fresh login
    if "is_active" in changes and changes["is_active"] != user.is_active:
        recorded["is_active"] = changes["is_active"]
        user.is_active = changes["is_active"]
        revoke = revoke or not user.is_active
    if changes.get("password"):
        user.password_hash = hash_password(changes["password"])
        user.password_changed_at = utcnow()
        recorded["password"] = "reset"  # noqa: S105 - audit label, not a secret
        revoke = True

    if not recorded:
        return user
    if revoke and not is_self:
        recorded["sessions_revoked"] = revoke_user_sessions(db, user.id)
    audit.record(
        db,
        "user.update",
        actor=auth.user,
        target_type="user",
        target_id=user.id,
        request=request,
        details=recorded,
    )
    db.commit()
    db.refresh(user)
    return user


@router.post("/users/{user_id}/erase", response_model=UserOut)
def erase_user(
    user_id: int, body: EraseRequest, auth: Admin, request: Request, db: DbSession
) -> User:
    """Erase a user's personal data (a data deletion request).

    The account is anonymized and disabled, and its sessions and login attempts are
    deleted. Alerts, notes and incidents keep pointing at the anonymized account. The
    append-only audit log is kept for accountability.
    """
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == auth.user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot erase your own account")
    if privacy.is_erased(user):
        raise HTTPException(status.HTTP_409_CONFLICT, "This account has already been erased")
    if body.confirm_username.strip().lower() != user.username.lower():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The username does not match")
    privacy.erase_user(db, user, auth.user, request)
    return user
