"""User and role administration (admin only)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import AuthContext, DbSession, require
from app.core.permissions import Permission, permissions_for
from app.core.security import hash_password
from app.models import Role, User
from app.schemas.auth import RoleOut, UserCreate, UserOut, UserUpdate
from app.services import audit
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
def list_users(_: Admin, db: DbSession) -> list[User]:
    # Bounded: user counts are small; capped defensively.
    return list(db.scalars(select(User).order_by(User.username).limit(1000)).all())


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, auth: Admin, request: Request, db: DbSession) -> User:
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
