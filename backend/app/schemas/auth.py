"""Request and response models for auth, users and audit."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.security import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH

RoleName = Literal["admin", "analyst", "viewer"]
USERNAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$"


def _check_password_strength(value: str) -> str:
    if value.strip() != value:
        raise ValueError("password must not start or end with whitespace")
    if len(set(value)) < 4:
        raise ValueError("password is too repetitive")
    return value


class LoginRequest(BaseModel):
    # Loose limits here: login must not reveal password policy or username rules.
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    role: RoleName
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None
    # Set when the user asked for their data to be deleted and no admin has erased it yet.
    deletion_requested_at: datetime | None = None

    @field_validator("role", mode="before")
    @classmethod
    def role_name(cls, v: Any) -> Any:
        return getattr(v, "name", v)


class MeOut(BaseModel):
    user: UserOut
    permissions: list[str]


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    _strength = field_validator("new_password")(_check_password_strength)


class UserCreate(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    email: EmailStr | None = None
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    role: RoleName

    _strength = field_validator("password")(_check_password_strength)


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr | None = None
    role: RoleName | None = None
    is_active: bool | None = None
    password: str | None = Field(
        default=None, min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH
    )

    @field_validator("password")
    @classmethod
    def strength(cls, v: str | None) -> str | None:
        return None if v is None else _check_password_strength(v)


class RoleOut(BaseModel):
    name: RoleName
    description: str
    permissions: list[str]


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    actor_user_id: int | None
    actor_username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    request_id: str | None
    details: dict[str, Any]

    @field_validator("ip", mode="before")
    @classmethod
    def ip_str(cls, v: Any) -> Any:
        return None if v is None else str(v)


class AuditPage(BaseModel):
    items: list[AuditEntryOut]
    next_before_id: int | None = Field(
        description="Pass as before_id to fetch the next (older) page; null when no more."
    )


class EraseRequest(BaseModel):
    """The admin retypes the username, so the wrong account is not erased by a misclick."""

    confirm_username: str = Field(min_length=1, max_length=64)


class DeletionRequestOut(BaseModel):
    requested_at: datetime
