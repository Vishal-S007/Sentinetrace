"""Import every model so Base.metadata is complete (used by Alembic)."""

from app.models.audit import AppConfig, AuditLog
from app.models.auth import LoginAttempt, Role, User, UserSession

__all__ = ["AppConfig", "AuditLog", "LoginAttempt", "Role", "User", "UserSession"]
