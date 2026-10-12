"""Import every model so Base.metadata is complete (used by Alembic)."""

from app.models.audit import AppConfig, AuditLog
from app.models.auth import LoginAttempt, Role, User, UserSession
from app.models.ingestion import Event, ImportedFile, IngestionError, IngestionJob, LogSource

__all__ = [
    "AppConfig",
    "AuditLog",
    "Event",
    "ImportedFile",
    "IngestionError",
    "IngestionJob",
    "LogSource",
    "LoginAttempt",
    "Role",
    "User",
    "UserSession",
]
