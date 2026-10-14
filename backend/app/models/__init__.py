"""Import every model so Base.metadata is complete (used by Alembic)."""

from app.models.audit import AppConfig, AuditLog
from app.models.auth import LoginAttempt, Role, User, UserSession
from app.models.detection import (
    Alert,
    AlertEvent,
    DetectionRule,
    DetectionRuleVersion,
    DetectionRun,
)
from app.models.incidents import Incident, IncidentAlert, InvestigationNote
from app.models.ingestion import Event, ImportedFile, IngestionError, IngestionJob, LogSource

__all__ = [
    "Alert",
    "AlertEvent",
    "DetectionRule",
    "DetectionRuleVersion",
    "DetectionRun",
    "AppConfig",
    "AuditLog",
    "Event",
    "Incident",
    "IncidentAlert",
    "InvestigationNote",
    "ImportedFile",
    "IngestionError",
    "IngestionJob",
    "LogSource",
    "LoginAttempt",
    "Role",
    "User",
    "UserSession",
]
