"""Role-based access control: which role may do what.

Roles live in the database; the permission set for each role is defined here, in code,
so it is reviewed and versioned with the endpoints that depend on it.
"""

from enum import StrEnum


class Permission(StrEnum):
    # Read access
    EVENTS_READ = "events:read"
    ALERTS_READ = "alerts:read"
    RULES_READ = "rules:read"
    INCIDENTS_READ = "incidents:read"
    REPORTS_READ = "reports:read"
    # Analyst actions
    ALERTS_TRIAGE = "alerts:triage"
    INCIDENTS_MANAGE = "incidents:manage"
    LOGS_IMPORT = "logs:import"
    REPORTS_EXPORT = "reports:export"
    # Administration
    RULES_MANAGE = "rules:manage"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"
    SETTINGS_MANAGE = "settings:manage"


_VIEWER = {
    Permission.EVENTS_READ,
    Permission.ALERTS_READ,
    Permission.RULES_READ,
    Permission.INCIDENTS_READ,
    Permission.REPORTS_READ,
}
_ANALYST = _VIEWER | {
    Permission.ALERTS_TRIAGE,
    Permission.INCIDENTS_MANAGE,
    Permission.LOGS_IMPORT,
    Permission.REPORTS_EXPORT,
}
_ADMIN = set(Permission)

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer": frozenset(_VIEWER),
    "analyst": frozenset(_ANALYST),
    "admin": frozenset(_ADMIN),
}


def permissions_for(role_name: str) -> frozenset[Permission]:
    # Unknown roles get nothing (fail closed).
    return ROLE_PERMISSIONS.get(role_name, frozenset())
