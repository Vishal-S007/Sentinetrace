"""Writing to the append-only audit trail."""

import ipaddress
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog, User


def client_ip(request: Request | None) -> str | None:
    """The client's IP address, or None if it isn't a valid IP (e.g. in tests)."""
    if request is None or request.client is None:
        return None
    try:
        return str(ipaddress.ip_address(request.client.host))
    except ValueError:
        return None


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    actor_username: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Add an audit entry to the current transaction (the caller commits)."""
    entry = AuditLog(
        action=action,
        actor_user_id=actor.id if actor else None,
        actor_username=actor.username if actor else actor_username,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip=client_ip(request),
        request_id=getattr(request.state, "request_id", None) if request else None,
        details=details or {},
    )
    db.add(entry)
    return entry
