"""Common types shared by all parsers."""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from typing import Any, Protocol

# Field length caps: longer values are truncated and flagged in attributes.
MAX_PATH = 2048
MAX_QUERY = 2048
MAX_UA = 1024
MAX_REFERRER = 2048
MAX_MESSAGE = 4096
MAX_USERNAME = 256
MAX_HOST = 255

EVENT_TYPES = (
    "http_request",
    "auth_failure",
    "auth_success",
    "auth_other",
    "app_log",
)


class ParseError(Exception):
    """A line could not be parsed. The message is a short, user-facing reason."""


@dataclass
class ParseContext:
    """Information a parser may need beyond the line itself."""

    timezone: tzinfo  # for timestamps without an offset
    reference_time: datetime  # aware; used to infer the year for syslog timestamps


@dataclass
class ParsedEvent:
    event_time: datetime  # timezone-aware, normalized to UTC by the parser
    event_type: str
    source_ip: str | None = None
    username: str | None = None
    http_method: str | None = None
    path: str | None = None
    query: str | None = None
    http_version: str | None = None
    http_status: int | None = None
    bytes_sent: int | None = None
    referrer: str | None = None
    user_agent: str | None = None
    host: str | None = None
    severity: str | None = None
    message: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


class Parser(Protocol):
    name: str

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent: ...


def clean_ip(value: str | None, attributes: dict[str, Any], key: str = "remote_host") -> str | None:
    """Return a valid IP string, or None (keeping a non-IP value such as a hostname aside)."""
    if value is None or value in ("", "-"):
        return None
    candidate = value.strip()
    # IPv6 may appear in brackets; IPv4-mapped forms are accepted as-is.
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        attributes[key] = truncate(candidate, MAX_HOST, attributes, key)
        return None


def truncate(value: str | None, limit: int, attributes: dict[str, Any], name: str) -> str | None:
    if value is None:
        return None
    if len(value) > limit:
        attributes.setdefault("truncated_fields", []).append(name)
        return value[:limit]
    return value


def dash_to_none(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value
