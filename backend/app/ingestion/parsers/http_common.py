"""Shared helpers for HTTP access-log formats."""

import re
from typing import Any

from app.ingestion.types import (
    MAX_PATH,
    MAX_QUERY,
    MAX_REFERRER,
    MAX_UA,
    ParseError,
    dash_to_none,
    truncate,
)

# A quoted field in Apache/Nginx logs: backslash escapes allowed inside.
QUOTED = r'(?:[^"\\]|\\.)*'

_METHOD = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_VERSION = re.compile(r"^HTTP/\d(?:\.\d)?$")


def unescape(value: str) -> str:
    """Undo the escaping Apache/Nginx apply inside quoted fields (\\" and \\\\)."""
    if "\\" not in value:
        return value
    return re.sub(r'\\(["\\])', r"\1", value)


def apply_request_line(request: str, out: dict[str, Any], attributes: dict[str, Any]) -> None:
    """Split 'METHOD target HTTP/x.y' into fields.

    A request line that doesn't have that shape (e.g. '-', TLS bytes sent to a plain-HTTP
    port, or garbage) is kept as an event with attributes.malformed_request = true, because
    malformed requests are themselves a detection signal.
    """
    request = unescape(request)
    parts = request.split(" ")
    if len(parts) == 3 and _METHOD.match(parts[0]) and _VERSION.match(parts[2]) and parts[1]:
        method, target, version = parts
        out["http_method"] = method.upper()
        out["http_version"] = version
        if "?" in target:
            path, query = target.split("?", 1)
        else:
            path, query = target, None
        out["path"] = truncate(path, MAX_PATH, attributes, "path")
        out["query"] = truncate(query, MAX_QUERY, attributes, "query")
        if target.lower().startswith(("http://", "https://")):
            attributes["absolute_uri"] = True
        return
    attributes["malformed_request"] = True
    attributes["request_line"] = truncate(request, MAX_PATH, attributes, "request_line")
    if parts and _METHOD.match(parts[0]) and len(parts) >= 2:
        # Best effort: keep the method and target of e.g. 'GET /x' (missing version).
        out["http_method"] = parts[0].upper()
        out["path"] = truncate(parts[1].split("?", 1)[0], MAX_PATH, attributes, "path")


def parse_status(value: str) -> int:
    if not value.isdigit() or not 100 <= int(value) <= 599:
        raise ParseError("invalid HTTP status")
    return int(value)


def parse_bytes(value: str) -> int | None:
    if value in ("-", ""):
        return None
    if not value.isdigit():
        raise ParseError("invalid byte count")
    return int(value)


def clean_referrer(value: str | None, attributes: dict[str, Any]) -> str | None:
    return truncate(
        dash_to_none(unescape(value) if value else value), MAX_REFERRER, attributes, "referrer"
    )


def clean_user_agent(value: str | None, attributes: dict[str, Any]) -> str | None:
    return truncate(
        dash_to_none(unescape(value) if value else value), MAX_UA, attributes, "user_agent"
    )
