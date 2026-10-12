"""Structured JSON logs: one JSON object per line (NDJSON / JSON Lines).

Nested objects are flattened to dotted keys (depth <= 3), so both flat application logs
and Elastic Common Schema style documents work. Each normalized field is taken from the
first key present in its alias list. Everything else is kept in attributes.
"""

import json
from typing import Any

from app.ingestion.timeparse import parse_epoch, parse_iso_time
from app.ingestion.types import (
    MAX_HOST,
    MAX_MESSAGE,
    MAX_PATH,
    MAX_QUERY,
    MAX_REFERRER,
    MAX_UA,
    MAX_USERNAME,
    ParseContext,
    ParsedEvent,
    ParseError,
    clean_ip,
    truncate,
)

ALIASES: dict[str, tuple[str, ...]] = {
    "time": ("@timestamp", "timestamp", "time", "ts", "datetime", "date", "event.created"),
    "ip": (
        "source.ip",
        "client.ip",
        "src_ip",
        "source_ip",
        "client_ip",
        "remote_addr",
        "remote_ip",
        "clientip",
        "ip",
    ),
    "user": ("user.name", "username", "user_name", "user", "login", "account"),
    "method": ("http.request.method", "method", "http_method", "request_method"),
    "path": ("url.path", "path", "uri", "url", "request_uri", "request_path"),
    "query": ("url.query", "query", "query_string", "args"),
    "status": (
        "http.response.status_code",
        "status",
        "status_code",
        "http_status",
        "response_code",
    ),
    "bytes": (
        "http.response.body.bytes",
        "bytes",
        "bytes_sent",
        "body_bytes_sent",
        "response_size",
    ),
    "ua": ("user_agent.original", "user_agent", "useragent", "http_user_agent", "ua"),
    "referrer": ("http.request.referrer", "referrer", "referer", "http_referer"),
    "host": ("host.name", "url.domain", "host", "hostname", "server_name"),
    "level": ("log.level", "level", "severity", "loglevel", "lvl"),
    "message": ("message", "msg", "log", "text"),
    "action": ("event.action", "event", "action", "event_type", "type"),
    "outcome": ("event.outcome", "outcome", "result", "status_text"),
}
_FAILURE_ACTIONS = {
    "login_failed",
    "login_failure",
    "failed_login",
    "auth_failed",
    "auth_failure",
    "authentication_failure",
    "authentication_failed",
    "invalid_password",
    "user_login_failed",
}
_SUCCESS_ACTIONS = {
    "login",
    "login_success",
    "logged_in",
    "auth_success",
    "authentication_success",
    "user_login",
    "user_login_success",
}
_AUTHISH = ("login", "logon", "auth", "signin", "sign_in")
MAX_ATTRIBUTES = 50
MAX_LINE_DEPTH = 3


def _flatten(obj: dict[str, Any], prefix: str = "", depth: int = 0) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and depth < MAX_LINE_DEPTH:
            flat.update(_flatten(value, f"{name}.", depth + 1))
        else:
            flat[name] = value
    return flat


def _pick(flat: dict[str, Any], field: str, used: set[str]) -> Any:
    for key in ALIASES[field]:
        if key in flat and flat[key] not in (None, "", "-"):
            used.add(key)
            return flat[key]
    return None


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))


def _as_int(value: Any, what: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ParseError(f"invalid {what}")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    raise ParseError(f"invalid {what}")


def _classify(action: str | None, outcome: str | None, has_http: bool) -> str:
    a = (action or "").strip().lower().replace("-", "_").replace(" ", "_").replace(".", "_")
    o = (outcome or "").strip().lower()
    if a in _FAILURE_ACTIONS or (any(k in a for k in _AUTHISH) and o in ("failure", "failed")):
        return "auth_failure"
    if a in _SUCCESS_ACTIONS or (any(k in a for k in _AUTHISH) and o == "success"):
        return "auth_success"
    if has_http:
        return "http_request"
    return "app_log"


class JsonParser:
    name = "json"

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ParseError("invalid JSON") from exc
        if not isinstance(obj, dict):
            raise ParseError("JSON value is not an object")
        flat = _flatten(obj)
        used: set[str] = set()
        attributes: dict[str, Any] = {}

        raw_time = _pick(flat, "time", used)
        if raw_time is None:
            raise ParseError("missing timestamp field")
        if isinstance(raw_time, bool):
            raise ParseError("invalid timestamp")
        if isinstance(raw_time, int | float):
            event_time = parse_epoch(float(raw_time), ctx.reference_time)
        elif isinstance(raw_time, str):
            stripped = raw_time.strip()
            if stripped.replace(".", "", 1).isdigit():
                event_time = parse_epoch(float(stripped), ctx.reference_time)
            else:
                event_time = parse_iso_time(stripped, ctx.timezone, ctx.reference_time)
        else:
            raise ParseError("invalid timestamp")

        method = _as_str(_pick(flat, "method", used))
        raw_path = _as_str(_pick(flat, "path", used))
        query = _as_str(_pick(flat, "query", used))
        if raw_path and "?" in raw_path and query is None:
            raw_path, query = raw_path.split("?", 1)
        action = _as_str(_pick(flat, "action", used))
        outcome = _as_str(_pick(flat, "outcome", used))
        raw_status = _pick(flat, "status", used)
        status: int | None = None
        if (
            isinstance(raw_status, int)
            and not isinstance(raw_status, bool)
            or (isinstance(raw_status, str) and raw_status.strip().isdigit())
        ):
            status = int(raw_status)
            if not 100 <= status <= 599:
                raise ParseError("invalid HTTP status")
        elif raw_status is not None:
            # Application logs often use "status": "failed"/"ok"; treat it as the outcome.
            outcome = outcome or _as_str(raw_status)
        has_http = bool(method or status is not None)
        level = _as_str(_pick(flat, "level", used))

        ip = _as_str(_pick(flat, "ip", used))
        user = _as_str(_pick(flat, "user", used))
        size = _as_int(_pick(flat, "bytes", used), "byte count")
        referrer = _as_str(_pick(flat, "referrer", used))
        ua = _as_str(_pick(flat, "ua", used))
        host = _as_str(_pick(flat, "host", used))
        message = _as_str(_pick(flat, "message", used))

        # Everything not mapped to a normalized field is kept (bounded) in attributes.
        for key, value in flat.items():
            if key not in used and len(attributes) < MAX_ATTRIBUTES:
                keep_native = isinstance(value, int | float | bool) or value is None
                attributes[key] = value if keep_native else str(value)[:1024]
        if action:
            attributes.setdefault("action", action[:128])
        if outcome:
            attributes.setdefault("outcome", outcome[:64])

        return ParsedEvent(
            event_time=event_time,
            event_type=_classify(action, outcome, has_http),
            source_ip=clean_ip(ip, attributes),
            username=truncate(user, MAX_USERNAME, attributes, "username"),
            http_method=method.upper()[:32] if method else None,
            path=truncate(raw_path, MAX_PATH, attributes, "path"),
            query=truncate(query, MAX_QUERY, attributes, "query"),
            http_status=status,
            bytes_sent=size,
            referrer=truncate(referrer, MAX_REFERRER, attributes, "referrer"),
            user_agent=truncate(ua, MAX_UA, attributes, "user_agent"),
            host=truncate(host, MAX_HOST, attributes, "host"),
            severity=level.lower()[:16] if level else None,
            message=truncate(message, MAX_MESSAGE, attributes, "message"),
            attributes=attributes,
        )
