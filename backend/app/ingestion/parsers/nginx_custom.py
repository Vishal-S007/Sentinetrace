"""Nginx access logs in a custom `log_format`.

The source stores the log_format string exactly as written in nginx.conf, e.g.

    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
    "$http_referer" "$http_user_agent" rt=$request_time

It is compiled into an anchored regular expression. A variable inside double quotes
matches a quoted value, inside [ ] matches up to ']', otherwise a run of non-spaces.
Known variables map to normalized fields; all others are kept in attributes.
"""

import re
from typing import Any

from app.ingestion.parsers.http_common import (
    QUOTED,
    apply_request_line,
    clean_referrer,
    clean_user_agent,
    parse_bytes,
    parse_status,
    unescape,
)
from app.ingestion.timeparse import parse_clf_time, parse_epoch, parse_iso_time
from app.ingestion.types import (
    MAX_HOST,
    MAX_PATH,
    MAX_QUERY,
    MAX_USERNAME,
    ParseContext,
    ParsedEvent,
    ParseError,
    clean_ip,
    dash_to_none,
    truncate,
)

MAX_PATTERN_LENGTH = 2000
MAX_VARIABLES = 60
TIME_VARIABLES = {"time_local", "time_iso8601", "msec"}
_VAR = re.compile(r"\$(?:\{(\w+)\}|(\w+))")


class PatternError(ValueError):
    """The log_format string can't be used."""


def compile_log_format(log_format: str) -> tuple[re.Pattern[str], list[str]]:
    fmt = " ".join(log_format.split())  # nginx.conf strings are often split across lines
    if not fmt:
        raise PatternError("log_format is empty")
    if len(fmt) > MAX_PATTERN_LENGTH:
        raise PatternError(f"log_format is longer than {MAX_PATTERN_LENGTH} characters")

    parts: list[str] = []
    names: list[str] = []
    pos = 0
    matches = list(_VAR.finditer(fmt))
    if not matches:
        raise PatternError("log_format contains no $variables")
    if len(matches) > MAX_VARIABLES:
        raise PatternError(f"log_format has more than {MAX_VARIABLES} variables")
    for i, m in enumerate(matches):
        before = fmt[pos : m.start()]
        after_end = matches[i + 1].start() if i + 1 < len(matches) else len(fmt)
        after = fmt[m.end() : after_end]
        parts.append(re.escape(before))
        name = m.group(1) or m.group(2)
        if before.endswith('"') and after.startswith('"'):
            value = QUOTED
        elif before.endswith("[") and after.startswith("]"):
            value = r"[^\]]*"
        else:
            value = r"\S*?"
        parts.append(f"(?P<v{i}>{value})")
        names.append(name)
        pos = m.end()
    parts.append(re.escape(fmt[pos:]))

    if not TIME_VARIABLES & set(names):
        raise PatternError("log_format must include $time_local, $time_iso8601 or $msec")
    return re.compile("^" + "".join(parts) + "$"), names


class NginxCustomParser:
    name = "nginx_custom"

    def __init__(self, log_format: str) -> None:
        self.pattern, self.names = compile_log_format(log_format)

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent:
        m = self.pattern.match(line)
        if m is None:
            raise ParseError("line does not match the configured log_format")
        values = {name: m.group(f"v{i}") for i, name in enumerate(self.names)}
        attributes: dict[str, Any] = {}
        out: dict[str, Any] = {}

        if "time_local" in values:
            event_time = parse_clf_time(values["time_local"], ctx.reference_time)
        elif "time_iso8601" in values:
            event_time = parse_iso_time(values["time_iso8601"], ctx.timezone, ctx.reference_time)
        else:
            try:
                event_time = parse_epoch(float(values["msec"]), ctx.reference_time)
            except ValueError as exc:
                raise ParseError("invalid timestamp") from exc

        if "request" in values:
            apply_request_line(values["request"], out, attributes)
        else:
            if "request_method" in values:
                out["http_method"] = dash_to_none(values["request_method"])
            target = values.get("request_uri")
            if target and target != "-":
                path, _, query = target.partition("?")
                out["path"] = truncate(path, MAX_PATH, attributes, "path")
                out["query"] = truncate(query or None, MAX_QUERY, attributes, "query")
            elif "uri" in values:
                out["path"] = truncate(dash_to_none(values["uri"]), MAX_PATH, attributes, "path")
            if "args" in values or "query_string" in values:
                q = dash_to_none(values.get("args") or values.get("query_string"))
                out["query"] = truncate(q, MAX_QUERY, attributes, "query")
            if "server_protocol" in values:
                out["http_version"] = dash_to_none(values["server_protocol"])

        if "status" in values:
            out["http_status"] = parse_status(values["status"])
        size = values.get("body_bytes_sent", values.get("bytes_sent"))
        if size is not None:
            out["bytes_sent"] = parse_bytes(size)

        ip_raw = values.get("remote_addr", values.get("realip_remote_addr"))
        host = values.get("host") or values.get("http_host") or values.get("server_name")

        known = {
            "time_local",
            "time_iso8601",
            "msec",
            "request",
            "request_method",
            "request_uri",
            "uri",
            "args",
            "query_string",
            "server_protocol",
            "status",
            "body_bytes_sent",
            "bytes_sent",
            "remote_addr",
            "realip_remote_addr",
            "remote_user",
            "http_referer",
            "http_user_agent",
            "host",
            "http_host",
            "server_name",
        }
        for name, value in values.items():
            if name not in known and dash_to_none(value) is not None:
                attributes[name] = unescape(value)[:1024]

        return ParsedEvent(
            event_time=event_time,
            event_type="http_request",
            source_ip=clean_ip(ip_raw, attributes),
            username=truncate(
                dash_to_none(values.get("remote_user")), MAX_USERNAME, attributes, "username"
            ),
            referrer=clean_referrer(values.get("http_referer"), attributes),
            user_agent=clean_user_agent(values.get("http_user_agent"), attributes),
            host=truncate(dash_to_none(host), MAX_HOST, attributes, "host"),
            attributes=attributes,
            **out,
        )
