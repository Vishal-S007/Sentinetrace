"""Apache/Nginx Common Log Format and Combined Log Format.

Combined (Apache `combined`, Nginx default `combined`):
    127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "http://ref/" "UA"
Common (CLF; Nginx/Apache `common`):
    127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326
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
)
from app.ingestion.timeparse import parse_clf_time
from app.ingestion.types import (
    MAX_USERNAME,
    ParseContext,
    ParsedEvent,
    ParseError,
    clean_ip,
    dash_to_none,
    truncate,
)

_PREFIX = (
    r"(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    rf'"(?P<request>{QUOTED})" (?P<status>\S+) (?P<bytes>\S+)'
)
COMMON_RE = re.compile(rf"^{_PREFIX}$")
COMBINED_RE = re.compile(rf'^{_PREFIX} "(?P<referrer>{QUOTED})" "(?P<ua>{QUOTED})"$')


class _ClfParser:
    name = "clf"
    pattern: re.Pattern[str] = COMMON_RE

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent:
        m = self.pattern.match(line)
        if m is None:
            raise ParseError(f"line does not match {self.name} format")
        g = m.groupdict()
        attributes: dict[str, Any] = {}
        out: dict[str, Any] = {}
        apply_request_line(g["request"], out, attributes)
        ident = dash_to_none(g["ident"])
        if ident:
            attributes["ident"] = ident
        return ParsedEvent(
            event_time=parse_clf_time(g["time"], ctx.reference_time),
            event_type="http_request",
            source_ip=clean_ip(g["host"], attributes),
            username=truncate(dash_to_none(g["user"]), MAX_USERNAME, attributes, "username"),
            http_status=parse_status(g["status"]),
            bytes_sent=parse_bytes(g["bytes"]),
            referrer=clean_referrer(g.get("referrer"), attributes),
            user_agent=clean_user_agent(g.get("ua"), attributes),
            attributes=attributes,
            **out,
        )


class ApacheCombinedParser(_ClfParser):
    name = "apache_combined"
    pattern = COMBINED_RE


class NginxCombinedParser(_ClfParser):
    name = "nginx_combined"
    pattern = COMBINED_RE


class NginxCommonParser(_ClfParser):
    name = "nginx_common"
    pattern = COMMON_RE
