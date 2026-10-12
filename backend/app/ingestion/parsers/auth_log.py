"""Linux authentication logs (syslog `auth.log` / `secure`), as written by rsyslog.

Two header styles are accepted:

    Oct 12 10:15:32 web01 sshd[1234]: <message>                  (RFC 3164, traditional)
    2026-10-12T10:15:32.123456+05:30 web01 sshd[1234]: <message>  (RFC 3339, high precision)

The traditional style has no year or time zone: the source's configured time zone is
used and the year is inferred from the upload time. Recognized messages from sshd,
sudo and pam_unix become auth_failure / auth_success events; any other line with a
valid header is kept as auth_other. Lines without a valid header are rejected.
"""

import re
from typing import Any

from app.ingestion.timeparse import parse_iso_time, parse_syslog_time
from app.ingestion.types import (
    MAX_HOST,
    MAX_MESSAGE,
    MAX_USERNAME,
    ParseContext,
    ParsedEvent,
    ParseError,
    clean_ip,
    truncate,
)

_HEADER_3164 = re.compile(
    r"^(?P<time>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
_HEADER_3339 = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?) "
    r"(?P<host>\S+) (?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)

# (pattern, event_type, auth method/subtype)
_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
            r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "auth_failure",
        "failed_{method}",
    ),
    (
        re.compile(
            r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic)"
            r" for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "auth_success",
        "accepted_{method}",
    ),
    (
        re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
        "auth_failure",
        "invalid_user",
    ),
    (
        re.compile(
            r"^pam_unix\((?P<svc>[^)]+)\): authentication failure;.*?"
            r"(?:rhost=(?P<ip>\S*))?\s*(?:user=(?P<user>\S+))?\s*$"
        ),
        "auth_failure",
        "pam_failure",
    ),
    (
        re.compile(
            r"^maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "auth_failure",
        "max_attempts_exceeded",
    ),
    (
        re.compile(
            r"^\s*(?P<user>\S+) : .*?(?:incorrect password attempts|authentication failure)"
        ),
        "auth_failure",
        "sudo_failure",
    ),
    (
        re.compile(
            r"^\s*(?P<user>\S+) : TTY=\S+ ; PWD=.* ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$"
        ),
        "auth_success",
        "sudo_command",
    ),
]


class AuthLogParser:
    name = "auth_log"

    def parse(self, line: str, ctx: ParseContext) -> ParsedEvent:
        m = _HEADER_3164.match(line)
        if m:
            event_time = parse_syslog_time(
                " ".join(m["time"].split()), ctx.timezone, ctx.reference_time
            )
        else:
            m = _HEADER_3339.match(line)
            if m is None:
                raise ParseError("line does not match the syslog auth.log format")
            event_time = parse_iso_time(m["time"], ctx.timezone, ctx.reference_time)

        msg = m["msg"]
        attributes: dict[str, Any] = {"program": m["prog"][:64]}
        if m["pid"]:
            attributes["pid"] = int(m["pid"])
        event_type, user, ip = "auth_other", None, None
        for pattern, etype, subtype in _RULES:
            r = pattern.search(msg)
            if r is None:
                continue
            g = r.groupdict()
            event_type = etype
            user = g.get("user") or None
            ip = g.get("ip") or None
            attributes["auth_event"] = subtype.format(method=g.get("method", ""))
            if g.get("invalid"):
                attributes["invalid_user"] = True
            if g.get("port"):
                attributes["port"] = int(g["port"])
            if g.get("target"):
                attributes["target_user"] = g["target"][:64]
            if g.get("cmd"):
                attributes["command"] = g["cmd"][:512]
            break

        return ParsedEvent(
            event_time=event_time,
            event_type=event_type,
            source_ip=clean_ip(ip, attributes, key="rhost"),
            username=truncate(user, MAX_USERNAME, attributes, "username"),
            host=truncate(m["host"], MAX_HOST, attributes, "host"),
            message=truncate(msg, MAX_MESSAGE, attributes, "message"),
            attributes=attributes,
        )
