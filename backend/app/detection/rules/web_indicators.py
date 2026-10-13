"""Per-request indicator rules: SQL injection, XSS, path traversal, suspicious methods.

Request data is URL-decoded (repeatedly, to catch double encoding) and lowercased before
matching. A match is an *indicator* that someone sent a suspicious payload. It is not proof
that the application was vulnerable or that an attack succeeded. Response codes are
reported to help the analyst judge that.
"""

import re
from collections.abc import Sequence
from datetime import datetime, timedelta

from pydantic import Field

from app.detection.base import (
    EventRow,
    Finding,
    Rule,
    RuleConfig,
    bucket_of,
    decode,
    fmt_time,
    iter_fields,
    scan,
    top,
)


class IndicatorConfig(RuleConfig):
    min_matches: int = Field(
        default=1, ge=1, le=10_000, description="Matching requests needed per IP and time bucket"
    )
    include_headers: bool = Field(default=True, description="Also scan User-Agent and Referer")


class _IndicatorRule(Rule):
    """Shared logic: group matching requests per source IP and time bucket."""

    patterns: dict[str, re.Pattern[str]]
    weak: frozenset[str] = frozenset()  # indicators that alone give low confidence
    noun: str
    tool_agents: re.Pattern[str] | None = None

    def match(self, e: EventRow) -> list[str]:
        cfg: IndicatorConfig = self.config  # type: ignore[assignment]
        found: list[str] = []
        for _, value in iter_fields(e, cfg.include_headers):
            if value:
                for name in self._scan(value):
                    if name not in found:
                        found.append(name)
        return found

    def _scan(self, value: str) -> tuple[str, ...]:
        """Decode + scan one field value, memoized: paths and user agents repeat a lot."""
        cache = self.__dict__.setdefault("_scan_cache", {})
        hit = cache.get(value)
        if hit is None:
            if len(cache) > 200_000:
                cache.clear()
            hit = cache[value] = tuple(scan(self.patterns, decode(value)))
        return hit

    def evaluate(
        self, events: Sequence[EventRow], bucket: timedelta, buckets: set[datetime]
    ) -> list[Finding]:
        cfg: IndicatorConfig = self.config  # type: ignore[assignment]
        matched: list[tuple[EventRow, list[str]]] = []
        for e in events:
            if e.source_ip and bucket_of(e.event_time, bucket) in buckets:
                names = self.match(e)
                if names:
                    matched.append((e, names))
        by_group: dict[tuple[str, datetime], list[tuple[EventRow, list[str]]]] = {}
        for e, names in matched:
            by_group.setdefault((e.source_ip, bucket_of(e.event_time, bucket)), []).append(
                (e, names)
            )

        findings = []
        for (ip, b), items in sorted(by_group.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            if len(items) < cfg.min_matches:
                continue
            evs = [e for e, _ in items]
            kinds = sorted({n for _, names in items for n in names})
            statuses = sorted({e.http_status for e in evs if e.http_status is not None})
            tool = bool(
                self.tool_agents
                and any(e.user_agent and self.tool_agents.search(e.user_agent.lower()) for e in evs)
            )
            strong_kinds = [k for k in kinds if k not in self.weak]
            if tool or len(strong_kinds) >= 2 or (strong_kinds and len(evs) >= 5):
                confidence = "high"
            elif strong_kinds:
                confidence = "medium"
            else:
                confidence = "low"
            reasons = []
            if tool:
                reasons.append("the User-Agent identifies a known attack tool")
            reasons.append(f"{len(kinds)} distinct indicator type(s): {', '.join(kinds)}")
            reasons.append(f"{len(evs)} matching request(s)")
            if not strong_kinds:
                reasons.append("only weak indicators matched (common in benign traffic)")
            server_errors = [s for s in statuses if s >= 500]
            outcome = (
                f" Responses included server errors ({', '.join(map(str, server_errors))}),"
                " which can mean the payload reached application code."
                if server_errors
                else ""
            )
            endpoints = top(e.path for e in evs)
            findings.append(
                Finding(
                    entity_key=f"ip={ip}",
                    bucket_start=b,
                    event_ids=[e.id for e in evs],
                    first_seen=evs[0].event_time,
                    last_seen=evs[-1].event_time,
                    title=f"{self.noun} indicators from {ip}",
                    reason=(
                        f"{len(evs)} request(s) from {ip} between "
                        f"{fmt_time(evs[0].event_time)} and "
                        f"{fmt_time(evs[-1].event_time)} contained {self.noun.lower()} patterns "
                        f"({', '.join(kinds)}). Response status codes: "
                        f"{', '.join(map(str, statuses)) or 'none recorded'}.{outcome} "
                        "Indicator only: a matching request does not show the attack succeeded."
                    ),
                    confidence=confidence,
                    confidence_reason="; ".join(reasons).capitalize() + ".",
                    source_ip=ip,
                    endpoint=endpoints[0] if endpoints else None,
                    indicators={e.id: names[0] for e, names in items},
                    details={
                        "indicator_types": kinds,
                        "status_codes": statuses,
                        "top_endpoints": endpoints,
                        "attack_tool_user_agent": tool,
                    },
                )
            )
        return findings


_SQL_TOOLS = re.compile(r"sqlmap|havij|sqlninja|bsqlbf|pangolin")


class SqlInjectionIndicators(_IndicatorRule):
    rule_id = "ST-WEB-001"
    name = "SQL injection indicators in request data"
    category = "web"
    description = (
        "Request path, query string or headers contained SQL injection patterns such as "
        "UNION SELECT, tautologies (' OR 1=1), stacked queries, time-delay functions or "
        "schema probes, after URL-decoding."
    )
    default_severity = "high"
    config_model = IndicatorConfig
    noun = "SQL injection"
    tool_agents = _SQL_TOOLS
    patterns = {
        "union_select": re.compile(r"\bunion\b(?:\s|/\*.*?\*/|\+)+(?:all\s+)?select\b"),
        "tautology": re.compile(
            r"['\"`)]\s*(?:or|and|\|\||&&)\s+['\"`(]?\s*(\w+)\s*['\"`]?\s*(?:=|like)\s*"
            r"['\"`]?\s*\1\b|\b(?:or|and)\s+(\d+)\s*=\s*\2\b"
        ),
        "comment_terminator": re.compile(r"['\"`]\s*(?:--(?:\s|$)|#\s*$|/\*)"),
        "time_based": re.compile(
            r"\b(?:sleep|pg_sleep)\s*\(\s*\d|waitfor\s+delay\s+'|\bbenchmark\s*\("
        ),
        "stacked_query": re.compile(
            r";\s*(?:drop|insert|update|delete|create|alter|exec|truncate)\s+\w"
        ),
        "schema_probe": re.compile(
            r"information_schema|sqlite_master|pg_catalog|sys\.tables|"
            r"mysql\.user|@@version"
        ),
        "error_based": re.compile(r"\b(?:extractvalue|updatexml)\s*\(|convert\s*\(\s*int\s*,"),
        "xp_cmdshell": re.compile(r"xp_cmdshell|sp_executesql"),
    }
    weak = frozenset({"comment_terminator"})
    recommended_steps = [
        "Review the matching requests and the endpoints they targeted.",
        "Check application and database logs at the same timestamps for SQL errors or "
        "unusual queries.",
        "Pay special attention to requests that returned 5xx or unusually large responses.",
        "Confirm the endpoint uses parameterized queries; if unsure, test it in a safe "
        "environment.",
        "Consider blocking the source IP and adding a WAF rule while investigating.",
    ]


class XssIndicators(_IndicatorRule):
    rule_id = "ST-WEB-002"
    name = "Cross-site scripting (XSS) indicators in request data"
    category = "web"
    description = (
        "Request data contained script tags, event-handler attributes, javascript: URLs or "
        "DOM-access payloads typical of reflected or stored XSS probing."
    )
    default_severity = "medium"
    config_model = IndicatorConfig
    noun = "Cross-site scripting"
    patterns = {
        "script_tag": re.compile(r"<\s*/?\s*script\b"),
        "event_handler": re.compile(
            r"<[^>]*\bon(?:error|load|mouseover|focus|click|toggle|begin|animationstart)\s*="
        ),
        "javascript_uri": re.compile(r"javascript\s*:"),
        "html_injection": re.compile(r"<\s*(?:svg|img|iframe|body|details|object|embed)\b"),
        "dom_access": re.compile(
            r"document\s*\.\s*(?:cookie|domain|write)|\b(?:alert|prompt|confirm)\s*\(\s*"
            r"(?:\d|['\"`]|document)"
        ),
    }
    weak = frozenset({"html_injection"})
    recommended_steps = [
        "Review the targeted pages: is the parameter reflected in the response?",
        "For stored-XSS suspicion, check whether the payload was saved (e.g. comments, "
        "profile fields) and where it is displayed.",
        "Verify output encoding and Content-Security-Policy on the affected pages.",
        "Look for follow-up requests suggesting a working payload (e.g. cookie exfiltration).",
    ]


class PathTraversalIndicators(_IndicatorRule):
    rule_id = "ST-WEB-003"
    name = "Path traversal indicators"
    category = "web"
    description = (
        "Request data contained directory-traversal sequences (../, encoded or doubly "
        "encoded) or references to sensitive system files such as /etc/passwd or win.ini."
    )
    default_severity = "high"
    config_model = IndicatorConfig
    noun = "Path traversal"
    patterns = {
        "dot_dot_slash": re.compile(r"(?:^|[/\\=])\.\.[/\\]"),
        "sensitive_file": re.compile(
            r"/etc/(?:passwd|shadow|hosts|group)\b|win\.ini|boot\.ini|/proc/self/|"
            r"c:[/\\]windows|\.htpasswd|web\.config|id_rsa\b|/\.ssh/"
        ),
        "null_byte": re.compile(r"\x00"),
    }
    recommended_steps = [
        "Check the response status and size of each matching request; a 200 with a large "
        "body to a traversal payload warrants urgent review.",
        "Identify which endpoint accepts file paths and confirm it canonicalizes and "
        "restricts them to an allowed directory.",
        "Search for other requests from this IP for sensitive files or configuration.",
    ]

    def match(self, e: EventRow) -> list[str]:
        found = super().match(e)
        raw = f"{e.path or ''}?{e.query or ''}".lower()
        if "%252e" in raw or "%25%32%65" in raw:
            found.append("double_encoding")
        return found


class SuspiciousMethodsConfig(IndicatorConfig):
    allowed_methods: list[str] = Field(
        default=["GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"],
        min_length=1,
        max_length=50,
    )
    include_malformed: bool = True


class SuspiciousMethods(_IndicatorRule):
    rule_id = "ST-WEB-007"
    name = "Suspicious HTTP methods and malformed requests"
    category = "web"
    description = (
        "Requests used HTTP methods outside the allowed list (e.g. TRACE, TRACK, CONNECT, "
        "PROPFIND, DEBUG) or had a malformed request line, e.g. TLS bytes sent to a "
        "plain-HTTP port or protocol fuzzing."
    )
    default_severity = "low"
    config_model = SuspiciousMethodsConfig
    noun = "Suspicious method or malformed request"
    patterns = {}
    weak = frozenset({"malformed_request"})
    recommended_steps = [
        "Check whether the method is legitimately used (e.g. WebDAV clients use PROPFIND).",
        "Malformed requests are usually scanners or misdirected TLS clients; correlate with "
        "other alerts from the same IP.",
        "Disable unused methods (TRACE/TRACK) at the web server.",
    ]

    def match(self, e: EventRow) -> list[str]:
        cfg: SuspiciousMethodsConfig = self.config  # type: ignore[assignment]
        found = []
        if cfg.include_malformed and e.attributes.get("malformed_request"):
            found.append("malformed_request")
        allowed = {m.upper() for m in cfg.allowed_methods}
        if e.http_method and e.http_method.upper() not in allowed:
            found.append(f"method_{e.http_method.lower()[:16]}")
        return found
