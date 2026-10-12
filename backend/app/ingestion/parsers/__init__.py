"""Parser registry."""

from app.ingestion.parsers.auth_log import AuthLogParser
from app.ingestion.parsers.clf import ApacheCombinedParser, NginxCombinedParser, NginxCommonParser
from app.ingestion.parsers.json_log import JsonParser
from app.ingestion.parsers.nginx_custom import NginxCustomParser, PatternError, compile_log_format
from app.ingestion.types import Parser

FORMAT_INFO: dict[str, dict[str, str]] = {
    "apache_combined": {
        "label": "Apache combined",
        "example": '203.0.113.9 - - [12/Oct/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"',
    },
    "nginx_combined": {
        "label": "Nginx combined (default)",
        "example": '203.0.113.9 - - [12/Oct/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 612 '
        '"-" "curl/8.5.0"',
    },
    "nginx_common": {
        "label": "Nginx / Apache common (CLF)",
        "example": '203.0.113.9 - alice [12/Oct/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 612',
    },
    "nginx_custom": {
        "label": "Nginx custom log_format",
        "example": "Provide the log_format string from nginx.conf, e.g. "
        '$remote_addr [$time_local] "$request" $status rt=$request_time',
    },
    "json": {
        "label": "JSON lines (application / security events)",
        "example": '{"timestamp":"2026-10-12T10:15:32Z","event":"login_failed",'
        '"user":"alice","src_ip":"203.0.113.9"}',
    },
    "auth_log": {
        "label": "Linux auth.log (syslog)",
        "example": "Oct 12 10:15:32 web01 sshd[1234]: Failed password for invalid user admin "
        "from 203.0.113.9 port 52144 ssh2",
    },
}

# Formats tried by auto-detection (nginx_custom needs a pattern; *_combined are identical).
DETECTABLE = ("json", "apache_combined", "nginx_common", "auth_log")


def build_parser(fmt: str, custom_pattern: str | None = None) -> Parser:
    if fmt == "apache_combined":
        return ApacheCombinedParser()
    if fmt == "nginx_combined":
        return NginxCombinedParser()
    if fmt == "nginx_common":
        return NginxCommonParser()
    if fmt == "nginx_custom":
        if not custom_pattern:
            raise PatternError("nginx_custom requires a log_format pattern")
        return NginxCustomParser(custom_pattern)
    if fmt == "json":
        return JsonParser()
    if fmt == "auth_log":
        return AuthLogParser()
    raise ValueError(f"unknown format {fmt!r}")


__all__ = [
    "DETECTABLE",
    "FORMAT_INFO",
    "PatternError",
    "build_parser",
    "compile_log_format",
]
