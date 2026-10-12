"""Unit tests for parsers, timestamp normalization and format detection (no database)."""

from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from app.ingestion.detect import detect_format
from app.ingestion.parsers import PatternError, build_parser, compile_log_format
from app.ingestion.timeparse import parse_epoch, parse_iso_time, parse_syslog_time
from app.ingestion.types import ParseContext, ParseError

FIXTURES = Path(__file__).parent / "fixtures" / "logs"
REF = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
CTX = ParseContext(timezone=UTC, reference_time=REF)
NGINX_CUSTOM = (
    '$remote_addr [$time_iso8601] "$request" $status $body_bytes_sent rt=$request_time '
    'ua="$http_user_agent" xff="$http_x_forwarded_for"'
)


def lines(name: str) -> list[str]:
    return [ln for ln in (FIXTURES / name).read_text().splitlines() if ln.strip()]


def parse_all(fmt: str, name: str, ctx: ParseContext = CTX, pattern: str | None = None):
    parser = build_parser(fmt, pattern)
    ok, bad = [], []
    for ln in lines(name):
        try:
            ok.append(parser.parse(ln, ctx))
        except ParseError as exc:
            bad.append((ln, str(exc)))
    return ok, bad


# --- Apache / Nginx CLF ------------------------------------------------------------------


def test_apache_combined_valid_fixture():
    ok, bad = parse_all("apache_combined", "apache_combined_valid.log")
    assert len(ok) == 6 and bad == []
    first, sqli, ipv6, tls, xss = ok[0], ok[2], ok[3], ok[4], ok[5]
    assert first.event_time == datetime(2026, 10, 10, 13, 55, 36, tzinfo=UTC)
    assert (first.http_method, first.path, first.http_status, first.bytes_sent) == (
        "GET",
        "/index.html",
        200,
        2326,
    )
    assert first.referrer == "https://example.com/" and first.user_agent.startswith("Mozilla")
    # +0530 offset normalized to UTC
    assert sqli.event_time == datetime(2026, 10, 10, 13, 55, 38, tzinfo=UTC)
    assert sqli.path == "/products" and "OR" in sqli.query
    assert ipv6.source_ip == "2001:db8::42" and ipv6.username == "alice"
    # Malformed request lines are kept (they are a detection signal), and flagged.
    assert tls.attributes["malformed_request"] is True and tls.http_method is None
    assert tls.http_status == 400
    # Escaped quotes inside the request are unescaped; content is stored as data.
    assert xss.query == 'q="<script>alert(1)</script>"'


def test_apache_combined_rejects_malformed_lines_with_reasons():
    ok, bad = parse_all("apache_combined", "apache_combined_mixed.log")
    assert len(ok) == 5 and len(bad) == 3
    reasons = sorted(r for _, r in bad)
    assert reasons == [
        "invalid HTTP status",
        "invalid timestamp",
        "line does not match apache_combined format",
    ]
    minus7 = next(e for e in ok if e.path == "/d")
    assert minus7.event_time == datetime(2026, 10, 10, 21, 0, 5, tzinfo=UTC)


def test_nginx_common_fixture():
    ok, bad = parse_all("nginx_common", "nginx_common.log")
    assert len(ok) == 4 and bad == []
    assert ok[1].username == "bob" and ok[1].http_status == 403
    assert ok[2].http_method == "PROPFIND"
    assert ok[3].path == "/../../etc/passwd"
    assert ok[0].referrer is None and ok[0].user_agent is None


def test_combined_parser_rejects_common_lines_and_vice_versa():
    common_line = lines("nginx_common.log")[0]
    combined_line = lines("apache_combined_valid.log")[0]
    with pytest.raises(ParseError):
        build_parser("apache_combined").parse(common_line, CTX)
    with pytest.raises(ParseError):
        build_parser("nginx_common").parse(combined_line, CTX)


def test_clf_requires_offset_and_rejects_future():
    base = '1.2.3.4 - - [{t}] "GET / HTTP/1.1" 200 1'
    p = build_parser("nginx_common")
    with pytest.raises(ParseError, match="invalid timestamp"):
        p.parse(base.format(t="10/Oct/2026:13:55:36"), CTX)
    with pytest.raises(ParseError, match="future"):
        p.parse(base.format(t="10/Oct/2030:13:55:36 +0000"), CTX)


def test_hostname_instead_of_ip_kept_as_attribute():
    e = build_parser("nginx_common").parse(
        'proxy.internal - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1', CTX
    )
    assert e.source_ip is None and e.attributes["remote_host"] == "proxy.internal"


def test_long_fields_are_truncated_and_flagged():
    long_path = "/" + "a" * 5000
    e = build_parser("nginx_common").parse(
        f'1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET {long_path} HTTP/1.1" 200 1', CTX
    )
    assert len(e.path) == 2048 and "path" in e.attributes["truncated_fields"]


# --- Nginx custom ------------------------------------------------------------------------


def test_nginx_custom_fixture():
    ok, bad = parse_all("nginx_custom", "nginx_custom.log", pattern=NGINX_CUSTOM)
    assert len(ok) == 2 and len(bad) == 1
    assert bad[0][1] == "line does not match the configured log_format"
    first, second = ok
    assert first.path == "/api/items" and first.query == "page=2" and first.bytes_sent == 1532
    assert first.attributes["request_time"] == "0.012"
    assert "http_x_forwarded_for" not in first.attributes  # "-" means absent
    assert second.http_method == "DELETE" and second.http_status == 204
    assert second.attributes["http_x_forwarded_for"] == "10.0.0.8"
    assert second.user_agent == "python-requests/2.32"


@pytest.mark.parametrize(
    "pattern,message",
    [
        ("", "empty"),
        ("no variables here", "no $variables"),
        ('$remote_addr "$request" $status', "must include $time_local"),
        ("$time_local " + "$x " * 70, "more than"),
    ],
)
def test_nginx_custom_pattern_validation(pattern, message):
    with pytest.raises(PatternError, match=message.replace("$", r"\$")):
        compile_log_format(pattern)


def test_nginx_custom_multiline_pattern_and_braces():
    regex, names = compile_log_format('${remote_addr} [$time_local]\n   "$request" $status')
    assert names == ["remote_addr", "time_local", "request", "status"]
    assert regex.match('1.2.3.4 [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200')


# --- JSON --------------------------------------------------------------------------------


def test_json_fixture():
    ctx = ParseContext(timezone=ZoneInfo("Asia/Kolkata"), reference_time=REF)
    ok, bad = parse_all("json", "app_events.jsonl", ctx=ctx)
    assert len(ok) == 6 and len(bad) == 3
    assert sorted(r for _, r in bad) == [
        "JSON value is not an object",
        "invalid JSON",
        "missing timestamp field",
    ]
    fail, success, app_err, http, fail2, heartbeat = ok
    assert (fail.event_type, fail.username, fail.source_ip) == (
        "auth_failure",
        "alice",
        "198.51.100.20",
    )
    assert fail.message == "bad password"
    # ECS nested fields; +02:00 normalized
    assert success.event_type == "auth_success" and success.severity == "info"
    assert success.event_time == datetime(2026, 10, 10, 7, 0, 5, 250000, tzinfo=UTC)
    # epoch milliseconds
    assert app_err.event_time == datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
    assert app_err.event_type == "app_log" and app_err.severity == "error"
    assert app_err.attributes == {"service": "billing", "retry": 3}
    # naive timestamp uses the source time zone (Asia/Kolkata = UTC+05:30)
    assert http.event_time == datetime(2026, 10, 10, 3, 30, 10, tzinfo=UTC)
    assert (http.event_type, http.http_method, http.path, http.query, http.http_status) == (
        "http_request",
        "GET",
        "/api/orders",
        "limit=10",
        200,
    )
    assert fail2.event_type == "auth_failure" and fail2.source_ip is None
    assert fail2.attributes["remote_host"] == "not-an-ip"
    assert heartbeat.event_type == "app_log" and heartbeat.attributes["outcome"] == "ok"


@pytest.mark.parametrize(
    "bad",
    [
        '{"timestamp": true}',
        '{"timestamp": "yesterday"}',
        '{"timestamp":"2026-10-10T00:00:00Z","status":1000}',
    ],
)
def test_json_invalid_values(bad):
    with pytest.raises(ParseError):
        build_parser("json").parse(bad, CTX)


def test_json_deeply_nested_is_bounded():
    deep = '{"timestamp":"2026-10-10T00:00:00Z","a":' + '{"b":' * 50 + "1" + "}" * 51
    e = build_parser("json").parse(deep, CTX)
    assert e.event_type == "app_log"


# --- auth.log ----------------------------------------------------------------------------


def test_auth_log_fixture():
    ctx = ParseContext(timezone=ZoneInfo("Asia/Kolkata"), reference_time=REF)
    ok, bad = parse_all("auth_log", "auth.log", ctx=ctx)
    assert len(ok) == 8 and len(bad) == 1
    by_event = [(e.event_type, e.attributes.get("auth_event"), e.username, e.source_ip) for e in ok]
    assert by_event == [
        ("auth_failure", "failed_password", "admin", "203.0.113.5"),
        ("auth_failure", "failed_password", "root", "203.0.113.5"),
        ("auth_success", "accepted_publickey", "deploy", "10.0.0.5"),
        ("auth_failure", "invalid_user", "oracle", "203.0.113.9"),
        ("auth_success", "sudo_command", "alice", None),
        ("auth_failure", "pam_failure", "root", "203.0.113.5"),
        ("auth_other", None, None, None),
        ("auth_failure", "failed_password", "bob", "198.51.100.7"),
    ]
    assert ok[0].attributes["invalid_user"] is True and ok[0].attributes["port"] == 52144
    # syslog time in the source zone (IST) -> UTC
    assert ok[0].event_time == datetime(2026, 10, 10, 4, 45, 32, tzinfo=UTC)
    assert ok[0].host == "web01" and ok[0].attributes["program"] == "sshd"
    assert ok[4].attributes["command"] == "/usr/bin/systemctl restart nginx"
    # RFC 3339 header with its own offset
    assert ok[7].event_time == datetime(2026, 10, 10, 4, 49, 0, 123456, tzinfo=UTC)


def test_syslog_year_inference_across_new_year():
    jan_ref = datetime(2027, 1, 2, 0, 0, tzinfo=UTC)
    assert parse_syslog_time("Dec 31 23:59:59", UTC, jan_ref).year == 2026
    assert parse_syslog_time("Jan  1 00:00:01", UTC, jan_ref).year == 2027


@pytest.mark.parametrize("value", ["Foo 10 10:00:00", "Oct 32 10:00:00", "Oct 10 25:00:00"])
def test_syslog_bad_times(value):
    with pytest.raises(ParseError):
        parse_syslog_time(value, UTC, REF)


# --- Timestamps --------------------------------------------------------------------------


def test_iso_and_epoch_normalization():
    ist = ZoneInfo("Asia/Kolkata")
    assert parse_iso_time("2026-10-10T10:00:00Z", ist, REF) == datetime(
        2026, 10, 10, 10, tzinfo=UTC
    )
    assert parse_iso_time("2026-10-10T10:00:00", ist, REF) == datetime(
        2026, 10, 10, 4, 30, tzinfo=UTC
    )
    assert parse_epoch(1791622800, REF) == parse_epoch(1791622800000, REF)
    with pytest.raises(ParseError, match="old"):
        parse_epoch(0, REF)


def test_dst_aware_source_timezone():
    ny = ZoneInfo("America/New_York")
    summer = parse_iso_time("2026-07-01T12:00:00", ny, REF)
    winter = parse_iso_time("2026-01-15T12:00:00", ny, REF)
    assert summer.hour == 16 and winter.hour == 17


# --- Detection ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("apache_combined_valid.log", "apache_combined"),
        ("nginx_common.log", "nginx_common"),
        ("app_events.jsonl", None),  # only 6/9 valid: below the confidence threshold
        ("auth.log", "auth_log"),
    ],
)
def test_detect_format(fixture, expected):
    assert detect_format(lines(fixture), CTX).format == expected


def test_detect_json_when_clean():
    sample = [
        ln
        for ln in lines("app_events.jsonl")
        if ln.startswith("{") and "timestamp" in ln and "broken" not in ln
    ]
    assert detect_format(sample, CTX).format == "json"


def test_detect_unknown_content():
    d = detect_format(["hello world", "foo bar"], CTX)
    assert d.format is None and d.confidence == 0.0
