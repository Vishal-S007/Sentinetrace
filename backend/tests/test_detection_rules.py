"""Every rule with positive and negative fixtures (events built directly in the DB)."""

import pytest
from sqlalchemy import select

from app.models import AlertEvent
from tests.detection_helpers import EventFactory, alerts, detect

ATTACKER = "203.0.113.66"
BENIGN = "198.51.100.10"


@pytest.fixture
def ev(db):
    return EventFactory(db)


def only_rule(db, settings, rule_id):
    detect(db, settings, only=[rule_id])
    return alerts(db, rule_id)


# --- ST-AUTH-001 Repeated authentication failures ------------------------------------------


def test_auth001_five_failures_in_window(db, settings, ev):
    ev.many(5, 0, 30, event_type="auth_failure", username="alice", source_ip=ATTACKER)
    [a] = only_rule(db, settings, "ST-AUTH-001")
    assert (a.username, str(a.source_ip), a.event_count) == ("alice", ATTACKER, 5)
    assert a.confidence == "medium" and "Indicator only" in a.reason


@pytest.mark.parametrize("case", ["four_failures", "spread_out", "different_users"])
def test_auth001_negatives(db, settings, ev, case):
    if case == "four_failures":
        ev.many(4, 0, 30, event_type="auth_failure", username="alice", source_ip=ATTACKER)
    elif case == "spread_out":  # 5 failures, 6 minutes apart (window is 5 minutes)
        ev.many(5, 0, 360, event_type="auth_failure", username="alice", source_ip=ATTACKER)
    else:
        for i in range(5):
            ev.add(i * 10, event_type="auth_failure", username=f"user{i}", source_ip=ATTACKER)
    assert only_rule(db, settings, "ST-AUTH-001") == []


def test_auth001_high_confidence_at_twice_threshold(db, settings, ev):
    ev.many(10, 0, 5, event_type="auth_failure", username="root", source_ip=ATTACKER)
    [a] = only_rule(db, settings, "ST-AUTH-001")
    assert a.confidence == "high" and a.event_count == 10


# --- ST-AUTH-002 Brute force / spraying ----------------------------------------------------


def test_auth002_volume(db, settings, ev):
    ev.many(20, 0, 10, event_type="auth_failure", username="admin", source_ip=ATTACKER)
    [a] = only_rule(db, settings, "ST-AUTH-002")
    assert a.event_count == 20 and a.severity == "high"


def test_auth002_password_spraying_distinct_users(db, settings, ev):
    for i in range(5):
        ev.add(i * 20, event_type="auth_failure", username=f"user{i}", source_ip=ATTACKER)
    [a] = only_rule(db, settings, "ST-AUTH-002")
    assert a.confidence == "high" and "spraying" in a.confidence_reason
    assert a.details["targeted_users"] == [f"user{i}" for i in range(5)]


def test_auth002_success_after_failures_is_highlighted(db, settings, ev):
    ev.many(20, 0, 5, event_type="auth_failure", username="admin", source_ip=ATTACKER)
    win = ev.add(200, event_type="auth_success", username="admin", source_ip=ATTACKER)
    ev.flush()
    [a] = only_rule(db, settings, "ST-AUTH-002")
    assert a.confidence == "high" and "successful login" in a.reason
    assert "does not confirm" in a.reason
    link = db.scalar(select(AlertEvent).where(AlertEvent.event_id == win.id))
    assert link.indicator == "auth_success_after_failures"


@pytest.mark.parametrize("case", ["below_volume", "below_users", "other_ips"])
def test_auth002_negatives(db, settings, ev, case):
    if case == "below_volume":
        ev.many(19, 0, 10, event_type="auth_failure", username="admin", source_ip=ATTACKER)
    elif case == "below_users":
        for i in range(4):
            ev.add(i * 20, event_type="auth_failure", username=f"user{i}", source_ip=ATTACKER)
    else:  # 20 failures, but each from a different IP
        for i in range(20):
            ev.add(i, event_type="auth_failure", username="admin", source_ip=f"192.0.2.{i + 1}")
    ev.flush()
    assert only_rule(db, settings, "ST-AUTH-002") == []


# --- ST-WEB-001 SQL injection -----------------------------------------------------------------

SQLI = {
    "union_select": "id=1%20UNION%20ALL%20SELECT%20username,password%20FROM%20users",
    "tautology": "user=admin%27%20OR%20%271%27%3D%271",
    "time_based": "id=1;SELECT%20pg_sleep(5)",
    "stacked_query": "id=1;%20DROP%20TABLE%20users",
    "schema_probe": "q=1%20and%20(select%201%20from%20information_schema.tables)",
    "error_based": "id=extractvalue(1,concat(0x7e,version()))",
    "double_encoded_union": "id=1%2520union%2520select%25201",
}


@pytest.mark.parametrize("name,query", SQLI.items())
def test_web001_patterns(db, settings, ev, name, query):
    ev.add(0, source_ip=ATTACKER, path="/products", query=query, http_status=500)
    [a] = only_rule(db, settings, "ST-WEB-001")
    expected = "union_select" if name == "double_encoded_union" else name
    assert expected in a.details["indicator_types"]
    assert "server errors" in a.reason  # 500 response is called out
    assert "does not show the attack succeeded" in a.reason


def test_web001_attack_tool_user_agent_gives_high_confidence(db, settings, ev):
    ev.add(
        0, source_ip=ATTACKER, path="/p", query="id=1%27%20--%20", user_agent="sqlmap/1.7.2#stable"
    )
    [a] = only_rule(db, settings, "ST-WEB-001")
    assert a.confidence == "high" and a.details["attack_tool_user_agent"] is True


def test_web001_payload_in_header_when_enabled(db, settings, ev):
    ev.add(0, source_ip=ATTACKER, path="/", user_agent="x' UNION SELECT 1--")
    assert len(only_rule(db, settings, "ST-WEB-001")) == 1


BENIGN_QUERIES = [
    "q=select+your+size",
    "name=O%27Brien",
    "q=union+station+chicago",
    "sort=created_at+desc",
    "q=it%27s--great",
    "q=1%3D1+is+true+in+math",
    "page=2&order=update+time",
    "q=drop+shipping",
    "title=Rock+%26+Roll",
]


@pytest.mark.parametrize("query", BENIGN_QUERIES)
def test_web001_benign_queries_do_not_alert(db, settings, ev, query):
    ev.add(0, source_ip=BENIGN, path="/search", query=query)
    assert only_rule(db, settings, "ST-WEB-001") == []


# --- ST-WEB-002 XSS ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value,indicator",
    [
        ("query", "q=%3Cscript%3Ealert(1)%3C/script%3E", "script_tag"),
        ("query", "name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E", "event_handler"),
        ("query", "next=javascript:alert(1)", "javascript_uri"),
        ("referrer", "https://x/?q=<svg/onload=prompt(1)>", "event_handler"),
        ("user_agent", "<script>document.write(1)</script>", "script_tag"),
    ],
)
def test_web002_patterns(db, settings, ev, field, value, indicator):
    ev.add(0, source_ip=ATTACKER, path="/comment", **{field: value})
    [a] = only_rule(db, settings, "ST-WEB-002")
    assert indicator in a.details["indicator_types"]


@pytest.mark.parametrize(
    "query",
    [
        "q=scripting+tutorial",
        "q=a%3Cb+and+c%3Eb",
        "page=description",
        "q=on+error+resume+next",
        "q=javascript+book",
    ],
)
def test_web002_benign(db, settings, ev, query):
    ev.add(0, source_ip=BENIGN, path="/search", query=query)
    assert only_rule(db, settings, "ST-WEB-002") == []


def test_web002_weak_only_is_low_confidence(db, settings, ev):
    ev.add(0, source_ip=ATTACKER, path="/x", query="bio=%3Cimg+src%3Dcat.png%3E")
    [a] = only_rule(db, settings, "ST-WEB-002")
    assert a.confidence == "low"


def test_headers_can_be_excluded_by_config(db, settings, ev):
    from app.models import DetectionRule

    rule = db.get(DetectionRule, "ST-WEB-002")
    rule.config = {**rule.config, "include_headers": False}
    ev.add(0, source_ip=ATTACKER, path="/", user_agent="<script>alert(1)</script>")
    assert only_rule(db, settings, "ST-WEB-002") == []


# --- ST-WEB-003 Path traversal ----------------------------------------------------------------


@pytest.mark.parametrize(
    "path,query,indicator",
    [
        ("/../../etc/passwd", None, "dot_dot_slash"),
        ("/download", "file=..%2F..%2F..%2Fetc%2Fshadow", "sensitive_file"),
        ("/static/%252e%252e%252fwin.ini", None, "double_encoding"),
        ("/view", "page=..%5C..%5Cwindows%5Cwin.ini", "dot_dot_slash"),
        ("/proc/self/environ", None, "sensitive_file"),
    ],
)
def test_web003_patterns(db, settings, ev, path, query, indicator):
    ev.add(0, source_ip=ATTACKER, path=path, query=query, http_status=400)
    [a] = only_rule(db, settings, "ST-WEB-003")
    assert indicator in a.details["indicator_types"]


@pytest.mark.parametrize(
    "path,query",
    [
        ("/docs/v1.2/guide", None),
        ("/files/report..pdf", None),
        ("/static/app..min.js", None),
        ("/search", "q=etc+passwords+manager"),
    ],
)
def test_web003_benign(db, settings, ev, path, query):
    ev.add(0, source_ip=BENIGN, path=path, query=query)
    assert only_rule(db, settings, "ST-WEB-003") == []


# --- ST-WEB-004 Request burst -----------------------------------------------------------------


def test_web004_burst(db, settings, ev):
    ev.many(300, 0, 0.1, source_ip=ATTACKER)
    [a] = only_rule(db, settings, "ST-WEB-004")
    assert a.event_count == 300 and a.details["peak_in_window"] == 300


def test_web004_just_below_threshold(db, settings, ev):
    ev.many(299, 0, 0.1, source_ip=BENIGN)
    assert only_rule(db, settings, "ST-WEB-004") == []


def test_web004_steady_traffic_below_rate(db, settings, ev):
    ev.many(1000, 0, 1.0, source_ip=BENIGN)  # 60 per minute for ~17 minutes
    assert only_rule(db, settings, "ST-WEB-004") == []


def test_web004_large_burst_is_one_alert_with_capped_evidence(db, settings, ev):
    settings.max_evidence_per_alert = 500
    ev.many(5000, 0, 0.05, source_ip=ATTACKER)  # 5,000 requests in ~4 minutes
    [a] = only_rule(db, settings, "ST-WEB-004")
    assert a.event_count == 5000 and a.evidence_truncated is True
    links = db.scalars(select(AlertEvent).where(AlertEvent.alert_id == a.id)).all()
    assert len(links) == 500
    assert a.confidence == "high"


def test_web004_burst_straddling_bucket_boundary_is_detected_once(db, settings, ev):
    # 150 requests in the last 30s of the 10:00 bucket + 150 in the first 30s of 11:00.
    ev.many(150, 3600 - 30, 0.2, source_ip=ATTACKER)
    ev.many(150, 3600, 0.2, source_ip=ATTACKER)
    [a] = only_rule(db, settings, "ST-WEB-004")
    assert a.event_count == 300
    assert a.bucket_start.hour == 11  # where the threshold was crossed


# --- ST-WEB-005 Repeated 401/403 ---------------------------------------------------------------


def test_web005_positive(db, settings, ev):
    ev.many(10, 0, 5, source_ip=ATTACKER, path="/api/admin", http_status=401)
    ev.many(5, 60, 5, source_ip=ATTACKER, path="/internal", http_status=403)
    [a] = only_rule(db, settings, "ST-WEB-005")
    assert a.details["count_401"] == 10 and a.details["count_403"] == 5


@pytest.mark.parametrize("count,step", [(14, 5), (15, 60)])  # too few; too slow
def test_web005_negative(db, settings, ev, count, step):
    ev.many(count, 0, step, source_ip=BENIGN, http_status=403)
    assert only_rule(db, settings, "ST-WEB-005") == []


def test_web005_ignores_other_statuses(db, settings, ev):
    ev.many(50, 0, 1, source_ip=BENIGN, http_status=200)
    assert only_rule(db, settings, "ST-WEB-005") == []


# --- ST-WEB-006 404 burst / recon ------------------------------------------------------------

SCANNER = [
    "/.env",
    "/.git/config",
    "/wp-admin/",
    "/phpmyadmin/",
    "/server-status",
    "/backup.zip",
    "/actuator/health",
]


def test_web006_scanner_paths_high_confidence(db, settings, ev):
    for i in range(30):
        ev.add(
            i * 2,
            source_ip=ATTACKER,
            http_status=404,
            path=SCANNER[i % len(SCANNER)] if i < 7 else f"/random-{i}",
        )
    [a] = only_rule(db, settings, "ST-WEB-006")
    assert a.confidence == "high" and len(a.details["scanner_paths"]) == 7


def test_web006_distinct_paths_threshold(db, settings, ev):
    for i in range(20):
        ev.add(i * 3, source_ip=ATTACKER, http_status=404, path=f"/page-{i}")
    [a] = only_rule(db, settings, "ST-WEB-006")
    assert a.confidence == "medium" and a.details["distinct_paths"] == 20


def test_web006_occasional_404s_are_fine(db, settings, ev):
    ev.many(10, 0, 30, source_ip=BENIGN, http_status=404, path="/favicon.ico")
    assert only_rule(db, settings, "ST-WEB-006") == []


# --- ST-WEB-007 Suspicious methods / malformed -------------------------------------------------


@pytest.mark.parametrize(
    "method,attrs,indicator",
    [
        ("TRACE", {}, "method_trace"),
        ("PROPFIND", {}, "method_propfind"),
        (None, {"malformed_request": True}, "malformed_request"),
    ],
)
def test_web007_positive(db, settings, ev, method, attrs, indicator):
    ev.add(0, source_ip=ATTACKER, http_method=method, attributes=attrs, http_status=400)
    [a] = only_rule(db, settings, "ST-WEB-007")
    assert indicator in a.details["indicator_types"]


def test_web007_normal_methods(db, settings, ev):
    for m in ("GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
        ev.add(0, source_ip=BENIGN, http_method=m)
    assert only_rule(db, settings, "ST-WEB-007") == []


def test_web007_allowed_methods_configurable(db, settings, ev):
    from app.models import DetectionRule

    rule = db.get(DetectionRule, "ST-WEB-007")
    rule.config = {**rule.config, "allowed_methods": [*rule.config["allowed_methods"], "PROPFIND"]}
    ev.add(0, source_ip=BENIGN, http_method="PROPFIND")
    assert only_rule(db, settings, "ST-WEB-007") == []


# --- ST-CORR-001 Correlation -------------------------------------------------------------------


def _recon_and_sqli(ev, ip):
    for i in range(30):
        ev.add(i, source_ip=ip, http_status=404, path=f"/probe-{i}")
    ev.add(100, source_ip=ip, path="/item", query="id=1%20union%20select%201,2")
    ev.flush()


def test_corr001_two_rules_same_ip(db, settings, ev):
    _recon_and_sqli(ev, ATTACKER)
    detect(db, settings)
    [corr] = alerts(db, "ST-CORR-001")
    assert corr.details["member_rules"] == ["ST-WEB-001", "ST-WEB-006"]
    assert str(corr.source_ip) == ATTACKER and corr.confidence == "high"
    assert corr.event_count == 31


def test_corr001_single_rule_does_not_correlate(db, settings, ev):
    for i in range(30):
        ev.add(i, source_ip=ATTACKER, http_status=404, path=f"/probe-{i}")
    detect(db, settings)
    assert alerts(db, "ST-WEB-006") and alerts(db, "ST-CORR-001") == []


def test_corr001_different_ips_do_not_correlate(db, settings, ev):
    for i in range(30):
        ev.add(i, source_ip=ATTACKER, http_status=404, path=f"/probe-{i}")
    ev.add(100, source_ip="192.0.2.200", path="/item", query="id=1%20union%20select%201")
    detect(db, settings)
    assert alerts(db, "ST-CORR-001") == []


def test_events_without_ip_are_ignored_by_ip_rules(db, settings, ev):
    ev.many(400, 0, 0.1, source_ip=None)
    ev.add(0, source_ip=None, query="id=1%20union%20select%201")
    detect(db, settings)
    assert alerts(db) == []


# --- Window boundary semantics: window = (t - W, t] ---------------------------------------


def test_window_boundary_exactly_w_apart_does_not_count(db, settings, ev):
    # 5 failures spanning exactly 300s: the first falls outside (t-300, t].
    for t in (0, 75, 150, 225, 300):
        ev.add(t, event_type="auth_failure", username="alice", source_ip=ATTACKER)
    assert only_rule(db, settings, "ST-AUTH-001") == []


def test_window_boundary_just_inside_counts(db, settings, ev):
    for t in (0, 74, 148, 222, 299):
        ev.add(t, event_type="auth_failure", username="alice", source_ip=ATTACKER)
    [a] = only_rule(db, settings, "ST-AUTH-001")
    assert a.event_count == 5


def test_window_boundary_burst_rule(db, settings, ev):
    # 300 requests spread so that any 60s window holds at most 299.
    ev.many(300, 0, 60 / 299, source_ip=BENIGN)
    assert only_rule(db, settings, "ST-WEB-004") == []
