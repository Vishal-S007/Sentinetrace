"""Security regression checks: headers, export limits, injection probes, no leakage."""

import pytest

from tests.conftest import csrf_headers
from tests.detection_helpers import EventFactory, detect


@pytest.fixture
def data(db, settings):
    ev = EventFactory(db)
    ev.many(300, 0, 0.1, source_ip="203.0.113.66")
    ev.add(40, source_ip="203.0.113.66", query="id=1%20union%20select%201")
    ev.flush()
    detect(db, settings)


def test_api_responses_forbid_documents_and_framing(client):
    resp = client.get("/api/health")
    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    # Errors carry the same headers.
    assert "content-security-policy" in client.get("/api/alerts").headers
    # The interactive API docs need their own scripts, so they are exempt.
    assert "content-security-policy" not in client.get("/api/docs").headers


def test_export_rate_limit_is_per_user(logged_in, settings, data):
    settings.export_rate_per_minute = 2
    a, _ = logged_in("analyst")
    b, _ = logged_in("analyst")
    assert a.get("/api/alerts/export").status_code == 200
    assert a.get("/api/events/export", params={"format": "json"}).status_code == 200
    resp = a.get("/api/alerts/export")
    assert resp.status_code == 429 and resp.headers["retry-after"] == "60"
    assert b.get("/api/alerts/export").status_code == 200  # other users are unaffected


def test_incident_reports_count_towards_the_limit(logged_in, settings, data):
    settings.export_rate_per_minute = 1
    c, _ = logged_in("analyst")
    inc = c.post("/api/incidents", json={"title": "x"}, headers=csrf_headers(c)).json()["id"]
    assert c.get(f"/api/incidents/{inc}/report").status_code == 200
    assert c.get(f"/api/incidents/{inc}/report").status_code == 429
    assert c.get("/api/alerts/export").status_code == 429


@pytest.mark.parametrize(
    "url,params,ok",
    [
        ("/api/events", {"q": "' OR 1=1 --"}, 200),
        ("/api/events", {"username": "x' OR '1'='1"}, 200),
        ("/api/events", {"source_ip": "1.1.1.1' OR '1'='1"}, 422),
        ("/api/events", {"http_status": "1;DROP"}, 422),
        ("/api/events", {"method": "GET'--"}, 200),
        ("/api/alerts", {"q": "%' UNION SELECT password_hash FROM users --"}, 200),
        ("/api/alerts", {"rule_id": "x' OR 'a'='a"}, 200),
        ("/api/incidents", {"q": "'); DROP TABLE incidents; --"}, 200),
        ("/api/audit", {"actor": "' OR ''='"}, 200),
        ("/api/audit", {"target_id": "1 OR 1=1"}, 200),
    ],
)
def test_injection_probes_are_inert(logged_in, data, url, params, ok):
    c, _ = logged_in("admin")
    resp = c.get(url, params=params)
    assert resp.status_code == ok, resp.text
    if ok == 200:
        assert resp.json()["items"] == []  # treated as literal text, so nothing matches
    assert "password_hash" not in resp.text.replace(params.get("q", ""), "")


def test_validation_errors_do_not_echo_input(logged_in):
    c, _ = logged_in("analyst")
    probe = "<script>alert(document.cookie)</script>"
    resp = c.post("/api/incidents", json={"title": "x", "severity": probe}, headers=csrf_headers(c))
    assert resp.status_code == 422
    assert probe not in resp.text


def test_session_cookie_flags(make_user, make_client):
    from tests.conftest import login

    user = make_user("viewer")
    c = make_client()
    resp = login(c, user.username)
    cookies = resp.headers.get_list("set-cookie")
    session = next(h for h in cookies if h.startswith("st_session="))
    assert "HttpOnly" in session and "SameSite=lax" in session.replace("Lax", "lax")
    csrf = next(h for h in cookies if h.startswith("st_csrf="))
    assert "HttpOnly" not in csrf  # the SPA must read it to send the header
