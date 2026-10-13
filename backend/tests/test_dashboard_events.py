"""Dashboard figures vs. independent SQL, event explorer filters/pagination, alert status."""

from datetime import timedelta

import pytest
from sqlalchemy import select, text

from app.api.routes import events as events_module
from app.api.routes.dashboard import compute_dashboard
from app.models import Alert, AuditLog
from tests.conftest import csrf_headers
from tests.detection_helpers import T0, EventFactory, alerts, detect

ATTACKER = "203.0.113.66"
OTHER = "203.0.113.77"


@pytest.fixture
def scenario(db, settings):
    """Mixed traffic over two hours with alerts of several severities."""
    ev = EventFactory(db)
    ev.many(300, 0, 0.1, source_ip=ATTACKER)  # burst -> ST-WEB-004 (medium)
    ev.add(40, source_ip=ATTACKER, path="/p", query="id=1%20union%20select%201")  # high + corr
    for i in range(30):
        ev.add(3700 + i, source_ip=OTHER, http_status=404, path=f"/x{i}")  # ST-WEB-006
    ev.many(50, 4000, 10, source_ip="198.51.100.5", path="/ok")  # benign
    ev.many(5, 4100, 5, event_type="auth_failure", username="bob", source_ip="10.0.0.9")
    ev.flush()
    detect(db, settings)
    return ev


def sql_count(db, query: str, **params) -> int:
    return db.execute(text(query), params).scalar_one()


# --- Dashboard ---------------------------------------------------------------------------------


def test_dashboard_matches_independent_sql(db, scenario):
    now = T0 + timedelta(hours=3)
    d = compute_dashboard(db, "24h", now=now)
    start, end = now - timedelta(hours=24), now
    p = {"s": start, "e": end}
    assert d["totals"]["events"] == sql_count(
        db, "SELECT count(*) FROM events WHERE event_time BETWEEN :s AND :e", **p
    )
    overlap = "first_seen <= :e AND last_seen >= :s"
    assert d["totals"]["alerts"] == sql_count(
        db, f"SELECT count(*) FROM alerts WHERE {overlap}", **p
    )
    assert d["totals"]["open_alerts"] == sql_count(
        db,
        f"SELECT count(*) FROM alerts WHERE {overlap} AND status IN ('new','investigating')",
        **p,
    )
    assert d["totals"]["high_open_alerts"] == sql_count(
        db,
        f"SELECT count(*) FROM alerts WHERE {overlap} AND status IN ('new','investigating') "
        "AND severity IN ('high','critical')",
        **p,
    )
    for row in d["alerts_by_severity"]:
        assert row["count"] == sql_count(
            db,
            f"SELECT count(*) FROM alerts WHERE {overlap} AND severity = :sev",
            sev=row["key"],
            **p,
        )
    # Time series add up to the totals.
    assert sum(pt["count"] for pt in d["events_over_time"]) == d["totals"]["events"]
    assert sum(
        sum(v for k, v in pt.items() if k != "bucket_start") for pt in d["alerts_over_time"]
    ) == sql_count(db, "SELECT count(*) FROM alerts WHERE first_seen BETWEEN :s AND :e", **p)
    assert d["bucket"] == "hour" and len(d["events_over_time"]) == 25
    per_hour = {pt["bucket_start"]: pt["count"] for pt in d["events_over_time"]}
    assert per_hour[T0] == 301 and per_hour[T0 + timedelta(hours=1)] == 85


def test_dashboard_top_lists(db, scenario):
    d = compute_dashboard(db, "all", now=T0 + timedelta(hours=3))
    ips = {r["source_ip"]: r for r in d["top_source_ips"]}
    assert ips[ATTACKER]["alert_count"] == 3  # burst + SQLi + correlation
    assert ips[ATTACKER]["max_severity"] == "high"
    assert d["top_source_ips"][0]["source_ip"] == ATTACKER
    rules = {r["rule_id"]: r["alert_count"] for r in d["top_rules"]}
    assert rules == {
        a: n
        for a, n in db.execute(text("SELECT rule_id, count(*) FROM alerts GROUP BY rule_id")).all()
    }
    assert all(a.severity in ("high", "critical") for a in d["recent_high_alerts"])
    assert d["data_range"]["first_event"] == T0


def test_dashboard_range_excludes_old_data(db, scenario):
    d = compute_dashboard(db, "24h", now=T0 + timedelta(days=30))
    assert d["totals"]["events"] == 0 and d["totals"]["alerts"] == 0
    assert d["data_range"]["last_event"] is not None  # UI can suggest "All time"


def test_dashboard_empty_database(db):
    d = compute_dashboard(db, "all")
    assert d["totals"]["events"] == 0 and d["events_over_time"] == []


def test_dashboard_api_and_permissions(logged_in, scenario, client):
    c, _ = logged_in("viewer")
    resp = c.get("/api/dashboard", params={"range": "all"})
    assert resp.status_code == 200 and resp.json()["totals"]["events"] == 386
    assert c.get("/api/dashboard", params={"range": "1y"}).status_code == 422
    assert client.get("/api/dashboard").status_code == 401


# --- Event explorer -----------------------------------------------------------------------------


def ids(resp):
    return [e["id"] for e in resp.json()["items"]]


@pytest.mark.parametrize(
    "params,expected",
    [
        ({"source_ip": ATTACKER}, 301),
        ({"source_ip": "203.0.113.0/24"}, 331),
        ({"http_status": "404"}, 30),
        ({"http_status": "4xx"}, 30),
        ({"http_status": "2xx"}, 356),
        ({"event_type": "auth_failure"}, 5),
        ({"username": "bob"}, 5),
        ({"method": "get"}, 386),
        ({"flagged": "true", "source_ip": "198.51.100.5"}, 0),
        ({"flagged": "false", "source_ip": "198.51.100.5"}, 50),
        ({"alert_severity": "high"}, 301),  # the correlation alert links the burst too
        ({"q": "union%20select"}, 1),
    ],
)
def test_event_filters(logged_in, scenario, params, expected):
    c, _ = logged_in("viewer")
    resp = c.get("/api/events", params={**params, "with_count": "true", "limit": 200})
    assert resp.status_code == 200, resp.text
    assert resp.json()["count"] == expected


def test_event_time_range(logged_in, scenario):
    c, _ = logged_in("viewer")
    resp = c.get(
        "/api/events",
        params={
            "since": (T0 + timedelta(hours=1)).isoformat(),
            "until": (T0 + timedelta(hours=2)).isoformat(),
            "with_count": "true",
        },
    )
    assert resp.json()["count"] == 85
    naive = c.get("/api/events", params={"since": "2026-10-01T00:00:00"})
    assert naive.status_code == 422


def test_text_search_escapes_wildcards(logged_in, db):
    ev = EventFactory(db)
    ev.add(0, raw_line="discount 100% off")
    ev.add(1, raw_line="discount 1000 off")
    ev.flush()
    c, _ = logged_in("viewer")
    resp = c.get("/api/events", params={"q": "100%", "with_count": "true"})
    assert resp.json()["count"] == 1  # '%' is literal, not a wildcard
    resp = c.get("/api/events", params={"q": "DISCOUNT", "with_count": "true"})
    assert resp.json()["count"] == 2  # case-insensitive


def test_alert_id_filter_returns_evidence(logged_in, db, scenario):
    sqli = alerts(db, "ST-WEB-001")[0]
    c, _ = logged_in("viewer")
    resp = c.get("/api/events", params={"alert_id": sqli.id, "with_count": "true"})
    [item] = resp.json()["items"]
    assert item["max_alert_severity"] == "high" and item["alert_count"] >= 2  # SQLi + burst/corr


def test_keyset_pagination_walks_everything_in_order(logged_in, db):
    ev = EventFactory(db)
    ev.many(25, 0, 1)
    ev.many(10, 100, 0)  # ten events with the same timestamp (ties broken by id)
    ev.flush()
    c, _ = logged_in("viewer")
    seen, cursor, pages = [], None, 0
    while True:
        params = {"limit": 7, **({"cursor": cursor} if cursor else {})}
        body = c.get("/api/events", params=params).json()
        assert len(body["items"]) <= 7
        seen += [(e["event_time"], e["id"]) for e in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 35 and len(set(seen)) == 35 and pages == 5
    assert seen == sorted(seen, reverse=True)


def test_count_is_capped(logged_in, db, monkeypatch):
    monkeypatch.setattr(events_module, "COUNT_CAP", 10)
    EventFactory(db).many(15, 0, 1)
    c, _ = logged_in("viewer")
    body = c.get("/api/events", params={"with_count": "true"}).json()
    assert body["count"] == 10 and body["count_capped"] is True


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 201},
        {"source_ip": "nope"},
        {"http_status": "6xx"},
        {"http_status": "abc"},
        {"event_type": "bogus"},
        {"alert_severity": "extreme"},
        {"cursor": "!!!"},
        {"q": "a"},
    ],
)
def test_event_filter_validation(logged_in, params):
    c, _ = logged_in("viewer")
    assert c.get("/api/events", params=params).status_code == 422


def test_event_detail(logged_in, db, scenario):
    sqli = alerts(db, "ST-WEB-001")[0]
    c, _ = logged_in("viewer")
    [item] = c.get("/api/events", params={"alert_id": sqli.id}).json()["items"]
    detail = c.get(f"/api/events/{item['id']}").json()
    assert detail["query"] == "id=1%20union%20select%201" and detail["line_number"] > 0
    assert {a["rule_id"] for a in detail["alerts"]} >= {"ST-WEB-001", "ST-WEB-004"}
    assert (
        next(a for a in detail["alerts"] if a["rule_id"] == "ST-WEB-001")["indicator"]
        == "union_select"
    )
    assert c.get("/api/events/999999999").status_code == 404


# --- Alert status ------------------------------------------------------------------


def test_analyst_changes_alert_status_with_audit(logged_in, db, scenario):
    a = alerts(db, "ST-WEB-001")[0]
    c, user = logged_in("analyst")
    resp = c.patch(
        f"/api/alerts/{a.id}",
        json={"status": "investigating", "note": "looking"},
        headers=csrf_headers(c),
    )
    assert resp.status_code == 200 and resp.json()["status"] == "investigating"
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "alert.status_change"))
    assert entry.details == {
        "from": "new",
        "to": "investigating",
        "note": "looking",
        "rule_id": "ST-WEB-001",
    }
    assert entry.actor_user_id == user.id
    # Same status again: no new audit entry.
    c.patch(f"/api/alerts/{a.id}", json={"status": "investigating"}, headers=csrf_headers(c))
    assert (
        len(db.scalars(select(AuditLog).where(AuditLog.action == "alert.status_change")).all()) == 1
    )


def test_status_survives_redetection(logged_in, db, settings, scenario):
    a = alerts(db, "ST-WEB-004")[0]
    c, _ = logged_in("analyst")
    c.patch(f"/api/alerts/{a.id}", json={"status": "false_positive"}, headers=csrf_headers(c))
    detect(db, settings)
    db.refresh(a)
    assert a.status == "false_positive"


def test_viewer_cannot_change_status(logged_in, db, scenario):
    a = alerts(db)[0]
    c, _ = logged_in("viewer")
    resp = c.patch(f"/api/alerts/{a.id}", json={"status": "resolved"}, headers=csrf_headers(c))
    assert resp.status_code == 403
    db.refresh(a)
    assert a.status == "new"


@pytest.mark.parametrize("body", [{"status": "closed"}, {"status": "resolved", "x": 1}, {}])
def test_status_validation(logged_in, db, scenario, body):
    a = alerts(db)[0]
    c, _ = logged_in("analyst")
    assert c.patch(f"/api/alerts/{a.id}", json=body, headers=csrf_headers(c)).status_code == 422


def test_alert_title_search(logged_in, db, scenario):
    c, _ = logged_in("viewer")
    items = c.get("/api/alerts", params={"q": "sql injection"}).json()["items"]
    assert [i["rule_id"] for i in items] == ["ST-WEB-001"]
    assert db.scalar(select(Alert).where(Alert.rule_id == "ST-WEB-001")) is not None
