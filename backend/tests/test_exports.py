"""CSV/JSON exports: same records as the database, caps, formula-injection safety,
permissions and auditing. Also the quiet health-check access-log filter."""

import csv
import io
import json
import logging

import pytest
from sqlalchemy import select, text

from app.api.routes import exports as exports_module
from app.main import QuietHealthChecks
from app.models import AuditLog
from app.services.exports import csv_safe
from tests.detection_helpers import EventFactory, alerts, detect

ATTACKER = "203.0.113.66"


@pytest.fixture
def scenario(db, settings):
    ev = EventFactory(db)
    ev.many(300, 0, 0.1, source_ip=ATTACKER)
    ev.add(40, source_ip=ATTACKER, path="/p", query="id=1%20union%20select%201")
    for i in range(30):
        ev.add(3700 + i, source_ip="203.0.113.77", http_status=404, path=f"/x{i}")
    ev.add(
        4000,
        source_ip="198.51.100.9",
        user_agent='=HYPERLINK("http://evil.example","x")',
        raw_line='@SUM(1+1) "quoted, with comma"',
    )
    ev.flush()
    detect(db, settings)
    return ev


def read_csv(resp) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(resp.text)))


def test_alert_csv_matches_database(logged_in, db, scenario):
    c, _ = logged_in("analyst")
    resp = c.get("/api/alerts/export", params={"severity": "medium"})
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")
    assert 'filename="alerts.csv"' in resp.headers["content-disposition"]
    rows = read_csv(resp)
    expected = db.execute(
        text(
            "SELECT id, rule_id, event_count FROM alerts WHERE severity = 'medium' ORDER BY id DESC"
        )
    ).all()
    assert [(int(r["id"]), r["rule_id"], int(r["event_count"])) for r in rows] == [
        tuple(e) for e in expected
    ]
    assert resp.headers["x-export-rows"] == str(len(expected))
    assert rows[0]["rule_name"] and rows[0]["first_seen"].startswith("2026-10-01T")


def test_alert_json_export_uses_queue_filters(logged_in, db, scenario):
    c, me = logged_in("analyst")
    target = alerts(db, "ST-WEB-001")[0]
    c.patch(
        f"/api/alerts/{target.id}",
        json={"assigned_to": me.id},
        headers={"X-CSRF-Token": c.cookies.get("st_csrf")},
    )
    data = json.loads(
        c.get("/api/alerts/export", params={"format": "json", "assigned_to": "me"}).text
    )
    assert [(d["id"], d["assignee"], d["source_ip"]) for d in data] == [
        (target.id, me.username, ATTACKER)
    ]
    assert c.get("/api/alerts/export", params={"format": "xml"}).status_code == 422
    assert c.get("/api/alerts/export", params={"source_ip": "nope"}).status_code == 422


def test_event_export_matches_explorer_filters(logged_in, db, scenario):
    c, _ = logged_in("analyst")
    params = {"source_ip": "203.0.113.0/24", "http_status": "4xx"}
    rows = read_csv(c.get("/api/events/export", params=params))
    explorer = c.get("/api/events", params={**params, "with_count": "true", "limit": 200}).json()
    assert len(rows) == explorer["count"] == 30
    assert [int(r["id"]) for r in rows] == [i["id"] for i in explorer["items"]]
    assert set(rows[0]) == set(exports_module.EVENT_COLUMNS)

    data = json.loads(c.get("/api/events/export", params={**params, "format": "json"}).text)
    assert [d["id"] for d in data] == [int(r["id"]) for r in rows]
    assert data[0]["http_status"] == 404 and data[0]["source_ip"] == "203.0.113.77"


def test_csv_cells_cannot_become_formulas(logged_in, db, scenario):
    c, _ = logged_in("analyst")
    [row] = read_csv(c.get("/api/events/export", params={"source_ip": "198.51.100.9"}))
    assert row["user_agent"] == '\'=HYPERLINK("http://evil.example","x")'
    assert row["raw_line"] == '\'@SUM(1+1) "quoted, with comma"'
    # JSON keeps the original value (it is not interpreted by spreadsheets).
    [item] = json.loads(
        c.get("/api/events/export", params={"source_ip": "198.51.100.9", "format": "json"}).text
    )
    assert item["user_agent"].startswith("=HYPERLINK")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("=1+1", "'=1+1"),
        ("+cmd", "'+cmd"),
        ("-x", "'-x"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tx", "'\tx"),
        ("-", "-"),
        ("-42", "-42"),
        ("-3.5", "-3.5"),
        ("normal", "normal"),
        ("", ""),
        (None, None),
        (7, 7),
    ],
)
def test_csv_safe(value, expected):
    assert csv_safe(value) == expected


def test_export_cap_marks_truncation(logged_in, db, scenario, monkeypatch):
    monkeypatch.setattr(exports_module, "EVENT_CAP", 10)
    c, _ = logged_in("analyst")
    resp = c.get("/api/events/export")
    assert len(read_csv(resp)) == 10
    assert resp.headers["x-export-truncated"] == "true" and resp.headers["x-export-rows"] == "10"
    data = json.loads(c.get("/api/events/export", params={"format": "json"}).text)
    assert len(data) == 10


def test_exports_are_audited_with_filters(logged_in, db, scenario):
    c, me = logged_in("analyst")
    c.get("/api/events/export", params={"source_ip": ATTACKER, "format": "json"})
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "export.events"))
    assert entry.actor_username == me.username
    assert entry.details == {
        "format": "json",
        "rows": 301,
        "truncated": False,
        "filters": {"source_ip": ATTACKER},
    }


def test_export_permissions(logged_in, db, scenario):
    viewer, _ = logged_in("viewer")
    analyst, _ = logged_in("analyst")
    admin, _ = logged_in("admin")
    for url in ("/api/alerts/export", "/api/events/export", "/api/audit/export"):
        assert viewer.get(url).status_code == 403, url
    assert analyst.get("/api/audit/export").status_code == 403  # audit is admin-only
    assert admin.get("/api/audit/export").status_code == 200


def test_audit_export_and_target_filter(logged_in, db, scenario):
    admin, _ = logged_in("admin")
    analyst, _ = logged_in("analyst")
    a = alerts(db)[0]
    analyst.patch(
        f"/api/alerts/{a.id}",
        json={"status": "resolved"},
        headers={"X-CSRF-Token": analyst.cookies.get("st_csrf")},
    )
    params = {"target_type": "alert", "target_id": str(a.id)}
    listed = admin.get("/api/audit", params=params).json()["items"]
    rows = read_csv(admin.get("/api/audit/export", params=params))
    assert [int(r["id"]) for r in rows] == [i["id"] for i in listed]
    assert [r["action"] for r in rows] == ["alert.status_change"]
    assert json.loads(rows[0]["details"])["to"] == "resolved"


def test_export_route_is_not_an_alert_id(logged_in, db, scenario):
    viewer, _ = logged_in("viewer")
    # Viewers get 403 from the export route, not 422 from /alerts/{alert_id}.
    assert viewer.get("/api/alerts/export").status_code == 403


def _access_record(path: str, status_code: int) -> logging.LogRecord:
    return logging.LogRecord(
        "uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "GET", path, "1.1", status_code), None,
    )  # fmt: skip


@pytest.mark.parametrize(
    "path,status_code,kept",
    [
        ("/api/health", 200, False),
        ("/api/ready", 200, False),
        ("/api/health?x=1", 200, False),
        ("/api/ready", 503, True),
        ("/api/alerts", 200, True),
    ],
)
def test_health_checks_are_not_logged(path, status_code, kept):
    assert QuietHealthChecks().filter(_access_record(path, status_code)) is kept
