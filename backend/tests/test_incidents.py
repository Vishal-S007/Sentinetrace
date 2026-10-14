"""Alert assignment and notes, incidents (linking, status, timeline) and incident reports."""

import json

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.models import AuditLog, Incident, InvestigationNote
from tests.conftest import csrf_headers
from tests.detection_helpers import EventFactory, alerts, detect

ATTACKER = "203.0.113.66"


@pytest.fixture
def scenario(db, settings):
    """A medium burst alert, a high SQLi alert and a correlation alert from one IP."""
    ev = EventFactory(db)
    ev.many(300, 0, 0.1, source_ip=ATTACKER)
    ev.add(
        40,
        source_ip=ATTACKER,
        path="/p",
        query="id=1%20union%20select%201",
        raw_line=f'{ATTACKER} - - "GET /p?id=1%20union%20select%201 ```x``` HTTP/1.1" 500',
    )
    ev.flush()
    detect(db, settings)
    return ev


def audit_actions(db, target_type: str, target_id) -> list[str]:
    return list(
        db.scalars(
            select(AuditLog.action)
            .where(AuditLog.target_type == target_type, AuditLog.target_id == str(target_id))
            .order_by(AuditLog.id)
        ).all()
    )


# --- Alert assignment ---------------------------------------------------------------


def test_assign_alert_records_history(logged_in, make_user, db, scenario):
    a = alerts(db, "ST-WEB-001")[0]
    c, me = logged_in("analyst")
    other = make_user("analyst")
    resp = c.patch(f"/api/alerts/{a.id}", json={"assigned_to": other.id}, headers=csrf_headers(c))
    assert resp.status_code == 200, resp.text
    assert resp.json()["assigned_to"] == other.id and resp.json()["assignee"] == other.username

    # Status and assignee in one request; then clear the assignee.
    resp = c.patch(
        f"/api/alerts/{a.id}",
        json={"status": "investigating", "assigned_to": me.id, "note": "taking it"},
        headers=csrf_headers(c),
    )
    assert resp.json()["status"] == "investigating" and resp.json()["assignee"] == me.username
    c.patch(f"/api/alerts/{a.id}", json={"assigned_to": None}, headers=csrf_headers(c))

    history = c.get(f"/api/alerts/{a.id}/activity").json()["history"]
    assert [(h["action"], h["details"].get("to")) for h in history] == [
        ("alert.assign", other.username),
        ("alert.status_change", "investigating"),
        ("alert.assign", me.username),
        ("alert.assign", None),
    ]
    assert history[2]["details"] == {"from": other.username, "to": me.username, "note": "taking it"}


def test_assignee_must_be_active_analyst_or_admin(logged_in, make_user, db, scenario):
    a = alerts(db)[0]
    c, _ = logged_in("analyst")
    for user_id in (
        make_user("viewer").id,
        make_user("analyst", is_active=False).id,
        999_999,
    ):
        resp = c.patch(
            f"/api/alerts/{a.id}", json={"assigned_to": user_id}, headers=csrf_headers(c)
        )
        assert resp.status_code == 422, user_id
    assert c.patch(f"/api/alerts/{a.id}", json={}, headers=csrf_headers(c)).status_code == 422
    db.refresh(a)
    assert a.assigned_to is None


def test_assignee_list_and_queue_filter(logged_in, make_user, db, scenario):
    c, me = logged_in("analyst")
    make_user("viewer", username="just.a.viewer")
    names = {u["username"] for u in c.get("/api/assignees").json()}
    assert me.username in names and "just.a.viewer" not in names

    mine = alerts(db, "ST-WEB-001")[0]
    c.patch(f"/api/alerts/{mine.id}", json={"assigned_to": me.id}, headers=csrf_headers(c))
    assert [i["id"] for i in c.get("/api/alerts?assigned_to=me").json()["items"]] == [mine.id]
    unassigned = {i["id"] for i in c.get("/api/alerts?assigned_to=none").json()["items"]}
    assert mine.id not in unassigned and len(unassigned) == len(alerts(db)) - 1
    assert c.get("/api/alerts?assigned_to=bob").status_code == 422

    viewer, _ = logged_in("viewer")
    assert viewer.get("/api/assignees").status_code == 403


# --- Alert notes --------------------------------------------------------------------


def test_alert_notes_and_evidence_references(logged_in, db, scenario):
    a = alerts(db, "ST-WEB-001")[0]
    event_id = db.scalar(text(f"SELECT event_id FROM alert_events WHERE alert_id = {a.id} LIMIT 1"))
    c, me = logged_in("analyst")
    h = csrf_headers(c)
    assert (
        c.post(
            f"/api/alerts/{a.id}/notes", json={"body": "  checked WAF logs  "}, headers=h
        ).status_code
        == 201
    )
    resp = c.post(
        f"/api/alerts/{a.id}/notes",
        json={"kind": "evidence", "body": "the injected request", "event_id": event_id},
        headers=h,
    )
    assert resp.status_code == 201 and resp.json()["author"] == me.username
    notes = c.get(f"/api/alerts/{a.id}/activity").json()["notes"]
    assert [(n["kind"], n["body"], n["event_id"]) for n in notes] == [
        ("note", "checked WAF logs", None),
        ("evidence", "the injected request", event_id),
    ]
    assert audit_actions(db, "alert", a.id).count("alert.note") == 2

    for bad in (
        {"body": "   "},
        {"body": "x" * 5001},
        {"body": "x", "kind": "rumour"},
        {"body": "x", "event_id": 999_999_999},
        {"body": "x", "extra": 1},
    ):
        assert c.post(f"/api/alerts/{a.id}/notes", json=bad, headers=h).status_code == 422, bad
    viewer, _ = logged_in("viewer")
    resp = viewer.post(
        f"/api/alerts/{a.id}/notes", json={"body": "x"}, headers=csrf_headers(viewer)
    )
    assert resp.status_code == 403
    assert viewer.get(f"/api/alerts/{a.id}/activity").status_code == 200


def test_notes_are_append_only_in_the_database(logged_in, db, scenario, connection):
    a = alerts(db)[0]
    c, _ = logged_in("analyst")
    c.post(f"/api/alerts/{a.id}/notes", json={"body": "original"}, headers=csrf_headers(c))
    note_id = db.scalar(select(InvestigationNote.id))
    for stmt in (
        f"UPDATE investigation_notes SET body = 'rewritten' WHERE id = {note_id}",
        f"DELETE FROM investigation_notes WHERE id = {note_id}",
    ):
        sp = connection.begin_nested()
        with pytest.raises(DBAPIError, match="append-only"):
            connection.execute(text(stmt))
        sp.rollback()
    assert (
        db.scalar(select(InvestigationNote.body).where(InvestigationNote.id == note_id))
        == "original"
    )


# --- Incidents ------------------------------------------------------------------------


def create_incident(c, **body):
    return c.post("/api/incidents", json={"title": "Web attack", **body}, headers=csrf_headers(c))


def test_create_incident_from_alerts(logged_in, db, scenario):
    sqli, burst = alerts(db, "ST-WEB-001")[0], alerts(db, "ST-WEB-004")[0]
    c, me = logged_in("analyst")
    resp = create_incident(c, summary="SQLi plus burst", alert_ids=[burst.id, sqli.id, sqli.id])
    assert resp.status_code == 201, resp.text
    inc = resp.json()
    assert inc["severity"] == "high"  # highest among linked alerts
    assert inc["status"] == "open" and inc["created_by"] == me.username
    assert sorted(a["id"] for a in inc["alerts"]) == sorted([sqli.id, burst.id])
    assert inc["alert_count"] == 2
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "incident.create"))
    assert sorted(entry.details["alert_ids"]) == sorted([sqli.id, burst.id])

    # Default severity without alerts; explicit severity wins.
    assert create_incident(c).json()["severity"] == "medium"
    assert (
        create_incident(c, severity="critical", alert_ids=[burst.id]).json()["severity"]
        == "critical"
    )
    # The alert's activity lists the incidents it belongs to.
    refs = c.get(f"/api/alerts/{burst.id}/activity").json()["incidents"]
    assert len(refs) == 2


def test_create_incident_validation_is_atomic(logged_in, db, scenario):
    a = alerts(db)[0]
    c, _ = logged_in("analyst")
    assert create_incident(c, alert_ids=[a.id, 999_999]).status_code == 422
    assert db.scalar(select(Incident.id)) is None
    for body in ({"title": "   "}, {"title": "x" * 201}, {"title": "t", "status": "open"}):
        assert c.post("/api/incidents", json=body, headers=csrf_headers(c)).status_code == 422
    assert create_incident(c, alert_ids=list(range(1, 202))).status_code == 422


def test_link_and_unlink_alerts(logged_in, db, scenario):
    first, *rest = alerts(db)
    c, _ = logged_in("analyst")
    inc_id = create_incident(c, alert_ids=[first.id]).json()["id"]
    h = csrf_headers(c)
    resp = c.post(
        f"/api/incidents/{inc_id}/alerts", json={"alert_ids": [first.id, rest[0].id]}, headers=h
    )
    assert resp.json()["alert_count"] == 2
    entries = db.scalars(select(AuditLog).where(AuditLog.action == "incident.link_alerts")).all()
    assert [e.details["alert_ids"] for e in entries] == [[rest[0].id]]  # only the new link
    # Re-linking only existing alerts changes nothing and is not audited.
    c.post(f"/api/incidents/{inc_id}/alerts", json={"alert_ids": [first.id]}, headers=h)
    assert (
        len(db.scalars(select(AuditLog).where(AuditLog.action == "incident.link_alerts")).all())
        == 1
    )

    resp = c.delete(f"/api/incidents/{inc_id}/alerts/{first.id}", headers=h)
    assert [a["id"] for a in resp.json()["alerts"]] == [rest[0].id]
    assert c.delete(f"/api/incidents/{inc_id}/alerts/{first.id}", headers=h).status_code == 404
    assert (
        c.post(f"/api/incidents/{inc_id}/alerts", json={"alert_ids": []}, headers=h).status_code
        == 422
    )
    assert c.get("/api/incidents/999999").status_code == 404


def test_status_owner_and_closed_at(logged_in, make_user, db, scenario):
    c, _ = logged_in("analyst")
    owner = make_user("admin")
    inc_id = create_incident(c).json()["id"]
    h = csrf_headers(c)
    resp = c.patch(
        f"/api/incidents/{inc_id}",
        json={"status": "contained", "assigned_to": owner.id, "note": "blocked at firewall"},
        headers=h,
    )
    assert resp.json()["assignee"] == owner.username and resp.json()["closed_at"] is None
    resolved = c.patch(f"/api/incidents/{inc_id}", json={"status": "resolved"}, headers=h).json()
    assert resolved["closed_at"] is not None
    reopened = c.patch(
        f"/api/incidents/{inc_id}", json={"status": "investigating"}, headers=h
    ).json()
    assert reopened["closed_at"] is None

    changes = [
        e.details
        for e in db.scalars(
            select(AuditLog).where(AuditLog.action == "incident.update").order_by(AuditLog.id)
        ).all()
    ]
    assert changes[0] == {
        "changes": {
            "status": {"from": "open", "to": "contained"},
            "assignee": {"from": None, "to": owner.username},
        },
        "note": "blocked at firewall",
    }
    # A no-op update is not audited.
    c.patch(f"/api/incidents/{inc_id}", json={"status": "investigating"}, headers=h)
    assert (
        len(changes)
        == 3
        == len(db.scalars(select(AuditLog).where(AuditLog.action == "incident.update")).all())
    )
    for body in ({}, {"status": "done"}, {"title": " "}, {"assigned_to": make_user("viewer").id}):
        assert c.patch(f"/api/incidents/{inc_id}", json=body, headers=h).status_code == 422, body


def test_timeline_merges_observations_changes_and_notes(logged_in, db, scenario):
    sqli = alerts(db, "ST-WEB-001")[0]
    c, me = logged_in("analyst")
    inc_id = create_incident(c, alert_ids=[sqli.id]).json()["id"]
    h = csrf_headers(c)
    c.patch(f"/api/incidents/{inc_id}", json={"status": "investigating"}, headers=h)
    c.post(
        f"/api/incidents/{inc_id}/notes", json={"kind": "action", "body": "Blocked IP"}, headers=h
    )
    timeline = c.get(f"/api/incidents/{inc_id}").json()["timeline"]
    assert [(t["kind"], t["title"]) for t in timeline] == [
        ("observed", f"First observed: {sqli.title}"),
        ("change", "Incident created"),
        ("change", "Status: open → investigating"),
        ("note", "Action taken"),
    ]
    assert timeline[-1]["detail"] == "Blocked IP" and timeline[-1]["actor"] == me.username
    times = [t["at"] for t in timeline]
    assert times == sorted(times)


def test_incident_list_filters(logged_in, db, scenario):
    c, me = logged_in("analyst")
    h = csrf_headers(c)
    a = create_incident(c, title="Credential stuffing").json()["id"]
    b = create_incident(c, title="SQL injection attempts", severity="high").json()["id"]
    c.patch(f"/api/incidents/{a}", json={"status": "closed", "assigned_to": me.id}, headers=h)

    def ids(**params):
        return [i["id"] for i in c.get("/api/incidents", params=params).json()["items"]]

    assert ids() == [b, a]
    assert ids(open_only="true") == [b]
    assert ids(status="closed") == [a]
    assert ids(assigned_to="me") == [a]
    assert ids(severity="high") == [b]
    assert ids(q="sql inj") == [b]
    page = c.get("/api/incidents", params={"limit": 1}).json()
    assert page["next_before_id"] == b
    assert ids(before_id=b) == [a]


def test_incident_permissions(logged_in, db, scenario):
    analyst, _ = logged_in("analyst")
    inc_id = create_incident(analyst).json()["id"]
    viewer, _ = logged_in("viewer")
    h = csrf_headers(viewer)
    assert viewer.get("/api/incidents").status_code == 200
    assert viewer.get(f"/api/incidents/{inc_id}").status_code == 200
    for method, url, body in (
        ("POST", "/api/incidents", {"title": "x"}),
        ("PATCH", f"/api/incidents/{inc_id}", {"status": "closed"}),
        ("POST", f"/api/incidents/{inc_id}/alerts", {"alert_ids": [alerts(db)[0].id]}),
        ("DELETE", f"/api/incidents/{inc_id}/alerts/1", None),
        ("POST", f"/api/incidents/{inc_id}/notes", {"body": "x"}),
    ):
        assert viewer.request(method, url, json=body, headers=h).status_code == 403, url
    # Viewers lack reports:export.
    assert viewer.get(f"/api/incidents/{inc_id}/report").status_code == 403


# --- Report ------------------------------------------------------------------------------


def test_markdown_report_contents(logged_in, db, scenario):
    sqli, burst = alerts(db, "ST-WEB-001")[0], alerts(db, "ST-WEB-004")[0]
    c, me = logged_in("analyst")
    h = csrf_headers(c)
    inc_id = create_incident(
        c,
        title="Web attack | from one IP",
        summary="Probe then injection.",
        alert_ids=[sqli.id, burst.id],
    ).json()["id"]
    c.post(
        f"/api/incidents/{inc_id}/notes",
        json={"kind": "action", "body": "Blocked at WAF"},
        headers=h,
    )
    resp = c.get(f"/api/incidents/{inc_id}/report")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    assert f"incident-{inc_id}-report.md" in resp.headers["content-disposition"]
    md = resp.text
    assert md.startswith(f"# Incident #{inc_id}: Web attack \\| from one IP")
    assert "Probe then injection." in md
    assert f"| #{sqli.id} | ST-WEB-001 | high | new | {ATTACKER} |" in md
    assert "do not by themselves confirm" in md
    assert "Blocked at WAF" in md and me.username in md
    # Log content with backticks stays inside a longer fence.
    assert "````\n" in md and "```x```" in md
    assert audit_actions(db, "incident", inc_id)[-1] == "incident.export"


def test_json_report_matches_database(logged_in, db, scenario):
    linked = [a.id for a in alerts(db)][:2]
    c, _ = logged_in("analyst")
    inc_id = create_incident(c, alert_ids=linked).json()["id"]
    resp = c.get(f"/api/incidents/{inc_id}/report", params={"format": "json"})
    data = json.loads(resp.text)
    assert sorted(a["id"] for a in data["alerts"]) == sorted(linked)
    for a in data["alerts"]:
        linked_count = db.scalar(
            text(f"SELECT count(*) FROM alert_events WHERE alert_id = {a['id']}")
        )
        assert len(a["evidence_sample"]) == min(5, linked_count)
        assert a["reason"]
    assert data["incident"]["alert_count"] == 2
    assert c.get(f"/api/incidents/{inc_id}/report", params={"format": "pdf"}).status_code == 422
