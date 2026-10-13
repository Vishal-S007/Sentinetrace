"""Rules, alerts and detection-run APIs, plus the ingestion -> detection pipeline."""

from pathlib import Path

import pytest
from sqlalchemy import select

from app.detection.runs import claim_next_run, process_run
from app.ingestion.processor import claim_next_job, process_job
from app.models import AuditLog, DetectionRule, DetectionRun
from tests.conftest import csrf_headers
from tests.detection_helpers import EventFactory, detect

FIXTURES = Path(__file__).parent / "fixtures" / "logs"
ATTACKER = "203.0.113.66"


@pytest.fixture(autouse=True)
def isolated_storage(settings, tmp_path):
    settings.storage_dir = tmp_path / "storage"


# --- Rules -------------------------------------------------------------------------------------


def test_viewer_can_list_rules_with_metadata(logged_in):
    c, _ = logged_in("viewer")
    rules = c.get("/api/rules").json()
    assert len(rules) == 10
    sqli = next(r for r in rules if r["rule_id"] == "ST-WEB-001")
    assert sqli["severity"] == "high" and sqli["enabled"] and sqli["version"] == 1
    assert sqli["recommended_steps"] and sqli["config_schema"]["properties"]["min_matches"]


def test_rule_detail_has_version_history(logged_in):
    c, _ = logged_in("viewer")
    rule = c.get("/api/rules/ST-AUTH-001").json()
    assert [v["version"] for v in rule["versions"]] == [1]
    assert c.get("/api/rules/NOPE").status_code == 404


def test_admin_updates_rule_creating_a_version(logged_in, db):
    c, admin = logged_in("admin")
    resp = c.patch(
        "/api/rules/ST-AUTH-001",
        json={"config": {"threshold": 8}, "severity": "high", "note": "tuning"},
        headers=csrf_headers(c),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == 2 and body["config"] == {"threshold": 8, "window_seconds": 300}
    assert body["severity"] == "high" and body["updated_by"] == admin.username
    assert [v["version"] for v in body["versions"]] == [2, 1]
    assert body["versions"][0]["note"] == "tuning"
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "rule.update"))
    assert entry.details["changes"]["config"]["to"]["threshold"] == 8


def test_noop_update_does_not_bump_version(logged_in):
    c, _ = logged_in("admin")
    resp = c.patch("/api/rules/ST-AUTH-001", json={"enabled": True}, headers=csrf_headers(c))
    assert resp.json()["version"] == 1


@pytest.mark.parametrize(
    "body,fragment",
    [
        ({"config": {"threshold": 0}}, "threshold"),
        ({"config": {"bogus": 1}}, "bogus"),
        ({"severity": "extreme"}, "severity"),
        ({}, "at least one"),
    ],
)
def test_rule_update_validation(logged_in, body, fragment):
    c, _ = logged_in("admin")
    resp = c.patch("/api/rules/ST-AUTH-001", json=body, headers=csrf_headers(c))
    assert resp.status_code == 422 and fragment in resp.text


def test_correlation_rule_cannot_include_itself(logged_in):
    c, _ = logged_in("admin")
    resp = c.patch(
        "/api/rules/ST-CORR-001",
        json={"config": {"rule_ids": ["ST-CORR-001", "ST-WEB-001"]}},
        headers=csrf_headers(c),
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_admins_change_rules_or_start_runs(logged_in, role):
    c, _ = logged_in(role)
    h = csrf_headers(c)
    assert c.patch("/api/rules/ST-AUTH-001", json={"enabled": False}, headers=h).status_code == 403
    assert c.post("/api/detection/runs", json={}, headers=h).status_code == 403


# --- Runs ----------------------------------------------------------------------------------------


def test_manual_run_api(logged_in, db, settings):
    EventFactory(db).many(300, 0, 0.1, source_ip=ATTACKER)
    c, _ = logged_in("admin")
    resp = c.post("/api/detection/runs", json={}, headers=csrf_headers(c))
    assert resp.status_code == 202 and resp.json()["status"] == "queued"
    run = claim_next_run(db)
    process_run(db, run, settings)
    runs = c.get("/api/detection/runs").json()
    assert runs[0]["status"] == "completed" and runs[0]["alerts_created"] == 1
    assert db.scalar(select(AuditLog).where(AuditLog.action == "detection.run")) is not None


@pytest.mark.parametrize(
    "body",
    [
        {"since": "2026-10-02T00:00:00", "until": None},
        {"since": "2026-10-02T00:00:00Z", "until": "2026-10-01T00:00:00Z"},
    ],
)
def test_run_range_validation(logged_in, body):
    c, _ = logged_in("admin")
    assert c.post("/api/detection/runs", json=body, headers=csrf_headers(c)).status_code == 422


# --- Alerts ---------------------------------------------------------------------------------------


def test_alert_list_detail_and_evidence(logged_in, db, settings):
    ev = EventFactory(db)
    sqli = ev.add(
        0,
        source_ip=ATTACKER,
        path="/item",
        query="id=1%20union%20select%201",
        raw_line="RAW sqli line",
        http_status=500,
    )
    ev.many(300, 10, 0.1, source_ip=ATTACKER)
    detect(db, settings)
    c, _ = logged_in("viewer")

    page = c.get("/api/alerts").json()
    by_rule = {a["rule_id"]: a for a in page["items"]}
    assert {"ST-WEB-001", "ST-WEB-004", "ST-CORR-001"} <= set(by_rule)
    a = by_rule["ST-WEB-001"]
    assert a["source_ip"] == ATTACKER and a["rule_name"].startswith("SQL injection")

    detail = c.get(f"/api/alerts/{a['id']}").json()
    assert detail["recommended_steps"] and detail["recommended_action"]
    assert "Indicator only" in detail["reason"] and detail["confidence_reason"]
    assert detail["evidence_count"] == 1 and detail["status"] == "new"

    evidence = c.get(f"/api/alerts/{a['id']}/evidence").json()
    [item] = evidence["items"]
    assert item["event_id"] == sqli.id and item["raw_line"] == "RAW sqli line"
    assert item["indicator"] == "union_select" and item["http_status"] == 500

    burst = c.get(
        f"/api/alerts/{by_rule['ST-WEB-004']['id']}/evidence", params={"limit": 100}
    ).json()
    # The burst counts every request from the IP, including the injection attempt.
    assert burst["total_events"] == 301 and len(burst["items"]) == 100
    nxt = c.get(
        f"/api/alerts/{by_rule['ST-WEB-004']['id']}/evidence",
        params={"after_id": burst["next_after_id"], "limit": 500},
    ).json()
    assert len(nxt["items"]) == 201 and nxt["next_after_id"] is None


def test_alert_filters(logged_in, db, settings):
    EventFactory(db).many(300, 0, 0.1, source_ip=ATTACKER)
    detect(db, settings)
    c, _ = logged_in("viewer")
    assert len(c.get("/api/alerts", params={"severity": "medium"}).json()["items"]) == 1
    assert c.get("/api/alerts", params={"severity": "high"}).json()["items"] == []
    assert len(c.get("/api/alerts", params={"source_ip": ATTACKER}).json()["items"]) == 1
    assert c.get("/api/alerts", params={"source_ip": "192.0.2.1"}).json()["items"] == []
    assert c.get("/api/alerts", params={"source_ip": "not-an-ip"}).status_code == 422
    assert len(c.get("/api/alerts", params={"status": "new"}).json()["items"]) == 1
    assert c.get("/api/alerts", params={"limit": 500}).status_code == 422
    assert c.get("/api/alerts/999999").status_code == 404


# --- Ingestion -> detection ---------------------------------------------------------------------


def test_completed_ingestion_queues_detection(logged_in, db, settings):
    c, _ = logged_in("analyst")
    h = csrf_headers(c)
    sid = c.post(
        "/api/sources", json={"name": "web", "format": "apache_combined"}, headers=h
    ).json()["id"]
    c.post(
        f"/api/sources/{sid}/files",
        files={"file": ("a.log", (FIXTURES / "apache_combined_valid.log").read_bytes())},
        headers=h,
    )
    job = claim_next_job(db)
    process_job(db, job, settings)
    run = db.scalar(select(DetectionRun).where(DetectionRun.job_id == job.id))
    assert run is not None and run.trigger == "ingestion" and run.status == "queued"

    claim_next_run(db)
    process_run(db, run, settings)
    assert run.status == "completed"
    rules = {
        a["rule_id"] for a in c.get("/api/alerts", params={"source_ip": ATTACKER}).json()["items"]
    }
    # The fixture contains a sqlmap request, a TLS-garbage request and an XSS probe from
    # 203.0.113.66: three rule types plus their correlation.
    assert rules == {"ST-WEB-001", "ST-WEB-002", "ST-WEB-007", "ST-CORR-001"}
    # The benign client in the same file triggers nothing.
    assert c.get("/api/alerts", params={"source_ip": "198.51.100.10"}).json()["items"] == []


def test_failed_ingestion_does_not_queue_detection(logged_in, db, settings):
    c, _ = logged_in("analyst")
    h = csrf_headers(c)
    sid = c.post("/api/sources", json={"name": "web", "format": "json"}, headers=h).json()["id"]
    c.post(
        f"/api/sources/{sid}/files",
        files={"file": ("a.log", (FIXTURES / "nginx_common.log").read_bytes())},
        headers=h,
    )
    job = claim_next_job(db)
    process_job(db, job, settings)
    assert job.status == "failed"
    assert db.scalar(select(DetectionRun).where(DetectionRun.job_id == job.id)) is None


def test_retry_removes_evidence_links_of_partial_events(logged_in, db, settings):
    c, _ = logged_in("analyst")
    h = csrf_headers(c)
    settings.max_lines_per_file = 3
    sid = c.post(
        "/api/sources", json={"name": "web", "format": "apache_combined"}, headers=h
    ).json()["id"]
    c.post(
        f"/api/sources/{sid}/files",
        files={"file": ("a.log", (FIXTURES / "apache_combined_valid.log").read_bytes())},
        headers=h,
    )
    job = claim_next_job(db)
    process_job(db, job, settings)
    assert job.status == "failed"
    detect(db, settings)  # a manual rescan links the partial events to alerts
    assert c.post(f"/api/jobs/{job.id}/retry", headers=h).status_code == 202


def test_rule_state_is_in_database(db):
    assert db.get(DetectionRule, "ST-WEB-001").config["min_matches"] == 1
