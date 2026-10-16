"""Data retention: exactly the eligible data is removed, nothing else; safe defaults."""

from datetime import timedelta

import pytest
from sqlalchemy import func, select, text

from app import cli
from app.models import (
    Alert,
    AlertEvent,
    AuditLog,
    Event,
    ImportedFile,
    Incident,
    IncidentAlert,
    IngestionError,
    InvestigationNote,
)
from app.services import retention
from app.worker import maybe_auto_purge
from tests.conftest import csrf_headers
from tests.detection_helpers import T0, EventFactory

NOW = T0 + timedelta(days=40)  # with 30 days' retention, the cutoff is T0 + 10 days
DAYS = 30


def make_alert(db, rule_id: str, status: str, events: list[Event], at=T0) -> Alert:
    n = db.scalar(select(func.count()).select_from(Alert)) or 0
    a = Alert(
        rule_id=rule_id, rule_version=1, group_key=f"k{n}-{status}", bucket_start=at, title="t",
        reason="r", severity="medium", status=status, confidence="low", confidence_reason="c",
        recommended_action="a", first_seen=at, last_seen=at + timedelta(minutes=5),
        event_count=len(events), window_seconds=60,
    )  # fmt: skip
    db.add(a)
    db.flush()
    for e in events:
        db.add(AlertEvent(alert_id=a.id, event_id=e.id))
    db.flush()
    return a


@pytest.fixture
def world(db, make_user, settings, tmp_path):
    """Old and recent data in every protected and unprotected shape."""
    settings.storage_dir = tmp_path / "storage"
    user = make_user("analyst")
    ev = EventFactory(db)
    old = lambda n, **kw: ev.many(n, 0, 1, **kw)  # noqa: E731
    w = {
        "closed_alert_events": old(3, path="/closed"),
        "open_alert_events": old(2, path="/open"),
        "incident_alert_events": old(2, path="/incident"),
        "noted_alert_events": old(2, path="/noted"),
        "noted_event": old(1, path="/noted-event"),
        "loose_old": old(5, path="/loose"),
        "recent": [ev.add(NOW - timedelta(days=1), path="/recent") for _ in range(4)],
    }
    db.flush()
    w["closed"] = make_alert(db, "ST-WEB-004", "resolved", w["closed_alert_events"])
    w["fp"] = make_alert(db, "ST-WEB-006", "false_positive", [])
    w["open"] = make_alert(db, "ST-WEB-004", "investigating", w["open_alert_events"])
    w["in_incident"] = make_alert(db, "ST-WEB-001", "resolved", w["incident_alert_events"])
    w["noted"] = make_alert(db, "ST-WEB-002", "resolved", w["noted_alert_events"])
    w["recent_closed"] = make_alert(db, "ST-WEB-003", "resolved", [], at=NOW - timedelta(days=2))
    # A closed alert sharing evidence with the open one: the shared event must stay.
    w["closed_sharing"] = make_alert(db, "ST-WEB-005", "resolved", w["open_alert_events"][:1])

    inc = Incident(title="kept", severity="high", created_by=user.id)
    db.add(inc)
    db.flush()
    db.add(IncidentAlert(incident_id=inc.id, alert_id=w["in_incident"].id, linked_by=user.id))
    db.add(InvestigationNote(alert_id=w["noted"].id, body="keep me", author_id=user.id))
    db.add(
        InvestigationNote(
            incident_id=inc.id, kind="evidence", body="see", event_id=w["noted_event"][0].id,
            author_id=user.id,
        )
    )  # fmt: skip

    # Rejected-line records: one finished old job, one recent job.
    ev.job.finished_at = T0
    db.add(IngestionError(job_id=ev.job.id, line_number=1, reason="bad", raw_line="x"))
    recent_src = EventFactory(db)
    recent_src.job.finished_at = NOW - timedelta(days=1)
    db.add(IngestionError(job_id=recent_src.job.id, line_number=1, reason="bad", raw_line="y"))

    # Stored uploads: one old unique file, and one old file sharing content with a recent upload.
    def stored(f: ImportedFile, key: str, uploaded_at, content: bytes) -> None:
        f.storage_key, f.uploaded_at, f.size_bytes = key, uploaded_at, len(content)
        path = settings.storage_dir / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    stored(ev.file, "files/aa/old-unique", T0, b"old content")
    stored(recent_src.file, "files/bb/shared", NOW - timedelta(days=1), b"shared!")
    shared_old = EventFactory(db)
    stored(shared_old.file, "files/bb/shared", T0, b"shared!")
    shared_old.job.finished_at = T0
    db.flush()
    w.update(
        incident=inc, old_file=ev.file, recent_file=recent_src.file, shared_old=shared_old.file
    )
    return w


def ids(rows) -> set[int]:
    return {r.id for r in rows}


def test_preview_matches_purge_and_only_eligible_data_goes(db, settings, world):
    before = retention.preview(db, settings, DAYS, now=NOW)
    assert (before.alerts, before.events, before.ingestion_errors, before.stored_files) == (
        3,  # closed, false positive, closed_sharing
        3 + 5,  # closed alert's evidence + loose old events
        1,
        1,
    )
    assert before.evidence_links == 3 + 1
    assert before.stored_bytes == len(b"old content")

    done = retention.purge(db, settings, DAYS, actor_username="test", now=NOW)
    assert done.as_dict() == before.as_dict()

    remaining_alerts = ids(db.scalars(select(Alert)).all())
    assert remaining_alerts == {
        world[k].id for k in ("open", "in_incident", "noted", "recent_closed")
    }
    remaining_events = ids(db.scalars(select(Event)).all())
    kept = [
        *world["open_alert_events"], *world["incident_alert_events"],
        *world["noted_alert_events"], *world["noted_event"], *world["recent"],
    ]  # fmt: skip
    assert remaining_events == ids(kept)
    # Evidence of kept alerts is intact.
    links = db.scalar(select(func.count()).select_from(AlertEvent))
    assert links == 2 + 2 + 2
    assert db.scalar(select(func.count()).select_from(IngestionError)) == 1
    assert db.scalar(select(func.count()).select_from(InvestigationNote)) == 2
    assert db.get(Incident, world["incident"].id) is not None


def test_stored_uploads_respect_shared_content(db, settings, world):
    retention.purge(db, settings, DAYS, actor_username="test", now=NOW)
    for f in (world["old_file"], world["recent_file"], world["shared_old"]):
        db.refresh(f)
    assert world["old_file"].content_purged_at is not None
    assert not (settings.storage_dir / "files/aa/old-unique").exists()
    # The shared content is still needed by the recent upload.
    assert world["shared_old"].content_purged_at is None
    assert (settings.storage_dir / "files/bb/shared").read_bytes() == b"shared!"
    # File metadata is never deleted.
    assert db.scalar(select(func.count()).select_from(ImportedFile)) == 3


def test_purge_is_idempotent_and_audited(db, settings, world):
    retention.purge(db, settings, DAYS, actor_username="test", now=NOW)
    again = retention.purge(db, settings, DAYS, actor_username="test", now=NOW)
    assert (again.alerts, again.events, again.ingestion_errors, again.stored_files) == (0, 0, 0, 0)
    entries = db.scalars(select(AuditLog).where(AuditLog.action == "retention.purge")).all()
    assert [e.details["events"] for e in entries] == [8, 0]
    assert entries[0].actor_username == "test"


def test_small_batches_give_the_same_result(db, settings, world):
    settings.retention_batch_size = 2
    done = retention.purge(db, settings, DAYS, actor_username="test", now=NOW)
    assert (done.alerts, done.events, done.evidence_links) == (3, 8, 4)


def test_minimum_retention_is_enforced(db, settings):
    with pytest.raises(retention.RetentionError, match="at least 7 days"):
        retention.preview(db, settings, 6)
    settings.retention_min_days = 30
    with pytest.raises(retention.RetentionError):
        retention.purge(db, settings, 29, actor_username="t")


def test_audit_log_and_notes_cannot_be_purged_even_directly(db, world, connection):
    """Retention never targets them, and the database refuses anyway."""
    db.add(AuditLog(action="test.entry"))
    db.flush()
    for stmt in ("DELETE FROM audit_log", "DELETE FROM investigation_notes"):
        sp = connection.begin_nested()
        with pytest.raises(Exception, match="append-only"):
            connection.execute(text(stmt))
        sp.rollback()


def test_api_preview_and_purge(logged_in, db, settings, world):
    c, admin = logged_in("admin")
    resp = c.get("/api/admin/retention", params={"older_than_days": 7})
    assert resp.status_code == 200
    body = resp.json()
    assert body["min_days"] == 7 and body["auto_days"] is None
    assert c.get("/api/admin/retention", params={"older_than_days": 3}).status_code == 422
    h = csrf_headers(c)
    assert (
        c.post("/api/admin/retention/purge", json={"older_than_days": 7}, headers=h).status_code
        == 422
    )
    resp = c.post(
        "/api/admin/retention/purge",
        json={"older_than_days": 7, "confirm": "yes"},
        headers=h,
    )
    assert resp.status_code == 422
    resp = c.post(
        "/api/admin/retention/purge", json={"older_than_days": 7, "confirm": "PURGE"}, headers=h
    )
    assert resp.status_code == 200, resp.text
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "retention.purge"))
    assert entry.actor_user_id == admin.id and entry.details["older_than_days"] == 7


def test_api_is_admin_only(logged_in, world):
    c, _ = logged_in("analyst")
    assert c.get("/api/admin/retention").status_code == 403
    resp = c.post(
        "/api/admin/retention/purge",
        json={"older_than_days": 30, "confirm": "PURGE"},
        headers=csrf_headers(c),
    )
    assert resp.status_code == 403


def test_retry_of_job_with_purged_upload_is_refused(logged_in, db, settings, world):
    retention.purge(db, settings, DAYS, actor_username="test", now=NOW)
    job_id = db.scalar(
        text(f"SELECT id FROM ingestion_jobs WHERE file_id = {world['old_file'].id}")
    )
    db.execute(text(f"UPDATE ingestion_jobs SET status = 'failed' WHERE id = {job_id}"))
    c, _ = logged_in("analyst")
    resp = c.post(f"/api/jobs/{job_id}/retry", headers=csrf_headers(c))
    assert resp.status_code == 409 and "removed by data retention" in resp.json()["detail"]


def test_retry_refused_when_notes_reference_job_events(logged_in, db, make_user):
    ev = EventFactory(db)
    e = ev.add(0)
    ev.job.status = "failed"
    db.flush()
    inc = Incident(title="x", severity="low", created_by=make_user("analyst").id)
    db.add(inc)
    db.flush()
    db.add(
        InvestigationNote(incident_id=inc.id, body="ref", event_id=e.id, author_id=inc.created_by)
    )
    db.flush()
    c, _ = logged_in("analyst")
    resp = c.post(f"/api/jobs/{ev.job.id}/retry", headers=csrf_headers(c))
    assert resp.status_code == 409 and "investigation notes" in resp.json()["detail"]


def test_automatic_purge_runs_once_a_day(db, settings, world):
    assert maybe_auto_purge(db, settings, now=NOW) is False  # disabled by default
    settings.retention_auto_days = DAYS
    # The service computes its own cutoff from the real clock, so pin "now" for it too.
    real_cutoff = retention.cutoff_for
    retention.cutoff_for = lambda days, s, now=None: real_cutoff(days, s, NOW)
    try:
        assert maybe_auto_purge(db, settings, now=NOW) is True
        assert maybe_auto_purge(db, settings, now=NOW + timedelta(hours=23)) is False
        assert maybe_auto_purge(db, settings, now=NOW + timedelta(hours=25)) is True
    finally:
        retention.cutoff_for = real_cutoff
    actors = db.scalars(
        select(AuditLog.actor_username).where(AuditLog.action == "retention.purge")
    ).all()
    assert actors == ["worker", "worker"]
    assert db.get(Alert, world["closed"].id) is None


def test_cli_refuses_short_retention(capsys):
    assert cli.main(["purge", "--older-than-days", "3"]) == 2
    assert "at least 7 days" in capsys.readouterr().err


def test_cli_preview_output(monkeypatch, capsys):
    counts = retention.RetentionCounts(
        cutoff=NOW, older_than_days=90, alerts=2, evidence_links=5, events=1234,
        ingestion_errors=7, stored_files=1, stored_bytes=2048,
    )  # fmt: skip
    calls = []
    monkeypatch.setattr(
        retention, "preview", lambda db, s, d: calls.append(("preview", d)) or counts
    )
    monkeypatch.setattr(
        retention, "purge", lambda db, s, d, **kw: calls.append(("purge", d)) or counts
    )
    assert cli.main(["purge", "--older-than-days", "90"]) == 0
    out = capsys.readouterr().out
    assert "Would remove" in out and "1,234" in out and "Preview only" in out
    assert cli.main(["purge", "--older-than-days", "90", "--execute"]) == 0
    assert "Removed" in capsys.readouterr().out
    assert calls == [("preview", 90), ("purge", 90)]


def test_system_settings_and_health(logged_in, settings, tmp_path):
    settings.storage_dir = tmp_path / "storage"
    (settings.storage_dir / "files").mkdir(parents=True)
    (settings.storage_dir / "files" / "a").write_bytes(b"12345")
    settings.export_rate_per_minute = 7
    c, _ = logged_in("admin")
    body = c.get("/api/admin/system").json()
    by_key = {s["key"]: s for s in body["settings"]}
    assert by_key["export_rate_per_minute"]["value"] == 7
    assert by_key["export_rate_per_minute"]["env"] == "ST_EXPORT_RATE_PER_MINUTE"
    assert by_key["cookie_secure"]["value"] is False  # development default
    # No secrets: neither the database URL nor its password appear anywhere.
    raw = c.get("/api/admin/system").text
    assert "database_url" not in by_key
    password = settings.database_url.hosts()[0].get("password")
    assert password and password not in raw
    assert body["database"]["size_bytes"] > 0 and "events" in body["database"]["rows"]
    assert body["storage"]["files"] == 1 and body["storage"]["bytes"] == 5
    assert set(body["queue"]) >= {"jobs_queued", "runs_queued", "last_import_finished_at"}
    analyst, _ = logged_in("analyst")
    assert analyst.get("/api/admin/system").status_code == 403
