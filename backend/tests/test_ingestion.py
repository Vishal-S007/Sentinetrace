"""Integration tests: upload -> stored file -> job -> worker processing -> events/errors."""

import csv
import io
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.ingestion.processor import claim_next_job, process_job, recover_stale_jobs, utcnow
from app.ingestion.storage import resolve_storage_path, sanitize_filename
from app.models import AuditLog, Event, ImportedFile, IngestionError, IngestionJob
from app.worker import run as worker_run
from tests.conftest import csrf_headers
from tests.test_parsers import NGINX_CUSTOM

FIXTURES = Path(__file__).parent / "fixtures" / "logs"


@pytest.fixture(autouse=True)
def isolated_storage(settings, tmp_path):
    settings.storage_dir = tmp_path / "storage"
    return settings.storage_dir


@pytest.fixture
def analyst(logged_in):
    client, user = logged_in("analyst")
    return client


def create_source(client, name="web", fmt="auto", **extra):
    body = {"name": name, "format": fmt, **extra}
    resp = client.post("/api/sources", json=body, headers=csrf_headers(client))
    assert resp.status_code == 201, resp.text
    return resp.json()


def upload(client, source_id, content: bytes, filename="access.log", fmt=None):
    data = {"format": fmt} if fmt else {}
    return client.post(
        f"/api/sources/{source_id}/files",
        files={"file": (filename, content, "text/plain")},
        data=data,
        headers=csrf_headers(client),
    )


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def run_worker(db, settings):
    jobs = []
    while (job := claim_next_job(db)) is not None:
        jobs.append(process_job(db, job, settings))
    return jobs


# --- Happy path per format ---------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture,source_format,pattern,expected",
    [
        ("apache_combined_valid.log", "apache_combined", None, (6, 6, 0, "completed")),
        ("apache_combined_mixed.log", "apache_combined", None, (8, 5, 3, "completed_with_errors")),
        ("nginx_common.log", "nginx_common", None, (4, 4, 0, "completed")),
        ("nginx_custom.log", "nginx_custom", NGINX_CUSTOM, (3, 2, 1, "completed_with_errors")),
        ("app_events.jsonl", "json", None, (9, 6, 3, "completed_with_errors")),
        ("auth.log", "auth_log", None, (9, 8, 1, "completed_with_errors")),
        ("apache_combined_valid.log", "auto", None, (6, 6, 0, "completed")),
    ],
)
def test_pipeline_per_format(analyst, db, settings, fixture, source_format, pattern, expected):
    extra = {"custom_pattern": pattern} if pattern else {}
    source = create_source(analyst, fmt=source_format, **extra)
    resp = upload(analyst, source["id"], fixture_bytes(fixture), filename=fixture)
    assert resp.status_code == 201, resp.text
    assert resp.json()["job"]["status"] == "queued"

    [job] = run_worker(db, settings)
    total, parsed, rejected, status = expected
    assert (job.total_lines, job.parsed_count, job.rejected_count, job.status) == (
        total,
        parsed,
        rejected,
        status,
    )
    assert job.duplicate_count == 0
    assert job.format == (source_format if source_format != "auto" else "apache_combined")
    assert (
        db.scalar(select(func.count()).select_from(Event).where(Event.job_id == job.id)) == parsed
    )
    assert (
        db.scalar(
            select(func.count()).select_from(IngestionError).where(IngestionError.job_id == job.id)
        )
        == rejected
    )


def test_events_preserve_raw_line_and_separate_times(analyst, db, settings):
    source = create_source(analyst, fmt="apache_combined")
    upload(analyst, source["id"], fixture_bytes("apache_combined_valid.log"))
    run_worker(db, settings)
    events = db.scalars(select(Event).order_by(Event.line_number)).all()
    original = fixture_bytes("apache_combined_valid.log").decode().splitlines()
    assert [e.raw_line for e in events] == original
    assert [e.line_number for e in events] == [1, 2, 3, 4, 5, 6]
    first = events[0]
    assert first.event_time.isoformat() == "2026-10-10T13:55:36+00:00"
    assert first.ingested_at > first.event_time  # ingestion time recorded separately
    assert str(events[3].source_ip) == "2001:db8::42"


def test_job_status_and_error_details_api(analyst, db, settings):
    source = create_source(analyst, fmt="apache_combined")
    job_id = upload(analyst, source["id"], fixture_bytes("apache_combined_mixed.log")).json()[
        "job"
    ]["id"]
    run_worker(db, settings)

    job = analyst.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "completed_with_errors" and job["filename"] == "access.log"
    assert job["source_name"] == "web" and job["created_by"].startswith("analyst")

    errors = analyst.get(f"/api/jobs/{job_id}/errors").json()
    assert [e["line_number"] for e in errors["items"]] == [3, 4, 6]
    assert errors["total_rejected"] == 3 and errors["stored"] == 3 and not errors["truncated"]
    assert errors["items"][1]["raw_line"] == "this is not an access log line at all"

    page = analyst.get(f"/api/jobs/{job_id}/errors", params={"limit": 2}).json()
    rest = analyst.get(
        f"/api/jobs/{job_id}/errors", params={"after_id": page["next_after_id"]}
    ).json()
    assert len(page["items"]) == 2 and len(rest["items"]) == 1

    resp = analyst.get(f"/api/jobs/{job_id}/errors.csv")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0] == ["line_number", "reason", "raw_line"] and len(rows) == 4

    listing = analyst.get("/api/jobs", params={"status": "completed_with_errors"}).json()
    assert [j["id"] for j in listing["items"]] == [job_id]
    assert analyst.get("/api/jobs", params={"status": "failed"}).json()["items"] == []


def test_csv_export_neutralizes_formula_injection(analyst, db, settings):
    source = create_source(analyst, fmt="nginx_common")
    upload(analyst, source["id"], b'=HYPERLINK("http://evil")\n+cmd|calc\n')
    [job] = run_worker(db, settings)
    rows = list(csv.reader(io.StringIO(analyst.get(f"/api/jobs/{job.id}/errors.csv").text)))
    assert rows[1][2].startswith("'=") and rows[2][2].startswith("'+")


# --- Duplicates --------------------------------------------------------------------------


def test_same_file_twice_is_rejected(analyst, db):
    source = create_source(analyst)
    content = fixture_bytes("nginx_common.log")
    assert upload(analyst, source["id"], content).status_code == 201
    second = upload(analyst, source["id"], content, filename="renamed.log")
    assert second.status_code == 409 and "already imported" in second.json()["detail"]
    assert db.scalar(select(func.count()).select_from(ImportedFile)) == 1


def test_same_file_into_another_source_is_allowed(analyst):
    content = fixture_bytes("nginx_common.log")
    a, b = create_source(analyst, name="a"), create_source(analyst, name="b")
    assert upload(analyst, a["id"], content).status_code == 201
    assert upload(analyst, b["id"], content).status_code == 201


def test_overlapping_files_count_duplicates(analyst, db, settings):
    source = create_source(analyst, fmt="apache_combined")
    upload(analyst, source["id"], fixture_bytes("overlap_part1.log"), filename="a.log")
    upload(analyst, source["id"], fixture_bytes("overlap_part2.log"), filename="b.log")
    first, second = run_worker(db, settings)
    # Two identical lines inside part1 are both kept (genuinely repeated requests).
    assert (first.parsed_count, first.duplicate_count) == (5, 0)
    # part2 repeats three of part1's lines (including both copies of /c).
    assert (second.parsed_count, second.duplicate_count, second.status) == (2, 3, "completed")
    assert db.scalar(select(func.count()).select_from(Event)) == 7


# --- Upload validation and safety --------------------------------------------------------


def test_malicious_filenames_are_never_used_as_paths(analyst, db, isolated_storage, tmp_path):
    source = create_source(analyst)
    names = {
        "../../etc/passwd": "passwd",
        "..\\..\\windows\\evil.log": "evil.log",
        "/abs/path/report.log": "report.log",
        "": "upload.log",
    }
    for i, (name, expected) in enumerate(names.items()):
        content = f'192.0.2.1 - - [10/Oct/2026:08:00:0{i} +0000] "GET / HTTP/1.1" 200 2\n'.encode()
        resp = upload(analyst, source["id"], content, filename=name)
        assert resp.status_code in (201, 422), resp.text
        if resp.status_code == 201:
            assert resp.json()["file"]["original_filename"] == expected
    for f in db.scalars(select(ImportedFile)).all():
        path = resolve_storage_path(isolated_storage, f.storage_key)
        assert path.is_file() and path.name == f.sha256
        assert path.is_relative_to(isolated_storage.resolve())
    assert not (tmp_path / "etc").exists()
    assert list((isolated_storage / "tmp").iterdir()) == []  # no leftover temp files


def test_sanitize_filename_strips_control_and_reserved_characters():
    assert sanitize_filename("a\x00b\nc<>:|?*.log") == "abc.log"
    assert sanitize_filename("  ...  ") == "upload.log"
    assert len(sanitize_filename("x" * 400 + ".log")) == 255


def test_resolve_storage_path_blocks_traversal(isolated_storage):
    with pytest.raises(ValueError):
        resolve_storage_path(isolated_storage, "../../etc/passwd")


@pytest.mark.parametrize(
    "filename,content,status_code,fragment",
    [
        ("logs.gz", b"\x1f\x8b\x08\x00binary", 415, "not supported"),
        ("access.log", b"\x1f\x8b\x08\x00binary", 415, "compressed or binary"),
        ("access.log", b"GET / HTTP/1.1\x00\x00\x00", 415, "NUL"),
        ("access.log", bytes(range(1, 32)) * 50, 415, "does not look like a text log"),
        ("access.log", b"", 422, "empty"),
    ],
)
def test_upload_type_validation(
    analyst, isolated_storage, filename, content, status_code, fragment
):
    source = create_source(analyst)
    resp = upload(analyst, source["id"], content, filename=filename)
    assert resp.status_code == status_code and fragment in resp.json()["detail"]
    tmp = isolated_storage / "tmp"
    assert not tmp.exists() or list(tmp.iterdir()) == []


def test_upload_size_limit(analyst, settings, isolated_storage):
    settings.max_upload_bytes = 200
    source = create_source(analyst)
    resp = upload(analyst, source["id"], b"x" * 201)
    assert resp.status_code == 413 and "limit" in resp.json()["detail"]
    assert list((isolated_storage / "tmp").iterdir()) == []


def test_body_size_middleware_rejects_before_parsing(analyst, settings):
    big = b"x" * (settings.max_upload_bytes + 2 * 1024 * 1024)
    resp = upload(analyst, 1, big)
    assert resp.status_code == 413
    # JSON endpoints have a 1 MB cap.
    resp = analyst.post(
        "/api/sources",
        content=b"{" + b" " * (1024 * 1024 + 10) + b"}",
        headers={**csrf_headers(analyst), "Content-Type": "application/json"},
    )
    assert resp.status_code == 413


def test_invalid_utf8_is_replaced_and_flagged(analyst, db, settings):
    source = create_source(analyst, fmt="nginx_common")
    line = b'192.0.2.1 - - [10/Oct/2026:08:00:00 +0000] "GET /caf\xe9 HTTP/1.1" 200 2\n'
    resp = upload(analyst, source["id"], line)
    assert resp.json()["file"]["encoding"] == "utf-8 (invalid bytes replaced)"
    run_worker(db, settings)
    event = db.scalar(select(Event))
    assert event.path == "/caf�" and event.attributes["encoding_replaced"] is True


def test_utf8_bom_and_crlf_are_handled(analyst, db, settings):
    source = create_source(analyst, fmt="nginx_common")
    content = "﻿" + fixture_bytes("nginx_common.log").decode().replace("\n", "\r\n")
    upload(analyst, source["id"], content.encode())
    [job] = run_worker(db, settings)
    assert (job.parsed_count, job.rejected_count) == (4, 0)


def test_overlong_lines_are_rejected_not_fatal(analyst, db, settings):
    settings.max_line_bytes = 200
    source = create_source(analyst, fmt="nginx_common")
    good = fixture_bytes("nginx_common.log")
    upload(analyst, source["id"], good + b"A" * 500 + b"\n")
    [job] = run_worker(db, settings)
    assert (job.parsed_count, job.rejected_count) == (4, 1)
    err = db.scalar(select(IngestionError))
    assert "longer than 200 bytes" in err.reason and len(err.raw_line) <= 2000


def test_line_limit_fails_job_with_partial_counts(analyst, db, settings):
    settings.max_lines_per_file = 2
    settings.ingest_batch_size = 1
    source = create_source(analyst, fmt="nginx_common")
    upload(analyst, source["id"], fixture_bytes("nginx_common.log"))
    [job] = run_worker(db, settings)
    assert job.status == "failed" and "limit of 2 lines" in job.error_message
    assert job.total_lines == 2 and job.parsed_count == 2


def test_error_storage_is_capped(analyst, db, settings):
    settings.max_errors_per_job = 2
    source = create_source(analyst, fmt="nginx_common")
    upload(analyst, source["id"], b"bad1\nbad2\nbad3\nbad4\n" + fixture_bytes("nginx_common.log"))
    [job] = run_worker(db, settings)
    assert job.rejected_count == 4 and job.errors_truncated is True
    assert db.scalar(select(func.count()).select_from(IngestionError)) == 2


def test_small_batches_give_same_counts(analyst, db, settings):
    settings.ingest_batch_size = 2
    source = create_source(analyst, fmt="apache_combined")
    upload(analyst, source["id"], fixture_bytes("apache_combined_mixed.log"))
    [job] = run_worker(db, settings)
    assert (job.total_lines, job.parsed_count, job.rejected_count) == (8, 5, 3)


# --- Failure handling --------------------------------------------------------------------


def test_undetectable_format_fails_with_guidance(analyst, db, settings):
    source = create_source(analyst, fmt="auto")
    upload(analyst, source["id"], b"hello\nworld\n")
    [job] = run_worker(db, settings)
    assert job.status == "failed" and "Choose the format explicitly" in job.error_message


def test_wrong_format_fails_when_nothing_parses(analyst, db, settings):
    source = create_source(analyst, fmt="json")
    upload(analyst, source["id"], fixture_bytes("nginx_common.log"))
    [job] = run_worker(db, settings)
    assert job.status == "failed" and "No lines could be parsed as json" in job.error_message


def test_upload_format_override(analyst, db, settings):
    source = create_source(analyst, fmt="json")
    upload(analyst, source["id"], fixture_bytes("nginx_common.log"), fmt="nginx_common")
    [job] = run_worker(db, settings)
    assert job.status == "completed" and job.format == "nginx_common"


def test_missing_and_tampered_files_fail_then_retry(analyst, db, settings, isolated_storage):
    source = create_source(analyst, fmt="nginx_common")
    body = upload(analyst, source["id"], fixture_bytes("nginx_common.log")).json()
    stored = resolve_storage_path(
        isolated_storage, db.get(ImportedFile, body["file"]["id"]).storage_key
    )
    original = stored.read_bytes()

    stored.chmod(0o640)
    stored.write_bytes(original + b"tampered")
    [job] = run_worker(db, settings)
    assert job.status == "failed" and "integrity" in job.error_message

    assert (
        analyst.post(f"/api/jobs/{job.id}/retry", headers=csrf_headers(analyst)).status_code == 202
    )
    stored.unlink()
    [job] = run_worker(db, settings)
    assert job.status == "failed" and "missing" in job.error_message

    stored.write_bytes(original)
    resp = analyst.post(f"/api/jobs/{job.id}/retry", headers=csrf_headers(analyst))
    assert resp.status_code == 202 and resp.json()["status"] == "queued"
    [job] = run_worker(db, settings)
    assert job.status == "completed" and job.parsed_count == 4 and job.attempts == 3
    # Retrying a non-failed job is refused.
    assert (
        analyst.post(f"/api/jobs/{job.id}/retry", headers=csrf_headers(analyst)).status_code == 409
    )


def test_retry_clears_partial_results(analyst, db, settings):
    settings.max_lines_per_file = 2
    source = create_source(analyst, fmt="nginx_common")
    upload(analyst, source["id"], fixture_bytes("nginx_common.log"))
    [job] = run_worker(db, settings)
    assert job.status == "failed" and job.parsed_count == 2
    settings.max_lines_per_file = 1000
    analyst.post(f"/api/jobs/{job.id}/retry", headers=csrf_headers(analyst))
    [job] = run_worker(db, settings)
    assert (job.status, job.parsed_count, job.duplicate_count) == ("completed", 4, 0)
    assert db.scalar(select(func.count()).select_from(Event)) == 4


def test_stale_running_jobs_are_recovered(analyst, db, settings):
    source = create_source(analyst, fmt="nginx_common")
    upload(analyst, source["id"], fixture_bytes("nginx_common.log"))
    job = claim_next_job(db)
    job.heartbeat_at = utcnow() - timedelta(minutes=settings.job_stale_minutes + 1)
    db.commit()
    assert recover_stale_jobs(db, settings) == 1
    db.refresh(job)
    assert job.status == "queued"

    job = claim_next_job(db)
    job.attempts = settings.max_job_attempts
    job.heartbeat_at = utcnow() - timedelta(minutes=settings.job_stale_minutes + 1)
    db.commit()
    recover_stale_jobs(db, settings)
    db.refresh(job)
    assert job.status == "failed" and "maximum attempts" in job.error_message


def test_worker_once_with_empty_queue_exits():
    assert worker_run(once=True) == 0


# --- Sources, RBAC and audit -------------------------------------------------------------


def test_viewer_can_read_but_not_import(logged_in, analyst):
    source = create_source(analyst)
    viewer, _ = logged_in("viewer")
    assert viewer.get("/api/sources").status_code == 200
    assert viewer.get("/api/jobs").status_code == 200
    assert viewer.get("/api/formats").status_code == 200
    assert (
        viewer.post("/api/sources", json={"name": "x"}, headers=csrf_headers(viewer)).status_code
        == 403
    )
    assert upload(viewer, source["id"], b"x").status_code == 403


@pytest.mark.parametrize(
    "body,fragment",
    [
        ({"name": "x", "format": "nginx_custom"}, "custom_pattern"),
        ({"name": "x", "format": "nginx_custom", "custom_pattern": "$remote_addr"}, "time_local"),
        ({"name": "x", "timezone": "Mars/Olympus"}, "unknown time zone"),
        ({"name": "x", "format": "syslog"}, "format"),
        ({"name": "   "}, "blank"),
    ],
)
def test_source_validation(analyst, body, fragment):
    resp = analyst.post("/api/sources", json=body, headers=csrf_headers(analyst))
    assert resp.status_code == 422 and fragment in resp.text


def test_source_name_unique_and_update(analyst, db, settings):
    source = create_source(analyst, name="edge")
    dup = analyst.post("/api/sources", json={"name": "edge"}, headers=csrf_headers(analyst))
    assert dup.status_code == 409
    h = csrf_headers(analyst)
    resp = analyst.patch(
        f"/api/sources/{source['id']}",
        json={"enabled": False, "timezone": "Asia/Kolkata"},
        headers=h,
    )
    assert resp.status_code == 200 and resp.json()["enabled"] is False
    blocked = upload(analyst, source["id"], fixture_bytes("nginx_common.log"))
    assert blocked.status_code == 409 and "disabled" in blocked.json()["detail"]
    bad = analyst.patch(f"/api/sources/{source['id']}", json={"format": "nginx_custom"}, headers=h)
    assert bad.status_code == 422


def test_source_listing_includes_stats(analyst, db, settings):
    source = create_source(analyst, fmt="nginx_common")
    upload(analyst, source["id"], fixture_bytes("nginx_common.log"))
    run_worker(db, settings)
    [listed] = [s for s in analyst.get("/api/sources").json() if s["id"] == source["id"]]
    assert listed["file_count"] == 1 and listed["event_count"] == 4
    assert listed["last_upload_at"] is not None


def test_upload_and_source_actions_are_audited(analyst, db):
    source = create_source(analyst)
    upload(analyst, source["id"], fixture_bytes("nginx_common.log"), filename="../x.log")
    actions = db.scalars(select(AuditLog.action).order_by(AuditLog.id)).all()
    assert "source.create" in actions and "file.upload" in actions
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "file.upload"))
    assert entry.details["filename"] == "x.log" and len(entry.details["sha256"]) == 64


def test_job_and_source_404s(analyst):
    assert analyst.get("/api/jobs/999999").status_code == 404
    assert analyst.get("/api/jobs/999999/errors").status_code == 404
    assert upload(analyst, 999999, b"x").status_code == 404


def test_jobs_listing_is_bounded(analyst):
    assert analyst.get("/api/jobs", params={"limit": 1000}).status_code == 422


def test_status_constraint_in_database(db):
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.execute(text("INSERT INTO log_sources (name, format) VALUES ('bad', 'nope')"))
    assert IngestionJob.__table__.c.status is not None
