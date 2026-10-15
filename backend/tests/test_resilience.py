"""Failure handling: worker keeps running through database errors, the API reports an
outage as 503 and a full disk as 507, and neither leaks internals."""

import errno

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app import worker
from app.db.session import get_db
from app.ingestion import storage
from tests.conftest import csrf_headers


def db_down() -> OperationalError:
    return OperationalError("SELECT 1", {}, Exception("connection refused (secret-host:5432)"))


def test_worker_backs_off_and_recovers(monkeypatch, settings):
    outcomes = iter([db_down(), db_down(), db_down(), True, False])
    delays: list[float] = []

    def tick(db, s, state):
        result = next(outcomes)
        if isinstance(result, Exception):
            raise result
        return result

    def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 4:  # after recovering and one idle poll, stop
            monkeypatch.setattr(worker, "_stop", True)

    monkeypatch.setattr(worker, "_tick", tick)
    monkeypatch.setattr(worker, "_sleep", sleep)
    monkeypatch.setattr(worker, "_stop", False)
    monkeypatch.setenv("ST_WORKER_POLL_SECONDS", "1")
    worker.get_settings.cache_clear()
    try:
        processed = worker.run()
    finally:
        worker.get_settings.cache_clear()
    assert processed == 1
    assert delays == [2.0, 4.0, 8.0, 1.0]  # exponential backoff, then the normal poll


def test_backoff_is_capped(monkeypatch):
    delays: list[float] = []

    def tick(db, s, state):
        raise db_down()

    def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 12:
            monkeypatch.setattr(worker, "_stop", True)

    monkeypatch.setattr(worker, "_tick", tick)
    monkeypatch.setattr(worker, "_sleep", sleep)
    monkeypatch.setattr(worker, "_stop", False)
    worker.run()
    assert max(delays) == worker.MAX_BACKOFF_SECONDS
    assert delays == sorted(delays)


def test_worker_once_does_not_crash_on_errors(monkeypatch):
    monkeypatch.setattr(worker, "_tick", lambda db, s, state: (_ for _ in ()).throw(db_down()))
    monkeypatch.setattr(worker, "_stop", False)
    assert worker.run(once=True) == 0


def test_database_outage_returns_503_without_details(app, client):
    def broken():
        raise db_down()
        yield  # pragma: no cover

    app.dependency_overrides[get_db] = broken
    client.cookies.set("st_session", "x")
    resp = client.get("/api/alerts")
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "5"
    body = resp.text
    assert "temporarily unavailable" in body and "request_id" in resp.json()
    assert "secret-host" not in body and "Traceback" not in body


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EDQUOT])
def test_full_disk_on_upload_returns_507(logged_in, monkeypatch, settings, tmp_path, code):
    settings.storage_dir = tmp_path / "storage"
    c, _ = logged_in("analyst")
    h = csrf_headers(c)
    sid = c.post("/api/sources", json={"name": "web", "format": "auto"}, headers=h).json()["id"]

    def full(*args, **kwargs):
        raise OSError(code, "No space left on device")

    monkeypatch.setattr(storage, "stage_upload", full)
    resp = c.post(f"/api/sources/{sid}/files", files={"file": ("a.log", b"x\n")}, headers=h)
    assert resp.status_code == 507
    assert "out of storage space" in resp.json()["detail"]


def test_other_storage_errors_are_generic_500(logged_in, app, monkeypatch, settings, tmp_path):
    settings.storage_dir = tmp_path / "storage"
    c, _ = logged_in("analyst")
    quiet = TestClient(app, raise_server_exceptions=False, cookies=dict(c.cookies))
    h = csrf_headers(c)
    sid = c.post("/api/sources", json={"name": "web", "format": "auto"}, headers=h).json()["id"]

    def denied(*args, **kwargs):
        raise OSError(errno.EACCES, "Permission denied: /srv/secret/path")

    monkeypatch.setattr(storage, "stage_upload", denied)
    resp = quiet.post(f"/api/sources/{sid}/files", files={"file": ("a.log", b"x\n")}, headers=h)
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Internal server error"
    assert "/srv/secret" not in resp.text
