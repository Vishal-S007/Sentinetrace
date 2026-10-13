"""Worker heartbeat and the container health check built on it."""

import os

from app.core.config import get_settings
from app.worker import check_health, heartbeat_max_age, main, run


def test_no_heartbeat_file_configured_is_unhealthy():
    assert check_health(None, 1.0) is False


def test_missing_file_is_unhealthy(tmp_path):
    assert check_health(tmp_path / "beat", 1.0) is False


def test_fresh_and_stale_heartbeat(tmp_path):
    beat = tmp_path / "beat"
    beat.touch()
    mtime = beat.stat().st_mtime
    limit = heartbeat_max_age(1.0)
    assert check_health(beat, 1.0, now=mtime + limit) is True
    assert check_health(beat, 1.0, now=mtime + limit + 1) is False


def test_limit_scales_with_poll_interval():
    assert heartbeat_max_age(1.0) == 30.0
    assert heartbeat_max_age(20.0) == 100.0


def test_worker_loop_touches_heartbeat(db, tmp_path, monkeypatch):
    beat = tmp_path / "beat"
    monkeypatch.setenv("ST_WORKER_HEARTBEAT_FILE", str(beat))
    monkeypatch.setenv("ST_STORAGE_DIR", str(tmp_path / "storage"))
    get_settings.cache_clear()
    try:
        assert main(["--check-health"]) == 1
        run(once=True)
        assert beat.exists()
        assert main(["--check-health"]) == 0
        os.utime(beat, (0, 0))
        assert main(["--check-health"]) == 1
    finally:
        get_settings.cache_clear()
