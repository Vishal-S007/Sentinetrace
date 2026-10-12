import os
import secrets

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from app import cli
from app.core.config import get_settings
from app.core.permissions import ROLE_PERMISSIONS, Permission, permissions_for
from app.core.security import hash_password, token_digest, verify_password
from app.db.session import Base
from tests.conftest import alembic_config


@pytest.fixture
def scratch_database_url():
    """A brand-new empty database, dropped afterwards."""
    base = make_url(str(get_settings().database_url))
    name = f"st_migr_{secrets.token_hex(4)}"
    admin = create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def test_migrations_upgrade_downgrade_upgrade(scratch_database_url):
    cfg = alembic_config(scratch_database_url)
    engine = create_engine(scratch_database_url)
    try:
        command.upgrade(cfg, "head")
        tables = set(inspect(engine).get_table_names())
        assert {"users", "roles", "sessions", "audit_log", "login_attempts", "app_config"} <= tables

        command.downgrade(cfg, "base")
        assert set(inspect(engine).get_table_names()) <= {"alembic_version"}

        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            roles = conn.execute(text("SELECT name FROM roles ORDER BY name")).scalars().all()
        assert roles == ["admin", "analyst", "viewer"]
    finally:
        engine.dispose()


def test_models_match_migrations():
    """No drift: the ORM models and the migrated schema are identical."""
    engine = create_engine(str(get_settings().database_url))
    try:
        with engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
        assert diff == []
    finally:
        engine.dispose()


# --- Unit tests ----------------------------------------------------------------------


def test_password_hashing():
    h = hash_password("a-long-test-password")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "a-long-test-password")
    assert not verify_password(h, "a-long-test-passworD")
    assert not verify_password(None, "anything")
    assert not verify_password("not-a-hash", "anything")


def test_token_digest_is_sha256_hex():
    assert len(token_digest("x")) == 64 and token_digest("x") != token_digest("y")


def test_permission_hierarchy():
    assert permissions_for("viewer") < permissions_for("analyst") < permissions_for("admin")
    assert permissions_for("admin") == frozenset(Permission)
    assert permissions_for("unknown-role") == frozenset()
    assert set(ROLE_PERMISSIONS) == {"admin", "analyst", "viewer"}


def test_cli_create_admin(monkeypatch, capsys):
    username = f"cliadmin{secrets.token_hex(3)}"
    monkeypatch.setitem(os.environ, "ST_ADMIN_PASSWORD", "cli-created-password")
    assert cli.main(["create-admin", "--username", username]) == 0
    assert cli.main(["create-admin", "--username", username]) == 1  # duplicate
    monkeypatch.setitem(os.environ, "ST_ADMIN_PASSWORD", "short")
    assert cli.main(["create-admin", "--username", f"{username}x"]) == 2
    assert cli.main(["create-admin", "--username", "bad/name"]) == 2
