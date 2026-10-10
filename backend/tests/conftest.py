import os

import pytest
from fastapi.testclient import TestClient

# Tests run against a real PostgreSQL database. Set ST_DATABASE_URL to a disposable
# test database (see README "Running tests"). We refuse to guess a default.
if not os.environ.get("ST_DATABASE_URL"):
    raise RuntimeError(
        "ST_DATABASE_URL is not set. Point it at a disposable PostgreSQL test database, "
        "e.g. postgresql+psycopg://sentineltrace:***@localhost:5432/sentineltrace_test"
    )
os.environ.setdefault("ST_ENVIRONMENT", "test")


@pytest.fixture
def client() -> TestClient:
    from app.main import create_app

    return TestClient(create_app())
