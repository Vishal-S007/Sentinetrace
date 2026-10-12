"""Test fixtures.

Tests run against a real PostgreSQL database named by ST_DATABASE_URL. At session start
the schema is dropped and rebuilt with Alembic, so that database MUST be disposable.
Each test runs inside a transaction that is rolled back afterwards; application code
that calls commit() only commits a savepoint.
"""

import os
from collections.abc import Callable, Iterator

import pytest

if not os.environ.get("ST_DATABASE_URL"):
    raise RuntimeError(
        "ST_DATABASE_URL is not set. Point it at a disposable PostgreSQL test database, "
        "e.g. postgresql+psycopg://sentineltrace:<password>@localhost:5432/sentineltrace_test"
    )
if "test" not in os.environ["ST_DATABASE_URL"].rsplit("/", 1)[-1]:
    raise RuntimeError("Refusing to run: the test database name must contain 'test'.")
os.environ.setdefault("ST_ENVIRONMENT", "test")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Connection, select, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import Settings, get_settings  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.session import get_db, get_engine  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, User  # noqa: E402

BACKEND_DIR = os.path.dirname(os.path.dirname(__file__))
DEFAULT_PASSWORD = "correct-horse-battery-staple"


def alembic_config(database_url: str) -> Config:
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    cfg.attributes["database_url"] = database_url
    cfg.attributes["configure_logger"] = False
    return cfg


@pytest.fixture(scope="session", autouse=True)
def database_schema() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    command.upgrade(alembic_config(str(get_settings().database_url)), "head")


@pytest.fixture
def connection() -> Iterator[Connection]:
    conn = get_engine().connect()
    trans = conn.begin()
    try:
        yield conn
    finally:
        trans.rollback()
        conn.close()


@pytest.fixture
def db(connection: Connection) -> Iterator[Session]:
    session = Session(
        bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def settings() -> Settings:
    """A fresh Settings object per test; tests may mutate it."""
    return Settings()  # type: ignore[call-arg]


@pytest.fixture
def app(db: Session, settings: Settings):
    application = create_app(settings)
    application.dependency_overrides[get_db] = lambda: db
    application.dependency_overrides[get_settings] = lambda: settings
    return application


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


@pytest.fixture
def make_client(app) -> Callable[..., TestClient]:
    """Extra independent clients (separate cookie jars), optionally with a client IP."""

    def factory(ip: str = "testclient") -> TestClient:
        return TestClient(app, client=(ip, 50000))

    return factory


@pytest.fixture
def make_user(db: Session) -> Callable[..., User]:
    counter = {"n": 0}

    def factory(
        role: str = "viewer",
        username: str | None = None,
        password: str = DEFAULT_PASSWORD,
        is_active: bool = True,
    ) -> User:
        counter["n"] += 1
        role_obj = db.scalar(select(Role).where(Role.name == role))
        user = User(
            username=username or f"{role}{counter['n']}",
            password_hash=hash_password(password),
            role=role_obj,
            is_active=is_active,
        )
        db.add(user)
        db.flush()
        return user

    return factory


def login(client: TestClient, username: str, password: str = DEFAULT_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("st_csrf", "")}


@pytest.fixture
def logged_in(make_user, make_client) -> Callable[..., tuple[TestClient, User]]:
    """Return a client already logged in as a new user with the given role."""

    def factory(role: str = "viewer") -> tuple[TestClient, User]:
        user = make_user(role)
        c = make_client()
        resp = login(c, user.username)
        assert resp.status_code == 200, resp.text
        return c, user

    return factory
