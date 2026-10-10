from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.api.routes import health as health_module
from app.core.config import get_settings
from app.db.session import check_database
from app.main import SECURITY_HEADERS, create_app


def test_health_ok(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": get_settings().version}


def test_ready_with_real_database(client: TestClient) -> None:
    resp = client.get("/api/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready", "database": "ok"}


def test_check_database_false_when_unreachable() -> None:
    # Port 1 on localhost: nothing listens there, so the connection must fail.
    engine = create_engine(
        "postgresql+psycopg://nobody:nothing@127.0.0.1:1/none",
        connect_args={"connect_timeout": 1},
    )
    assert check_database(engine) is False


def test_ready_returns_503_when_database_down(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(health_module, "check_database", lambda: False)
    resp = client.get("/api/ready")
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready", "database": "unavailable"}


def test_security_headers_present(client: TestClient) -> None:
    resp = client.get("/api/health")
    for key, value in SECURITY_HEADERS.items():
        assert resp.headers[key] == value
    assert len(resp.headers["X-Request-ID"]) == 32


def test_unhandled_error_hides_internals() -> None:
    app = create_app()

    @app.get("/api/_boom")
    def boom() -> None:
        raise RuntimeError("secret internal detail /etc/db-password")

    resp = TestClient(app, raise_server_exceptions=False).get("/api/_boom")
    assert resp.status_code == 500
    body = resp.text
    assert "secret internal detail" not in body
    assert "Traceback" not in body
    assert resp.json()["detail"] == "Internal server error"


def test_unknown_route_404_json(client: TestClient) -> None:
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}


def test_no_cors_by_default(client: TestClient) -> None:
    resp = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in resp.headers


def test_openapi_available(client: TestClient) -> None:
    resp = client.get("/api/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert "/api/health" in paths and "/api/ready" in paths
