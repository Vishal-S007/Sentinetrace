import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.models import AuditLog
from app.services import audit as audit_service
from tests.conftest import csrf_headers, login

NEW_PASSWORD = "another-strong-passphrase"


# --- Role enforcement ------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst"])
@pytest.mark.parametrize("path", ["/api/users", "/api/roles", "/api/audit"])
def test_non_admins_get_403(logged_in, role, path):
    c, _ = logged_in(role)
    assert c.get(path).status_code == 403


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_non_admins_cannot_create_users(logged_in, role):
    c, _ = logged_in(role)
    resp = c.post(
        "/api/users",
        json={"username": "sneaky", "password": NEW_PASSWORD, "role": "admin"},
        headers=csrf_headers(c),
    )
    assert resp.status_code == 403


def test_roles_listing(logged_in):
    c, _ = logged_in("admin")
    roles = {r["name"]: r for r in c.get("/api/roles").json()}
    assert set(roles) == {"admin", "analyst", "viewer"}
    assert set(roles["viewer"]["permissions"]) < set(roles["analyst"]["permissions"])
    assert set(roles["analyst"]["permissions"]) < set(roles["admin"]["permissions"])


# --- User management -----------------------------------------------------------------


def test_admin_creates_user_who_can_log_in(logged_in, make_client, db):
    c, admin = logged_in("admin")
    resp = c.post(
        "/api/users",
        json={
            "username": "new.analyst",
            "password": NEW_PASSWORD,
            "role": "analyst",
            "email": "analyst@example.com",
        },
        headers=csrf_headers(c),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "analyst"
    assert "password" not in resp.text

    assert login(make_client(), "new.analyst", NEW_PASSWORD).status_code == 200
    entry = db.scalar(
        select(AuditLog).where(
            AuditLog.action == "user.create", AuditLog.target_id == str(resp.json()["id"])
        )
    )
    assert entry.actor_user_id == admin.id and entry.details["role"] == "analyst"
    assert NEW_PASSWORD not in str(entry.details)


def test_duplicate_username_case_insensitive(logged_in, make_user):
    c, _ = logged_in("admin")
    make_user(username="Dup.User")
    resp = c.post(
        "/api/users",
        json={"username": "dup.user", "password": NEW_PASSWORD, "role": "viewer"},
        headers=csrf_headers(c),
    )
    assert resp.status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "ok.name", "password": "short", "role": "viewer"},
        {"username": "ok.name", "password": "aaaaaaaaaaaaaaaa", "role": "viewer"},
        {"username": "../etc/passwd", "password": NEW_PASSWORD, "role": "viewer"},
        {"username": "x", "password": NEW_PASSWORD, "role": "viewer"},
        {"username": "ok.name", "password": NEW_PASSWORD, "role": "superuser"},
    ],
)
def test_create_user_validation(logged_in, payload):
    c, _ = logged_in("admin")
    assert c.post("/api/users", json=payload, headers=csrf_headers(c)).status_code == 422


def test_role_change_revokes_target_sessions(logged_in, db):
    admin_c, _ = logged_in("admin")
    target_c, target = logged_in("viewer")
    resp = admin_c.patch(
        f"/api/users/{target.id}", json={"role": "analyst"}, headers=csrf_headers(admin_c)
    )
    assert resp.status_code == 200 and resp.json()["role"] == "analyst"
    assert target_c.get("/api/auth/me").status_code == 401


def test_deactivate_user(logged_in, make_client):
    admin_c, _ = logged_in("admin")
    target_c, target = logged_in("analyst")
    resp = admin_c.patch(
        f"/api/users/{target.id}", json={"is_active": False}, headers=csrf_headers(admin_c)
    )
    assert resp.status_code == 200 and resp.json()["is_active"] is False
    assert target_c.get("/api/auth/me").status_code == 401
    assert login(make_client(), target.username).status_code == 401


def test_admin_cannot_lock_themselves_out(logged_in):
    c, admin = logged_in("admin")
    h = csrf_headers(c)
    assert (
        c.patch(f"/api/users/{admin.id}", json={"is_active": False}, headers=h).status_code == 400
    )
    assert c.patch(f"/api/users/{admin.id}", json={"role": "viewer"}, headers=h).status_code == 400
    assert c.get("/api/auth/me").json()["user"]["role"] == "admin"


def test_update_unknown_user_and_unknown_field(logged_in, make_user):
    c, _ = logged_in("admin")
    h = csrf_headers(c)
    assert c.patch("/api/users/999999", json={"role": "viewer"}, headers=h).status_code == 404
    target = make_user()
    resp = c.patch(f"/api/users/{target.id}", json={"password_hash": "x"}, headers=h)
    assert resp.status_code == 422


# --- Audit trail ---------------------------------------------------------------------


def test_audit_log_rejects_update_delete_truncate(db):
    entry = audit_service.record(db, "test.event")
    db.flush()
    for stmt in (
        "UPDATE audit_log SET action = 'tampered' WHERE id = :id",
        "DELETE FROM audit_log WHERE id = :id",
        "TRUNCATE audit_log",
    ):
        with pytest.raises(DBAPIError, match="append-only"):
            with db.begin_nested():
                db.execute(text(stmt), {"id": entry.id})
    assert db.scalar(select(AuditLog.action).where(AuditLog.id == entry.id)) == "test.event"


def test_audit_listing_filters_and_keyset_pagination(logged_in, db):
    c, _ = logged_in("admin")
    for i in range(5):
        audit_service.record(db, "test.page", target_id=i)
    db.flush()

    page1 = c.get("/api/audit", params={"action": "test.page", "limit": 2}).json()
    page2 = c.get(
        "/api/audit",
        params={"action": "test.page", "limit": 2, "before_id": page1["next_before_id"]},
    ).json()
    page3 = c.get(
        "/api/audit",
        params={"action": "test.page", "limit": 2, "before_id": page2["next_before_id"]},
    ).json()
    ids = [e["id"] for p in (page1, page2, page3) for e in p["items"]]
    assert len(ids) == 5 and len(set(ids)) == 5
    assert ids == sorted(ids, reverse=True)
    assert page3["next_before_id"] is None
    assert {e["action"] for p in (page1, page2, page3) for e in p["items"]} == {"test.page"}


def test_audit_limit_is_bounded(logged_in):
    c, _ = logged_in("admin")
    assert c.get("/api/audit", params={"limit": 1000}).status_code == 422


def test_audit_api_is_read_only(logged_in):
    c, _ = logged_in("admin")
    h = csrf_headers(c)
    assert c.post("/api/audit", json={}, headers=h).status_code == 405
    assert c.delete("/api/audit", headers=h).status_code == 405
