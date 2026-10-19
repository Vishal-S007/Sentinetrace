"""Legal facts endpoint, sign-in record pruning, deletion requests and erasure."""

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.models import AuditLog, LoginAttempt, User, UserSession
from app.services import privacy
from app.services.auth import utcnow
from tests.conftest import csrf_headers, login

# --- Legal facts ------------------------------------------------------------------------


def test_legal_facts_are_public_and_come_from_settings(client, settings):
    settings.operator_name = "Example Security Team"
    settings.operator_contact = "privacy@example.com"
    settings.login_attempt_retention_days = 45
    resp = client.get("/api/legal")
    assert resp.status_code == 200
    body = resp.json()
    assert body["operator"]["name"] == "Example Security Team"
    assert body["operator"]["contact"] == "privacy@example.com"
    assert body["retention"]["login_attempt_days"] == 45
    assert body["retention"]["session_absolute_hours"] == settings.session_absolute_hours
    assert [c["name"] for c in body["cookies"]] == ["st_session", "st_csrf"]


def test_legal_facts_never_include_secrets(client, settings):
    text = client.get("/api/legal").text.lower()
    assert "password" not in text
    assert "postgresql" not in text


def test_legal_cookie_list_matches_cookies_actually_set(make_user, make_client):
    user = make_user("viewer")
    c = make_client()
    login(c, user.username)
    listed = {x["name"] for x in c.get("/api/legal").json()["cookies"]}
    assert set(c.cookies.keys()) == listed


# --- Pruning ----------------------------------------------------------------------------


def test_prune_deletes_only_old_sign_in_records(db, settings, make_user):
    user = make_user("viewer")
    now = utcnow()
    old, recent = now - timedelta(days=40), now - timedelta(days=1)
    db.add_all(
        [
            LoginAttempt(username="someone", ip="198.51.100.1", succeeded=False, attempted_at=old),
            LoginAttempt(
                username="someone", ip="198.51.100.1", succeeded=False, attempted_at=recent
            ),
        ]
    )
    common = {"user_id": user.id, "csrf_hash": "c" * 64, "ip": "198.51.100.2"}
    db.add_all(
        [
            # expired long ago -> deleted
            UserSession(token_hash="a" * 64, expires_at=old, last_seen_at=old, **common),
            # revoked long ago -> deleted
            UserSession(
                token_hash="b" * 64, expires_at=now + timedelta(hours=1), revoked_at=old,
                last_seen_at=recent, **common,
            ),
            # live -> kept
            UserSession(
                token_hash="d" * 64, expires_at=now + timedelta(hours=1), last_seen_at=now, **common
            ),
        ]
    )  # fmt: skip
    db.flush()

    result = privacy.prune_sign_in_records(db, settings, now)
    assert (result.login_attempts, result.sessions) == (1, 2)
    assert db.scalar(select(func.count()).select_from(LoginAttempt)) == 1
    assert db.scalars(select(UserSession.token_hash)).all() == ["d" * 64]
    # Running again finds nothing more.
    again = privacy.prune_sign_in_records(db, settings, now)
    assert (again.login_attempts, again.sessions) == (0, 0)


def test_prune_never_deletes_inside_the_rate_limit_window(db, settings):
    settings.login_attempt_retention_days = 1
    settings.login_window_seconds = 3 * 86400  # longer than the retention period
    now = utcnow()
    db.add(
        LoginAttempt(
            username="x", ip="198.51.100.9", succeeded=False, attempted_at=now - timedelta(days=2)
        )
    )
    db.flush()
    assert privacy.prune_sign_in_records(db, settings, now).login_attempts == 0


# --- Deletion requests ------------------------------------------------------------------


def test_user_requests_deletion_once_and_admin_sees_it(logged_in, db):
    c, user = logged_in("viewer")
    first = c.post("/api/auth/deletion-request", headers=csrf_headers(c))
    assert first.status_code == 200, first.text
    second = c.post("/api/auth/deletion-request", headers=csrf_headers(c))
    assert second.json()["requested_at"] == first.json()["requested_at"]
    assert (
        db.scalar(
            select(func.count()).where(
                AuditLog.action == privacy.DELETION_REQUEST, AuditLog.target_id == str(user.id)
            )
        )
        == 1
    )
    assert c.get("/api/auth/me").json()["user"]["deletion_requested_at"] is not None

    admin, _ = logged_in("admin")
    listed = {u["id"]: u for u in admin.get("/api/users").json()}
    assert listed[user.id]["deletion_requested_at"] is not None


def test_deletion_request_requires_csrf(logged_in):
    c, _ = logged_in("viewer")
    assert c.post("/api/auth/deletion-request").status_code == 403


# --- Erasure ----------------------------------------------------------------------------


def _erase(c, user_id: int, confirm: str):
    return c.post(
        f"/api/users/{user_id}/erase", json={"confirm_username": confirm}, headers=csrf_headers(c)
    )


def test_admin_erases_a_users_personal_data(logged_in, make_user, make_client, db):
    target = make_user("analyst", username="Leaving.Person")
    target.email = "leaving@example.com"
    db.flush()
    tc = make_client()
    assert login(tc, "Leaving.Person").status_code == 200
    tc.post("/api/auth/deletion-request", headers=csrf_headers(tc))
    login(make_client(), "leaving.person", "wrong-password-123")  # a failed attempt too

    admin, admin_user = logged_in("admin")
    resp = _erase(admin, target.id, "leaving.person")  # case-insensitive confirmation
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["username"] == f"erased-user-{target.id}"
    assert body["email"] is None
    assert body["is_active"] is False
    assert body["last_login_at"] is None
    assert body["deletion_requested_at"] is None

    # Sessions and login attempts are gone, and the old session no longer works.
    assert db.scalar(select(func.count()).where(UserSession.user_id == target.id)) == 0
    assert db.scalar(select(func.count()).where(LoginAttempt.username == "leaving.person")) == 0
    assert tc.get("/api/auth/me").status_code == 401
    assert login(make_client(), "Leaving.Person").status_code == 401

    # The request is no longer pending, and the erasure is audited without personal data.
    listed = {u["id"]: u for u in admin.get("/api/users").json()}
    assert listed[target.id]["deletion_requested_at"] is None
    entry = db.scalar(select(AuditLog).where(AuditLog.action == privacy.ERASE))
    assert entry.actor_user_id == admin_user.id
    assert entry.target_id == str(target.id)
    assert "leaving" not in str(entry.details).lower()


def test_erase_guards(logged_in, make_user, db):
    admin, admin_user = logged_in("admin")
    target = make_user("viewer")
    assert _erase(admin, admin_user.id, admin_user.username).status_code == 400  # self
    assert _erase(admin, target.id, "someone-else").status_code == 400  # wrong name
    assert _erase(admin, 999_999, "x").status_code == 404
    assert _erase(admin, target.id, target.username).status_code == 200
    assert _erase(admin, target.id, f"erased-user-{target.id}").status_code == 409  # again
    # An erased account cannot be revived.
    revive = admin.patch(
        f"/api/users/{target.id}",
        json={"is_active": True, "password": "a-brand-new-passphrase"},
        headers=csrf_headers(admin),
    )
    assert revive.status_code == 409
    assert db.get(User, target.id).is_active is False


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_admins_can_erase(logged_in, make_user, role):
    c, _ = logged_in(role)
    target = make_user("viewer")
    assert _erase(c, target.id, target.username).status_code == 403


def test_erased_prefix_is_reserved_for_new_users(logged_in):
    admin, _ = logged_in("admin")
    resp = admin.post(
        "/api/users",
        json={"username": "erased-user-77", "password": "a-strong-passphrase", "role": "viewer"},
        headers=csrf_headers(admin),
    )
    assert resp.status_code == 400


def test_worker_housekeeping_prunes_sign_in_records(db, settings):
    from app import worker

    db.add(
        LoginAttempt(
            username="old", ip="198.51.100.3", succeeded=False,
            attempted_at=utcnow() - timedelta(days=400),
        )
    )  # fmt: skip
    db.flush()
    state = worker._State()
    state.last_recovery = float("inf")  # skip stale-job recovery in this test
    state.last_retention_check = float("-inf")  # the hourly housekeeping is due
    assert worker._tick(db, settings, state) is False  # no queued work: housekeeping runs
    assert db.scalar(select(func.count()).where(LoginAttempt.username == "old")) == 0
