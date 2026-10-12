from datetime import timedelta

from sqlalchemy import select, update

from app.models import AuditLog, LoginAttempt, UserSession
from app.services.auth import utcnow
from tests.conftest import DEFAULT_PASSWORD, csrf_headers, login


def _set_cookie_headers(resp) -> dict[str, str]:
    out = {}
    for raw in resp.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0]
        out[name] = raw.lower()
    return out


# --- Login ---------------------------------------------------------------------------


def test_login_success_sets_secure_cookies(client, make_user, db):
    user = make_user("analyst")
    resp = login(client, user.username)
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["username"] == user.username
    assert body["user"]["role"] == "analyst"
    assert "logs:import" in body["permissions"] and "users:manage" not in body["permissions"]
    assert "password" not in resp.text and "hash" not in resp.text

    cookies = _set_cookie_headers(resp)
    assert "httponly" in cookies["st_session"]
    assert "samesite=lax" in cookies["st_session"]
    assert "httponly" not in cookies["st_csrf"]
    assert "samesite=strict" in cookies["st_csrf"]

    # Only a hash of the token is stored.
    token = client.cookies["st_session"]
    stored = db.scalars(select(UserSession.token_hash)).all()
    assert token not in stored and len(stored[-1]) == 64


def test_login_is_case_insensitive_on_username(client, make_user):
    make_user(username="Alice.Admin")
    assert login(client, "alice.admin").status_code == 200


def test_wrong_password_and_unknown_user_give_same_401(client, make_user):
    user = make_user()
    wrong = login(client, user.username, "not-the-password")
    unknown = login(client, "no-such-user", "whatever-password")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "Invalid username or password"}
    assert "st_session" not in client.cookies


def test_inactive_user_cannot_log_in(client, make_user):
    user = make_user(is_active=False)
    assert login(client, user.username).status_code == 401


def test_login_requires_json_content_type(client, make_user):
    user = make_user()
    resp = client.post(
        "/api/auth/login",
        content=f'{{"username":"{user.username}","password":"{DEFAULT_PASSWORD}"}}',
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 422
    assert "st_session" not in client.cookies


def test_validation_errors_do_not_echo_input(client):
    secret = "x" * 500  # exceeds max length
    resp = client.post("/api/auth/login", json={"username": "someone", "password": secret})
    assert resp.status_code == 422
    assert secret not in resp.text


def test_login_failure_is_audited_without_password(client, make_user, db):
    user = make_user()
    login(client, user.username, "wrong-password-123")
    entry = db.scalars(
        select(AuditLog).where(AuditLog.action == "auth.login.failure").order_by(AuditLog.id.desc())
    ).first()
    assert entry is not None and entry.actor_username == user.username
    assert "wrong-password-123" not in str(entry.details)


# --- Rate limiting ---------------------------------------------------------------------


def test_sixth_failed_login_is_rate_limited(client, make_user):
    user = make_user()
    for _ in range(5):
        assert login(client, user.username, "bad-password").status_code == 401
    blocked = login(client, user.username, "bad-password")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    # Even the correct password is refused while limited.
    assert login(client, user.username).status_code == 429


def test_rate_limit_per_ip_across_usernames(make_client, make_user, settings):
    settings.login_max_failures_per_ip = 3
    c = make_client(ip="203.0.113.7")
    for i in range(3):
        assert login(c, f"guess{i}", "bad-password").status_code == 401
    victim = make_user()
    assert login(c, victim.username).status_code == 429
    # A different IP is unaffected.
    assert login(make_client(ip="198.51.100.9"), victim.username).status_code == 200


def test_failures_outside_window_do_not_count(client, make_user, db, settings):
    user = make_user()
    old = utcnow() - timedelta(seconds=settings.login_window_seconds + 60)
    for _ in range(10):
        db.add(LoginAttempt(username=user.username, succeeded=False, attempted_at=old))
    db.flush()
    assert login(client, user.username).status_code == 200


# --- Sessions ------------------------------------------------------------------------


def test_me_requires_authentication(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_user_and_permissions(logged_in):
    c, user = logged_in("viewer")
    resp = c.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json()["user"]["id"] == user.id
    assert "alerts:triage" not in resp.json()["permissions"]


def test_logout_invalidates_session_server_side(logged_in):
    c, _ = logged_in()
    old_session = c.cookies["st_session"]
    old_csrf = c.cookies["st_csrf"]
    resp = c.post("/api/auth/logout", headers=csrf_headers(c))
    assert resp.status_code == 204
    assert "st_session" not in c.cookies

    # Replaying the old cookie must fail: the session is revoked in the database.
    c.cookies.set("st_session", old_session)
    c.cookies.set("st_csrf", old_csrf)
    assert c.get("/api/auth/me").status_code == 401


def test_random_or_tampered_cookie_rejected(client):
    client.cookies.set("st_session", "forged-token-value")
    assert client.get("/api/auth/me").status_code == 401


def test_absolute_expiry(logged_in, db):
    c, user = logged_in()
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id)
        .values(expires_at=utcnow() - timedelta(seconds=1))
    )
    assert c.get("/api/auth/me").status_code == 401


def test_idle_timeout(logged_in, db, settings):
    c, user = logged_in()
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id)
        .values(last_seen_at=utcnow() - timedelta(minutes=settings.session_idle_minutes + 1))
    )
    assert c.get("/api/auth/me").status_code == 401


def test_deactivated_user_session_stops_working(logged_in, db):
    c, user = logged_in()
    user.is_active = False
    db.flush()
    assert c.get("/api/auth/me").status_code == 401


# --- CSRF ----------------------------------------------------------------------------


def test_state_change_without_csrf_header_is_rejected(logged_in):
    c, _ = logged_in()
    assert c.post("/api/auth/logout").status_code == 403
    assert c.get("/api/auth/me").status_code == 200  # session still valid


def test_csrf_header_must_match_cookie(logged_in):
    c, _ = logged_in()
    assert c.post("/api/auth/logout", headers={"X-CSRF-Token": "wrong"}).status_code == 403


def test_csrf_token_from_another_session_is_rejected(logged_in):
    c1, _ = logged_in()
    c2, _ = logged_in()
    foreign = c2.cookies["st_csrf"]
    c1.cookies.set("st_csrf", foreign)  # attacker plants a cookie + header from their session
    assert c1.post("/api/auth/logout", headers={"X-CSRF-Token": foreign}).status_code == 403


# --- Password change -----------------------------------------------------------------


def test_password_change_flow(logged_in, make_client):
    c, user = logged_in()
    other = make_client()
    assert login(other, user.username).status_code == 200

    bad = c.post(
        "/api/auth/password",
        json={"current_password": "nope", "new_password": "a-brand-new-password"},
        headers=csrf_headers(c),
    )
    assert bad.status_code == 400

    ok = c.post(
        "/api/auth/password",
        json={"current_password": DEFAULT_PASSWORD, "new_password": "a-brand-new-password"},
        headers=csrf_headers(c),
    )
    assert ok.status_code == 204
    assert c.get("/api/auth/me").status_code == 200  # current session kept
    assert other.get("/api/auth/me").status_code == 401  # other sessions revoked
    assert login(make_client(), user.username).status_code == 401
    assert login(make_client(), user.username, "a-brand-new-password").status_code == 200


def test_password_change_rejects_weak_password(logged_in):
    c, _ = logged_in()
    resp = c.post(
        "/api/auth/password",
        json={"current_password": DEFAULT_PASSWORD, "new_password": "short"},
        headers=csrf_headers(c),
    )
    assert resp.status_code == 422
