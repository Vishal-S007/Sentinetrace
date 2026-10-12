"""Login, logout, current user and password change."""

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.deps import CSRF_COOKIE, SESSION_COOKIE, AppSettings, Auth, DbSession
from app.core.config import Settings
from app.core.permissions import permissions_for
from app.core.security import hash_password, verify_password
from app.schemas.auth import LoginRequest, MeOut, PasswordChangeRequest, UserOut
from app.services import audit
from app.services.auth import (
    authenticate,
    check_login_rate_limit,
    create_session,
    record_login_attempt,
    revoke_session,
    revoke_user_sessions,
    utcnow,
)

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_CREDENTIALS = "Invalid username or password"


def _set_auth_cookies(response: Response, settings: Settings, token: str, csrf: str) -> None:
    max_age = settings.session_absolute_hours * 3600
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    # Readable by the frontend so it can echo it in the X-CSRF-Token header.
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/",
    )


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=settings.secure_cookies)


def _me(auth_user, permissions) -> MeOut:
    return MeOut(user=UserOut.model_validate(auth_user), permissions=sorted(permissions))


@router.post(
    "/login",
    response_model=MeOut,
    responses={401: {"description": "Invalid credentials"}, 429: {"description": "Rate limited"}},
)
def login(
    body: LoginRequest, request: Request, response: Response, db: DbSession, settings: AppSettings
) -> MeOut:
    ip = audit.client_ip(request)
    limit = check_login_rate_limit(db, settings, body.username, ip)
    if limit.limited:
        audit.record(
            db, "auth.login.rate_limited", actor_username=body.username[:64], request=request
        )
        db.commit()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(limit.retry_after_seconds)},
        )

    user = authenticate(db, body.username, body.password)
    if user is None:
        record_login_attempt(db, body.username, ip, succeeded=False)
        audit.record(db, "auth.login.failure", actor_username=body.username[:64], request=request)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    record_login_attempt(db, body.username, ip, succeeded=True)
    issued = create_session(db, settings, user, ip, request.headers.get("user-agent"))
    user.last_login_at = utcnow()
    audit.record(
        db,
        "auth.login.success",
        actor=user,
        target_type="session",
        target_id=issued.session.id,
        request=request,
    )
    db.commit()

    _set_auth_cookies(response, settings, issued.token, issued.csrf_token)
    return _me(user, permissions_for(user.role.name))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(auth: Auth, request: Request, db: DbSession, settings: AppSettings) -> Response:
    revoke_session(db, auth.session)
    audit.record(
        db,
        "auth.logout",
        actor=auth.user,
        target_type="session",
        target_id=auth.session.id,
        request=request,
    )
    db.commit()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_auth_cookies(response, settings)
    return response


@router.get("/me", response_model=MeOut)
def me(auth: Auth) -> MeOut:
    return _me(auth.user, auth.permissions)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChangeRequest, auth: Auth, request: Request, db: DbSession
) -> Response:
    if not verify_password(auth.user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "New password must be different")
    auth.user.password_hash = hash_password(body.new_password)
    auth.user.password_changed_at = utcnow()
    revoked = revoke_user_sessions(db, auth.user.id, except_session_id=auth.session.id)
    audit.record(
        db,
        "auth.password_change",
        actor=auth.user,
        target_type="user",
        target_id=auth.user.id,
        request=request,
        details={"other_sessions_revoked": revoked},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
