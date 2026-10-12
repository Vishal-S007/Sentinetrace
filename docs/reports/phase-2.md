# Phase 2 Report: Authentication, Roles, Migrations, Audit

Date: 2026-10-12 · Result: **Gate passed locally**, including Playwright E2E in a real Chromium. CI confirmation is pending on push.

## What was built

### Database (Alembic migration `0001`)
- **Tables:** `roles`, `users`, `sessions`, `login_attempts`, `audit_log`, `app_config`. All have foreign keys and indexes.
- **Usernames:** unique case-insensitively, enforced by a unique index on `lower(username)`.
- **Append-only audit log:** a PL/pgSQL trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log`.
- **Roles** `admin`, `analyst` and `viewer` are seeded by the migration.
- **Never deleted:** users are only deactivated, so audit actor references always stay valid.

### Authentication (`/api/auth/*`)
- **Login:**
  - Argon2id password verification.
  - The same 401 message for a wrong password, an unknown user or a disabled user.
  - Constant-work verification, so response timing doesn't reveal which usernames exist.
  - JSON content type required.
- **Sessions:**
  - The token is 256 bits of randomness in an `HttpOnly; SameSite=Lax` cookie. `Secure` is on in production or with `ST_COOKIE_SECURE=true`.
  - Only the SHA-256 of the token is stored.
  - 60-minute idle and 12-hour absolute expiry.
- **CSRF:** a per-session token. Unsafe methods need the `X-CSRF-Token` header to match the `st_csrf` cookie and the hash bound to the session.
- **Login rate limiting:** a sliding window held in PostgreSQL. 5 failures per username or 20 per IP in 15 minutes returns `429` with `Retry-After`. All limits are configurable.
- **Logout** revokes the session server-side.
- **Password change** revokes all of the user's other sessions.

### Authorization
- **Permissions:** 13 permissions defined in code (`app/core/permissions.py`), with the hierarchy viewer ⊂ analyst ⊂ admin. Unknown roles get nothing (fail closed).
- **Enforcement:** a `require(Permission...)` dependency on every protected endpoint.

### Administration
- **Users:**
  - `GET/POST /api/users`, `PATCH /api/users/{id}` (role, active, email, password reset), `GET /api/roles`.
  - Role changes, deactivation and password resets revoke the target's sessions.
  - Admins cannot deactivate or demote themselves, which prevents lockout.
- **Audit:** `GET /api/audit` is read-only, with keyset pagination and filters by action, actor and time. There is no write or delete endpoint.
- **CLI:** `python -m app.cli create-admin --username NAME` prompts for the password, or reads `ST_ADMIN_PASSWORD`.

**Audited actions:** login success, failure and rate-limited; logout; password change; user create; user update. Entries never contain passwords.

### Frontend
- **Login page:** loading, invalid-credential, rate-limit and session-expired states.
- **Auth context:** a global 401 handler returns the user to login with a notice.
- **Route guards** (`RequireAuth`, `RequirePermission`). Navigation hides links the role cannot use, and the server enforces the same rules independently.
- **Users & roles:**
  - create user, with server validation errors shown per field
  - change role
  - enable or disable
  - a role-permission matrix
  - your own row is locked
- **Audit log:** filters, "Load older entries" pagination, and empty and error states.
- **My account:** profile, permissions, and password change.
- **Sign out.**

### Infrastructure
- The backend container runs `alembic upgrade head` at startup.
- Compose passes `FORWARDED_ALLOW_IPS` so per-IP rate limiting sees real client IPs behind nginx.
- **CI:**
  - The `e2e` job migrates, seeds an admin and runs the login E2E.
  - The `compose` job creates an admin inside the container and logs in through nginx.

## Commands executed and results

| Check | Command | Result |
|---|---|---|
| Backend tests (real PostgreSQL 16) | `uv run pytest -q` | **64 passed** |
| Backend lint/format | `ruff check .` / `ruff format --check .` | passed |
| Model ↔ migration drift | `alembic check` + `test_models_match_migrations` | no drift |
| Migration round trip | upgrade → downgrade → upgrade on a fresh scratch DB | passed |
| Frontend tests | `npx vitest run` | **24 passed** (5 files) |
| Frontend lint / build | `npm run lint` / `npm run build` | 0 warnings / built |
| **E2E (Playwright, Chromium)** | `npx playwright test` against the live backend and PostgreSQL | **3 passed** |
| Compose file | `docker compose config --quiet` | valid |
| Live API check via frontend proxy | curl: anon `/me`, bad login, login, create user without/with CSRF, audit, logout | 401, 401, 200, **403**, 201, entries present, 204 |

### Key security tests (backend)
- **Coverage tests.** These enumerate every operation in the OpenAPI schema:
  - every non-public operation returns 401 without a session
  - every state-changing operation returns 403 without CSRF
  - **Mutation-checked:** a temporary unprotected route was added and the test correctly failed. The route was then removed.
- **Rate limiting:**
  - the 6th failed login returns 429 with `Retry-After`, and even the correct password is refused while limited
  - the per-IP limit works across usernames, and other IPs are unaffected
  - attempts outside the window don't count
- **Sessions:**
  - logout invalidates the session server-side (replaying the old cookie gives 401)
  - forged cookie, absolute expiry, idle timeout and deactivated user each give 401
- **CSRF:**
  - a missing header, a mismatched header, and a token taken from another user's session are all rejected
- **Validation:**
  - a `text/plain` login is rejected
  - validation errors don't echo input
  - failed-login audit entries don't contain the password
- **Users:**
  - viewers and analysts get 403 on users, roles and audit, and cannot create users
  - duplicate usernames are caught case-insensitively
  - username and password validation (including `../etc/passwd`)
  - unknown fields give 422
- **Audit log:**
  - `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log` are rejected by the database
  - keyset pagination has no gaps or duplicates
  - `limit` is capped
  - the API is read-only (405)

### E2E scenario (real browser, real backend and database)
1. An anonymous visit to `/status` redirects to `/login`.
2. A wrong password shows a generic error.
3. The admin signs in and sees live health. They create a viewer, see the creation in the audit log, then the viewer signs in in a separate browser context. The viewer has no admin navigation, `/admin/users` shows "Access denied", and the API returns **403**. The admin disables the viewer, and the viewer's session ends immediately. The admin signs out, protected pages redirect to login, and `/api/auth/me` returns **401**.

## Note on local E2E runs
Phase 1 relied on CI for the browser tests. This phase also ran them locally, using the pre-installed Chromium via the new optional `PW_CHROMIUM_PATH` setting. Docker image pulls are still unavailable locally, so `docker compose up` is verified in CI only.

## Outstanding issues / limitations
- **Rate-limit race:** the check and the attempt insert are not serialized. Concurrent bursts could exceed the limit by a few attempts before it applies. This is acceptable for an MVP and documented here.
- **Audit-log superuser caveat:** a PostgreSQL superuser could still disable the trigger. The app's database role should not be a superuser in production. Deployment hardening is documented in Phase 8.
- **Expired session rows:** these are not purged automatically yet. Retention and purge are Phase 6 and 7 scope.

## Next: Phase 3
Parsers for Apache combined, Nginx (common and custom), JSON and an auth-log format; format detection; upload validation (size, type, encoding, safe storage by hash); ingestion jobs with parsed, rejected and duplicate counts and line-level errors; normalized event persistence.
