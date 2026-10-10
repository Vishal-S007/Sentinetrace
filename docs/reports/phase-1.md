# Phase 1 Report: Scaffold

Date: 2026-10-10 · Result: **Gate passed. All checks verified, including in GitHub Actions.**

## What was built

- **Backend** (`backend/`):
  - FastAPI app factory
  - environment-based settings: database URL required, `postgresql+psycopg` enforced
  - SQLAlchemy engine/session with `pool_pre_ping`
  - `GET /api/health` (liveness, no DB access) and `GET /api/ready` (readiness: 200 when the DB answers, 503 when it doesn't)
  - security headers and a request ID on every response
  - CORS off unless origins are explicitly configured
  - a generic 500 handler that never leaks exception text or tracebacks
  - validation errors that don't echo input
  - OpenAPI at `/api/docs`
- **Frontend** (`frontend/`):
  - Vite + React 19 + TypeScript 6 + Tailwind 4 dark SOC theme
  - React Router shell
  - a typed API client
  - **System status** page wired to the real health/readiness endpoints, with loading, healthy, DB-unavailable and API-unreachable states and a working Re-check button
  - the navigation lists only implemented screens, so there are no dead links
- **Infra:**
  - `docker-compose.yml`: PostgreSQL 16 with healthcheck, backend (non-root, healthcheck) and nginx frontend (same-origin `/api` proxy, CSP and security headers)
  - Dockerfiles, `.env.example`
  - `scripts/dev-postgres.sh`: Docker-free local PostgreSQL
- **CI** (`.github/workflows/ci.yml`): backend lint and tests on a PostgreSQL service, frontend lint/test/build, Playwright E2E against a live backend, and a full `docker compose up` smoke test.

## Commands executed and results

| Check | Command | Result |
|---|---|---|
| Backend tests (real PostgreSQL 16) | `uv run pytest -q` | **9 passed** |
| Backend lint/format | `uv run ruff check .` / `ruff format --check .` | passed / 12 files formatted |
| Frontend unit tests | `npx vitest run` | **5 passed** |
| Frontend lint | `npm run lint` (oxlint) | 0 warnings |
| Frontend typecheck + build | `npm run build` | built (264 kB JS, 84 kB gzipped) |
| Compose file | `docker compose config --quiet` | valid |
| CI workflow | YAML parse | 4 jobs: backend, frontend, e2e, compose |
| Live: health | `curl :8000/api/health` | 200 `{"status":"ok"}` |
| Live: ready | `curl :8000/api/ready` | 200 `{"database":"ok"}` |
| Live: via frontend proxy | `curl :4173/api/ready` | 200 (same-origin proxy works) |
| Live: DB stopped | stop PostgreSQL, then `curl /api/ready` | **503** `{"database":"unavailable"}` |
| Live: DB restarted | start PostgreSQL, then `curl /api/ready` | 200 (recovers without restarting the API) |

**Backend tests cover:**
- health payload
- readiness against a real DB
- `check_database` returns False for an unreachable server
- readiness returns 503
- security headers
- 500 responses hide internals
- 404 responses are JSON
- no CORS by default
- OpenAPI exposes both endpoints

**Frontend tests cover:**
- loading → healthy
- 503 readiness treated as "Unavailable", not as an error
- network failure shows the error state
- a 500 shows the server message
- Re-check recovers from an error and issues new requests

## Verified in GitHub Actions (CI run #1, commit 6c73c94)

The local development environment had no access to browser downloads or Docker Hub, so these ran in CI instead:

| Job | Result | Duration |
|---|---|---|
| backend (ruff + pytest on PostgreSQL 16 service) | ✅ success | 25s |
| frontend (lint, Vitest 5/5, build) | ✅ success | 14s |
| e2e (Playwright, Chromium, live backend) | ✅ success | 1m 19s |
| compose (`docker compose up --build`, health through nginx) | ✅ success | 57s |

Overall run status: **Success** (1m 49s).

## Outstanding issues

- None blocking. Alembic is not initialized yet; that is Phase 2 scope.

## Next: Phase 2

Phase 2 covers authentication, database models, migrations and authorization:
- users and roles
- server-side sessions in HttpOnly cookies
- CSRF double-submit
- Argon2id password hashing
- login rate limiting
- RBAC dependencies
- an append-only audit table enforced by a DB trigger
- Alembic migrations tested up, down and up again
- an automated test that every protected route rejects unauthenticated access
