# SentinelTrace

A log analysis and threat detection platform. It ingests web-server and authentication logs, normalizes them, runs deterministic detection rules, and presents evidence-backed alerts for investigation.

> **Status:** Phase 4 (detection engine) complete. See [Development progress](#development-progress). This is a local MVP under active development, not a production security product.

**Stack:** FastAPI · SQLAlchemy · Alembic · PostgreSQL 16 · React 19 · TypeScript · Vite · Tailwind CSS · Recharts · Pytest · Vitest · Playwright · Docker Compose

---

## Quick start (Docker Compose)

```bash
cp .env.example .env
# set ST_PG_PASSWORD in .env, e.g.:
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
docker compose up --build
```

Database migrations run automatically when the backend starts. Create the first admin account:

```bash
docker compose exec backend python -m app.cli create-admin --username admin
```

- App: <http://localhost:8080> (sign in with the admin account)
- API docs (OpenAPI): <http://localhost:8080/api/docs>

## Local development (without Docker)

Requirements: Python 3.13, [uv](https://docs.astral.sh/uv/), Node 22, PostgreSQL 16 server binaries.

```bash
# 1. Database: a local cluster in ./.pgdata on 127.0.0.1:5432
export ST_PG_PASSWORD='choose-a-local-password'
scripts/dev-postgres.sh start          # creates the sentineltrace and sentineltrace_test DBs

# 2. Backend
cd backend
cat > .env <<EOF
ST_DATABASE_URL=postgresql+psycopg://sentineltrace:${ST_PG_PASSWORD}@127.0.0.1:5432/sentineltrace
EOF
uv sync
uv run alembic upgrade head            # create/upgrade the schema
uv run python -m app.cli create-admin --username admin   # first time only; prompts for a password
uv run uvicorn app.main:app --reload --port 8000

# 3. Ingestion worker (separate terminal): processes uploaded log files
cd backend && uv run python -m app.worker

# 4. Frontend (separate terminal). The Vite dev server proxies /api to :8000.
cd frontend
npm install
npm run dev                            # http://localhost:5173
```

## Running tests

```bash
# Backend: runs against a real PostgreSQL test database
cd backend
ST_DATABASE_URL=postgresql+psycopg://sentineltrace:${ST_PG_PASSWORD}@127.0.0.1:5432/sentineltrace_test \
  uv run pytest
uv run ruff check . && uv run ruff format --check .

# Frontend unit/component tests, lint, build
cd frontend
npm test && npm run lint && npm run build

# End-to-end (needs the backend running on :8000 with an admin account)
npx playwright install chromium        # or set PW_CHROMIUM_PATH to an existing Chromium
E2E_ADMIN_USER=admin E2E_ADMIN_PASSWORD='...' npm run test:e2e
```

The backend test suite **drops and rebuilds the schema** of the database in `ST_DATABASE_URL`, so it refuses to run unless the database name contains `test`.

CI (`.github/workflows/ci.yml`) runs four jobs on every push:
- backend tests
- frontend tests
- Playwright E2E
- a full `docker compose up` smoke test

## Project layout

```
backend/    FastAPI app (app/), parsers (app/ingestion/), detection (app/detection/), worker (app/worker.py), tests/, Alembic migrations (alembic/), CLI (app/cli.py)
datasets/   synthetic/: deterministic generator + ground truth for evaluating detection
frontend/   React + Vite SPA, Vitest tests (src/**/*.test.tsx), Playwright specs (e2e/)
scripts/    dev-postgres.sh: Docker-free local database
docs/       spec, plan, per-phase reports
```

## Importing logs

1. **Log sources** → add a source. Choose its format, or *Auto-detect*. Set its time zone, which is used for timestamps without an offset.
2. Upload a file to the source. Supported formats:
   - Apache combined
   - Nginx combined, common or custom `log_format`
   - JSON lines
   - Linux `auth.log`
3. **Ingestion jobs** shows live progress. Each job reports:
   - parsed, rejected and duplicate counts
   - every rejected line with its line number and reason, downloadable as CSV
   - a Retry button when the job failed

Details of each format, field mapping, limits and duplicate handling: [docs/log-formats.md](docs/log-formats.md).

## Detection

After each import, the worker runs 10 deterministic rules over the new events:
- authentication failures and brute force
- SQL injection, XSS and path traversal indicators
- request bursts
- repeated 401/403 responses
- 404 reconnaissance
- suspicious methods
- multi-stage correlation

Alerts are grouped per entity and hour, linked to their evidence events, and explained with a confidence level. Admins can tune thresholds through the API; every change is versioned and audited. Rules, logic and evaluation: [docs/detection-rules.md](docs/detection-rules.md).

```bash
# Regenerate the synthetic evaluation dataset (deterministic)
python3 datasets/synthetic/generate.py
# Evaluate detection against its ground truth (prints precision/recall)
cd backend && uv run pytest tests/test_synthetic_dataset.py -s
```

## Authentication and roles

| Role | Can do |
|---|---|
| **viewer** | Read dashboards, events, alerts, rules, incidents and reports |
| **analyst** | Everything a viewer can, plus triage alerts, manage incidents, import logs and export reports |
| **admin** | Everything, plus manage users, detection rules and settings, and read the audit log |

- **Sessions:** server-side, held in an `HttpOnly` cookie. Only a SHA-256 hash of the token is stored. Logout, password changes, role changes and deactivation revoke sessions immediately. Sessions expire after 60 idle minutes or 12 hours, both configurable.
- **CSRF:** every state-changing request needs an `X-CSRF-Token` header. It must match both the `st_csrf` cookie and the token bound to the session.
- **Passwords:** hashed with Argon2id, minimum 12 characters.
- **Login rate limiting:** 5 failed attempts per username or 20 per IP within 15 minutes returns `429` with `Retry-After`.
- **Audit log:** append-only. A database trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log`, and the API has no endpoint that writes or deletes entries.

## Security notes

- No secrets are committed. All credentials come from environment variables, and `.env` files are git-ignored.
- The browser only ever talks to one origin (Vite proxy in dev, nginx in Compose), so CORS is disabled by default.
- API errors never include stack traces or exception text. A request ID is returned for correlation.
- This is a **defensive** analysis tool for synthetic or authorized logs only.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `RuntimeError: ST_DATABASE_URL is not set` when running pytest | Export `ST_DATABASE_URL` pointing at the `sentineltrace_test` DB |
| `/api/ready` returns 503 | PostgreSQL isn't reachable. Run `scripts/dev-postgres.sh status`, check the URL and password |
| `ST_DATABASE_URL must use the postgresql+psycopg:// scheme` | Use the `postgresql+psycopg://` prefix, not `postgres://` |
| Status page says "API unreachable" | The backend isn't running on :8000, or `ST_API_URL` points elsewhere |
| No alerts after an import | Alerts appear after the job's detection run completes (`GET /api/detection/runs`). Check that rules are enabled (`GET /api/rules`) |
| Changed a threshold but old alerts remain | Alerts are never deleted automatically. Queue a rescan (`POST /api/detection/runs`) to apply new thresholds to past events |
| Uploaded job stays "Queued" | The worker isn't running. Start `uv run python -m app.worker` (Compose starts it automatically) |
| Job failed: "Could not detect the log format" | Set the source's format explicitly, or choose a format when uploading |
| Upload rejected with 415 | The file is compressed or binary. Decompress it first (`gunzip access.log.gz`) |
| auth.log times are off by hours | Set the source's time zone to the server's zone. Syslog timestamps carry no offset |
| Login always returns 429 | Too many failed attempts. Wait 15 minutes (`ST_LOGIN_WINDOW_SECONDS`), or clear `login_attempts` in a dev database |
| Logged out immediately after signing in over plain HTTP | `ST_COOKIE_SECURE=true` (or `ST_ENVIRONMENT=production`) needs HTTPS. Unset it for local HTTP |
| `Roles missing. Run 'alembic upgrade head' first.` | Run migrations before `create-admin` |
| `dev-postgres.sh`: binaries not found | Install PostgreSQL 16 (e.g. `brew install postgresql@16` or `apt install postgresql-16`) |

## Development progress

| Phase | Scope | Status |
|---|---|---|
| 0 | Environment inspection and plan ([report](docs/PHASE0_PLAN.md)) | ✅ |
| 1 | Scaffold, health checks, Compose, CI ([report](docs/reports/phase-1.md)) | ✅ |
| 2 | Auth, models, migrations, RBAC, audit ([report](docs/reports/phase-2.md)) | ✅ |
| 3 | Parsers, ingestion, normalization ([report](docs/reports/phase-3.md)) | ✅ |
| 4 | Detection engine, alert grouping ([report](docs/reports/phase-4.md)) | ✅ |
| 5 | Dashboard, event explorer, alert UI | ⏳ next |
| 6 | Incidents, rules UI, audit, exports | |
| 7 | Test hardening, security checks | |
| 8 | Full system acceptance | |

Project requirements: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
