# SentinelTrace

A log analysis and threat detection platform. It ingests web-server and authentication logs, normalizes them, runs deterministic detection rules, and presents evidence-backed alerts for investigation.

> **Status:** Phase 1 (scaffold) complete, CI green. See [Development progress](#development-progress). This is a local MVP under active development, not a production security product.

**Stack:** FastAPI · SQLAlchemy · Alembic · PostgreSQL 16 · React 19 · TypeScript · Vite · Tailwind CSS · Recharts · Pytest · Vitest · Playwright · Docker Compose

---

## Quick start (Docker Compose)

```bash
cp .env.example .env
# set ST_PG_PASSWORD in .env, e.g.:
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
docker compose up --build
```

- App: <http://localhost:8080>
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
uv run uvicorn app.main:app --reload --port 8000

# 3. Frontend (separate terminal). The Vite dev server proxies /api to :8000.
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

# End-to-end (needs the backend running on :8000 and Playwright's Chromium)
npx playwright install chromium
npm run test:e2e
```

CI (`.github/workflows/ci.yml`) runs four jobs on every push:
- backend tests
- frontend tests
- Playwright E2E
- a full `docker compose up` smoke test

## Project layout

```
backend/    FastAPI app (app/), tests, Alembic migrations (Phase 2+)
frontend/   React + Vite SPA, Vitest tests (src/**/*.test.tsx), Playwright specs (e2e/)
scripts/    dev-postgres.sh: Docker-free local database
docs/       spec, plan, per-phase reports
```

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
| `dev-postgres.sh`: binaries not found | Install PostgreSQL 16 (e.g. `brew install postgresql@16` or `apt install postgresql-16`) |

## Development progress

| Phase | Scope | Status |
|---|---|---|
| 0 | Environment inspection and plan ([report](docs/PHASE0_PLAN.md)) | ✅ |
| 1 | Scaffold, health checks, Compose, CI ([report](docs/reports/phase-1.md)) | ✅ |
| 2 | Auth, models, migrations, RBAC | ⏳ next |
| 3 | Parsers, ingestion, normalization | |
| 4 | Detection engine, alert grouping | |
| 5 | Dashboard, event explorer, alert UI | |
| 6 | Incidents, rules UI, audit, exports | |
| 7 | Test hardening, security checks | |
| 8 | Full system acceptance | |

Project requirements: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
