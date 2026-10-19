# SentinelTrace

A log analysis and threat detection platform. It imports web-server, application and authentication logs, normalizes them into one event schema, runs deterministic detection rules, and presents evidence-backed alerts for investigation, incident handling and reporting.

> **Status:** all eight development phases complete ([acceptance report](docs/reports/phase-8.md)). This is a **local MVP for synthetic or authorized logs**, not a production security product. Detection quality is measured only on the bundled synthetic datasets.

**Stack:** FastAPI · SQLAlchemy · Alembic · PostgreSQL 16 · React 19 · TypeScript · Vite · Tailwind CSS · Recharts · Pytest · Vitest · Playwright · Docker Compose

![Security overview](docs/screenshots/02-dashboard.png)

## Features

- **Ingestion:**
  - Apache combined, Nginx (common, combined or a custom `log_format`), JSON lines and Linux `auth.log`, with format auto-detection
  - streaming parser with per-line rejection reasons, duplicate detection, upload limits, and safe, content-addressed file storage
- **Detection:**
  - 10 deterministic, versioned rules: authentication failures, brute force, SQL injection, XSS, path traversal, request bursts, 401/403 floods, 404 reconnaissance, suspicious methods, multi-stage correlation
  - alerts are grouped per entity and hour, linked to the original log lines, and explained with a confidence level and next steps
- **Investigation:**
  - a dashboard computed from the stored events and alerts, with drill-downs, a server-side event explorer, and an alert queue with owners and notes
  - incidents with a merged timeline, and Markdown/JSON incident reports
- **Reporting:** CSV/JSON exports of alerts, events and the audit log, with the same filters as the screens.
- **Administration:**
  - users and roles (viewer, analyst, admin)
  - an append-only audit log
  - detection rule tuning with version history
  - data retention with preview
  - a settings & health screen
- **Security:**
  - server-side sessions in HttpOnly cookies, CSRF protection, Argon2id passwords and login rate limiting
  - strict Content-Security-Policy, and authorization checks on every endpoint (enforced by a test)
- **Quality:**
  - 392 backend tests (96% line coverage), 94 frontend tests and 10 Playwright tests, including WCAG 2.1 AA accessibility checks
  - an evaluation against ground truth, with no missed alerts, no wrong alerts, and zero alerts on 24 hours of benign traffic
  - an [automated acceptance check](#acceptance-check)

| | |
|---|---|
| ![Alert investigation](docs/screenshots/04-alert-investigation.png) | ![Incident](docs/screenshots/05-incident.png) |
| Alert with evidence, explanation and triage | Incident with linked alerts and timeline |
| ![Alert queue](docs/screenshots/03-alert-queue.png) | ![Event explorer](docs/screenshots/06-event-explorer.png) |
| Alert queue with filters and bulk incident creation | Event explorer with raw log line and linked alerts |
| ![Detection rule](docs/screenshots/07-detection-rule.png) | ![Settings and status](docs/screenshots/08-settings-status.png) |
| Versioned rule settings | Settings & system health |

## Architecture

```mermaid
flowchart LR
  B[Browser<br/>React SPA] -->|same origin, cookie session + CSRF| N[nginx<br/>static files + /api proxy]
  N --> A[FastAPI API]
  A --> P[(PostgreSQL 16)]
  A -->|uploads| S[(Upload storage)]
  W[Worker<br/>ingestion + detection] --> P
  W --> S
  A -.queues jobs.-> P
  P -.claims jobs<br/>FOR UPDATE SKIP LOCKED.-> W
```

- **API (`backend/app`):** authentication, uploads, queries, triage, exports. Every endpoint checks permissions.
- **Worker (`python -m app.worker`):** claims queued imports and detection runs from the database (no separate message broker), parses files in batches with `COPY`, then runs detection on the imported time range. It retries with backoff if the database is unavailable.
- **Database:** normalized events with time and IP indexes, alerts with evidence links, incidents and notes, and an append-only audit log enforced by triggers. The schema is managed by Alembic migrations.
- **Frontend (`frontend/src`):** a React single-page app. All filtering and paging happen on the server.

## Quick start (Docker Compose)

Requirements: Docker Desktop (or Docker Engine with Compose), Git and Python 3.

```bash
git clone https://github.com/Vishal-S007/Sentinetrace.git && cd Sentinetrace
# Write a .env with a random database password (optional settings: see .env.example)
python3 -c "import secrets; print('ST_PG_PASSWORD=' + secrets.token_urlsafe(24))" > .env
docker compose up --build -d
```

Database migrations run automatically when the backend starts. Create the first admin account (the password needs at least 12 characters):

```bash
docker compose exec backend python -m app.cli create-admin --username admin
```

- App: <http://localhost:8080> (sign in with the admin account)
- API docs (OpenAPI): <http://localhost:8080/api/docs>
- Logs: `docker compose logs -f backend worker` · Stop: `docker compose down` (data is kept) · Reset everything: `docker compose down -v`

**Try it with the demo data:**
1. Under **Log sources**, create three sources:
   - `web` with format `apache_combined`
   - `auth` with format `auth_log`
   - `app` with format `json`
2. Upload `web_access.log`, `auth.log` and `app_events.jsonl` from `datasets/synthetic/` to the matching sources.
3. Open **Overview** → **All time**. The 13 expected alerts appear within seconds.

## Local development (without Docker)

Requirements: Python 3.13, [uv](https://docs.astral.sh/uv/), Node 22, PostgreSQL 16 server binaries.

```bash
# 1. Database: a local cluster in ./.pgdata on 127.0.0.1:5432
#    (ST_PG_PORT / ST_PG_DATA change the port / data folder)
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
#   (non-interactive: ST_ADMIN_PASSWORD='...' uv run python -m app.cli create-admin --username admin)
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
  uv run pytest --cov=app                # with a coverage report
uv run ruff check . && uv run ruff format --check .

# Frontend unit/component tests (with coverage), lint, build
cd frontend
npm run test:coverage && npm run lint && npm run build

# Dependency audits (runtime dependencies)
cd backend && uv export --frozen --no-dev --no-emit-project > /tmp/req.txt \
  && uvx pip-audit -r /tmp/req.txt --disable-pip --require-hashes
cd frontend && npm audit --omit=dev --audit-level=high

# End-to-end (needs the backend running on :8000 with an admin account)
npx playwright install chromium        # or set PW_CHROMIUM_PATH to an existing Chromium
E2E_ADMIN_USER=admin E2E_ADMIN_PASSWORD='...' npm run test:e2e
```

The backend test suite **drops and rebuilds the schema** of the database in `ST_DATABASE_URL`, so it refuses to run unless the database name contains `test`.

CI (`.github/workflows/ci.yml`) runs five jobs on every push:
- backend tests with coverage (fails below 92%)
- frontend tests with coverage thresholds, lint and build
- dependency audits (`pip-audit`, `npm audit`)
- Playwright E2E, including a check that every screen works under the production Content-Security-Policy
- a full `docker compose up` smoke test

Two synthetic datasets are evaluated by the tests:
- `datasets/synthetic/` has attacks with ground truth; detection must match it exactly.
- `datasets/synthetic/benign/` is 24 hours of legitimate-only traffic, with near-misses just below the default thresholds; it must raise no alerts.

Both are regenerated byte-for-byte by their `generate.py`.

## Acceptance check

`scripts/acceptance.py` checks a running installation against the spec's final delivery criteria, through the API only:
- services up
- authentication and roles
- import and parsing
- alerts matching the ground truth
- no alerts on benign traffic
- investigation changes persisting and audited
- dashboard figures matching independent queries
- exports matching the screens

It needs only Python 3.11+ (no packages). Run it on a **fresh** installation, because it imports the synthetic datasets:

```bash
docker compose down -v && docker compose up -d --build     # fresh database
docker compose exec backend python -m app.cli create-admin --username admin
python3 scripts/acceptance.py --base-url http://localhost:8080 --username admin
# local development: --base-url http://localhost:5173
```

It prints PASS/FAIL with the evidence for each of the 21 checks and exits non-zero if any fail. It creates two temporary users, six log sources and one incident.

## Project layout

```
backend/    FastAPI app (app/), parsers (app/ingestion/), detection (app/detection/), worker (app/worker.py), tests/, Alembic migrations (alembic/), CLI (app/cli.py)
datasets/   synthetic/: deterministic generator + ground truth for evaluating detection
frontend/   React + Vite SPA, Vitest tests (src/**/*.test.tsx), Playwright specs (e2e/)
scripts/    dev-postgres.sh: Docker-free local database; acceptance.py: end-to-end acceptance check
docs/       spec, deployment guide, acceptance matrix, per-phase reports, screenshots
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

## Investigating alerts

After signing in, the **Security overview** shows activity for the selected range (24 hours to all time). Every number, bar and list item links to the matching filtered view.

- **Alert queue** (`/alerts`): filter by status, severity, rule, owner, source IP or title. Filters live in the URL, so a view can be bookmarked or shared. Analysts can tick several alerts and group them into an incident.
- **Alert page:** what was observed, why the confidence level was chosen, recommended steps, and the original log lines as evidence. Analysts and admins can set the owner and status, add notes (a note, an action taken, or an evidence reference to an event), and add the alert to an incident. A history panel shows every change, from the audit log.
- **Event explorer** (`/events`): search the raw log text and filter by time, IP or CIDR (`203.0.113.0/24`), event type, HTTP status (`404` or `4xx`), method, username, source, or whether detection flagged the event. Open any row to see every field and the alerts that reference it.
- **Incidents** (`/incidents`): related alerts grouped for investigation, with an owner, status (open → investigating → contained → resolved / closed), severity and summary. The timeline merges when each alert was observed, every change, and every note in time order. Notes cannot be edited or deleted (a database trigger enforces this); corrections are new notes.
- **Incident report:** download Markdown or JSON with the incident details, linked alerts, the first evidence lines of each, the timeline and the notes. Each download is audited.

## Exports

Analysts and admins can export what they are looking at, with the same filters, as CSV or JSON:

| Export | Where | Limit |
|---|---|---|
| Alerts | Alert queue → Export | 50,000 rows |
| Events | Event explorer → Export | 100,000 rows |
| Audit log | Audit log → Export (admin) | 100,000 rows |

- When a limit is reached the file is cut off and the response header `X-Export-Truncated: true` says so; narrow the filters to get the rest.
- CSV cells that begin with `=`, `+`, `-`, `@`, tab or carriage return get a leading `'` so spreadsheet apps show them as text instead of running them as formulas. JSON keeps the original values.
- Every export is recorded in the audit log with its filters and row count.
- Each user can run at most 10 exports or incident reports per minute (`ST_EXPORT_RATE_PER_MINUTE`).

## Data retention

Old data can be removed safely with a preview first. What is eligible:

| Data | Removed when |
|---|---|
| Alerts | Resolved or false positive, last seen before the cutoff, **not** in an incident, **no** notes |
| Events | Before the cutoff, **not** evidence for a kept alert, **not** referenced by a note |
| Rejected-line records | Their import finished before the cutoff |
| Stored uploads | Uploaded before the cutoff, imports finished, content not shared with a newer upload (the file's metadata is kept) |

**Never removed:** open alerts, incidents, investigation notes, users, sources, rule history and the audit log (append-only).

```bash
# Preview, then delete (Docker Compose)
docker compose exec backend python -m app.cli purge --older-than-days 90
docker compose exec backend python -m app.cli purge --older-than-days 90 --execute
```

- Admins can do the same under **Data retention** in the app; it shows the preview and asks you to type `PURGE`.
- Set `ST_RETENTION_AUTO_DAYS=90` to let the worker purge automatically once a day.
- Periods shorter than `ST_RETENTION_MIN_DAYS` (default 7) are refused.
- Every purge is recorded in the audit log with what it removed.
- Deletes run in batches, so a large purge does not lock the tables, and an interrupted purge can simply be run again.

## Detection rules

**Detection rules** (`/rules`) lists every rule with its severity, state, version and open alerts. Admins can enable or disable a rule, change its severity and thresholds, and add a change note. Each save creates a new version, kept in the version history with what changed and who changed it. Changes apply to new imports; **Re-run detection** applies them to events already imported.

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
- **Audit log:** append-only. A database trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log`, and the API has no endpoint that writes or deletes entries. Admins can filter it by action, actor, or target (for example one alert or incident) and export it.
- **Investigation notes:** append-only in the same way (a trigger rejects `UPDATE` and `DELETE`).

## Deployment

[docs/deployment.md](docs/deployment.md) covers running SentinelTrace beyond a laptop: HTTPS, secrets, database roles and backups, upgrades, retention, monitoring and the limits of this MVP.

## Security notes

- No secrets are committed. All credentials come from environment variables, and `.env` files are git-ignored.
- The browser only ever talks to one origin (Vite proxy in dev, nginx in Compose), so CORS is disabled by default.
- **Content-Security-Policy:** the app allows scripts, styles and connections only from its own origin (no inline scripts or styles, no third parties, no framing). API responses send `default-src 'none'`.
- **Failure handling:** a database outage returns `503` with `Retry-After`; a full disk on upload returns `507`; neither exposes internal details.
- API errors never include stack traces or exception text. A request ID is returned for correlation.
- This is a **defensive** analysis tool for synthetic or authorized logs only.

## Privacy, legal pages and accessibility

- **Legal pages:** `/legal/privacy`, `/legal/terms` and `/legal/cookies` are public and linked from the sign-in page and the sidebar. Retention periods and cookie details are filled in from the running configuration. Set the operator's details first:
  ```bash
  ST_OPERATOR_NAME="Example Security Team"
  ST_OPERATOR_CONTACT=privacy@example.com
  ST_OPERATOR_ADDRESS="1 Example Road, Example City"
  ```
- **Cookies:** only two strictly necessary cookies (session and CSRF). There is no tracking, analytics or third-party content, so the sign-in page shows a notice rather than a consent banner.
- **Data minimisation:** the worker deletes login attempts after 30 days and ended sessions after 7 days (`ST_LOGIN_ATTEMPT_RETENTION_DAYS`, `ST_SESSION_RETENTION_DAYS`).
- **Deletion requests:** users choose *Request deletion of my data* on **My account**. Admins see the request on **Users & roles** and use *Erase data*, which anonymizes and disables the account and deletes its sessions and sign-in records. The append-only audit log is kept.
- **Accessibility:** WCAG 2.1 AA checks with axe-core on every screen, a keyboard-only test, a skip link, visible focus rings and table alternatives for charts (`frontend/e2e/accessibility.spec.ts`).
- **Third-party licences:** [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The full 20-point review is in [docs/COMPLIANCE.md](docs/COMPLIANCE.md). The legal texts are a starting point; have them reviewed for your jurisdiction.

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
| Overview shows zeros after importing older logs | The range is relative to now; choose **All time** (the page offers it when older data exists) |
| Changed a rule but old alerts did not change | Rule changes apply to new imports. Use **Detection rules → Re-run detection** to re-evaluate existing events |
| Export stops at a round number | It hit the export limit (see [Exports](#exports)). Narrow the filters |
| Upload fails with 507 | The server's disk is full. Free space, e.g. with a [retention purge](#data-retention) that removes old stored uploads |
| Requests fail with 503 "database is temporarily unavailable" | PostgreSQL is down or unreachable. The worker keeps retrying with backoff and resumes when it is back |
| Export returns 429 | More than 10 exports in a minute. Wait a minute |
| Retry of a failed job returns 409 | Its upload was removed by retention (upload the file again), or notes reference its events |
| Owner list is empty when assigning | Only active analysts and admins can own alerts and incidents. Create one under **Users & roles** |

## Development progress

| Phase | Scope | Status |
|---|---|---|
| 0 | Environment inspection and plan ([report](docs/PHASE0_PLAN.md)) | ✅ |
| 1 | Scaffold, health checks, Compose, CI ([report](docs/reports/phase-1.md)) | ✅ |
| 2 | Auth, models, migrations, RBAC, audit ([report](docs/reports/phase-2.md)) | ✅ |
| 3 | Parsers, ingestion, normalization ([report](docs/reports/phase-3.md)) | ✅ |
| 4 | Detection engine, alert grouping ([report](docs/reports/phase-4.md)) | ✅ |
| 5 | Dashboard, event explorer, alert UI ([report](docs/reports/phase-5.md)) | ✅ |
| 6 | Incidents, rules UI, audit, exports ([report](docs/reports/phase-6.md)) | ✅ |
| 7 | Test hardening, security checks, retention ([report](docs/reports/phase-7.md)) | ✅ |
| 8 | Full system acceptance ([report](docs/reports/phase-8.md)) | ✅ |

Project requirements: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
