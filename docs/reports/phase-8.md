# Phase 8 Report: Full System Acceptance

Date: 2026-10-16 · Result: **All final delivery criteria met** (spec section 14), verified on a clean checkout. CI confirmation is pending on push.

## How acceptance was run

1. **Clean checkout.** A fresh `git clone` of the GitHub repository (commit `19c782e`) into an empty folder, with no files carried over from development.
2. **README setup, word for word.** Every command in "Local development (without Docker)" was run as written:
   - database script
   - backend `.env`, `uv sync`, `alembic upgrade head`, `create-admin`
   - API with `--reload`, worker
   - `npm install`, `npm run dev`

   It worked without changes. The Docker Compose path cannot be run here (Docker Hub is not reachable from this machine). It is exercised by the CI `compose` job on every push: build, migrations, login through nginx, an upload processed by the worker container, and detection on the synthetic dataset.
3. **README test commands, word for word,** in the clean clone: backend tests with coverage, lint and format, frontend tests with coverage, lint, build, both dependency audits, and the Playwright suite.
4. **Automated acceptance check.** The new `scripts/acceptance.py` was run against the fresh instance; its output is below.
5. **Raw SQL comparison.** The dashboard was compared directly with SQL counts on the same database.
6. **Migration round trip.** All six migrations were taken down to an empty schema and back up, and `alembic check` reported no drift.

## Acceptance check output (clean instance)

```
1-2. Setup: services are up
  [PASS] API and database: health=ok version=0.1.0 database=ok
  [PASS] Frontend served: CSP: missing…

3. Authentication and permissions
  [PASS] Admin login: signed in as admin
  [PASS] Role-based access: anonymous GET /api/alerts: ok, viewer GET /api/alerts: ok, viewer GET /api/users: ok, viewer POST /api/sources: ok, viewer GET /api/alerts/export: ok, analyst GET /api/audit: ok, analyst GET /api/admin/system: ok
  [PASS] Logout invalidates the session: GET /api/auth/me after logout returned 401

4. Import and parse the synthetic attack dataset
  [PASS] All files parsed: web_access.log: completed, 6331 parsed, 0 rejected; auth.log: completed, 81 parsed, 0 rejected; app_events.jsonl: completed, 208 parsed, 0 rejected
  [PASS] Duplicate import refused: re-upload returned 409

5. Known suspicious patterns raise the expected evidence-backed alerts
  [PASS] Alerts match ground truth: 13/13 expected alerts, missing=[], unexpected=[]
  [PASS] Every alert has evidence and an explanation: 13/13 alerts with original log lines, reason, confidence explanation and next steps
  [PASS] Alerts are worded as indicators: every reason states it is an indicator / does not confirm compromise

6. Normal traffic does not trigger every rule
  [PASS] Benign-only dataset raises no alerts: 23632 benign events imported, 0 new alerts
  [PASS] Benign entities in the attack dataset not alerted: 44 benign IPs, 0 alerted; rules fired: 10

7. Alerts can be investigated, updated and persisted
  [PASS] Changes persist (read back in a new session): alert #6 investigating, owner acc.analyst.0a5622, 1 note(s), incident #1 with 4 timeline entries
  [PASS] Changes are in the audit log: actions: ['alert.assign', 'alert.note', 'alert.status_change']

8. Dashboard figures match independent queries
  [PASS] Total events = sum of per-source counts (and explorer count): dashboard 30252, sources 30252, explorer 10000+ (capped)
  [PASS] Log sources tile = sources list: dashboard 6, list 6
  [PASS] Alerts by severity = alert queue: dashboard {'low': 1, 'medium': 8, 'high': 4, 'critical': 0}, queue {'low': 1, 'medium': 8, 'high': 4, 'critical': 0}, total 13 vs 13
  [PASS] Open alerts = alert queue: dashboard 13, queue 13

9. Exports contain the correct records
  [PASS] Alert CSV = alert queue: 13 rows vs 13 alerts
  [PASS] Event export = explorer filter: 600 exported vs 600 in the explorer for 203.0.113.40
  [PASS] Incident report content: Markdown report has alert #6 and the incident note (2420 chars)

21/21 checks passed.
```

The "Frontend served" check shows `CSP: missing` because the Vite **development** server does not send the policy. The preview server and nginx do, and the E2E suite runs under it.

**Dashboard vs raw SQL** on the same database:

```
SQL: events=30252 alerts=13 open=13 high_open=4 sources=6 files=6 by_sev=high=4,low=1,medium=8
API: events=30252 alerts=13 open=13 high_open=4 sources=6 files=6 by_sev=high=4,low=1,medium=8
```

## Defects found and fixed in this phase

| # | Found by | Problem | Fix |
|---|---|---|---|
| 1 | Spec review | Required screen 12, "Application settings and health status", had health but no settings view | New **Settings & status** screen: effective configuration grouped with the `ST_*` variable for each value (secrets never shown), plus database size and row counts, import and detection queue, upload storage and free disk. Admin-only API `GET /api/admin/system`, with tests on both sides |
| 2 | Screenshot run | The note box cleared itself after a save finished, which could wipe text typed while the save was in flight | Only the text that was sent is cleared. Regression test confirmed to fail on the old code |
| 3 | Clean-checkout run | `dev-postgres.sh` failed with a bare "Permission denied" when run as root from a private folder (Linux) | Clear explanation of the cause, plus an `ST_PG_DATA` override |
| 4 | Setup on a Mac (Phase 5) | The Quick start told users to generate a password and paste it into `.env`, which was easy to miss | Quick start now writes `.env` with one command, includes the 12-character admin password rule, and walks through loading the demo data |
| 5 | Clean-checkout run | README did not mention `ST_ADMIN_PASSWORD` (non-interactive admin creation) or the data-folder and port options | Documented |

**Also verified while running:** a database interruption during the acceptance setup made the worker log one failed iteration, retry after 2 s, and continue. This is the Phase 7 back-off working against a real outage, not just in a unit test.

## New in this phase
- **`scripts/acceptance.py`:** a standard-library-only end-to-end acceptance check (21 checks mapped to spec section 14). It runs against Docker or local installs and refuses to run on a non-fresh database so the ground-truth comparison stays valid.
- **`docs/ACCEPTANCE.md`:** every spec requirement (sections 3-14) mapped to where it is implemented and the tests or evidence for it.
- **`docs/deployment.md`:** HTTPS, cookies, forwarded IPs, secrets, least-privilege database role, backups and restore, upgrades and rollback, monitoring, key settings, and known limitations.
- **README:**
  - project overview, feature list, architecture diagram and screenshots (`docs/screenshots/`, synthetic data only)
  - a rewritten Quick start
  - acceptance-check and deployment sections

## Final test results

| Check | Result |
|---|---|
| Backend tests (`uv run pytest --cov=app`, PostgreSQL 16) | **379 passed**, line coverage **96.3%** (CI minimum 92%) |
| Frontend tests (Vitest) | **87 passed**; lines 86.9%, statements 83.6%, branches 75.4% (CI thresholds enforced) |
| End-to-end (Playwright, real API + worker) | **7 passed**, repeated twice against the same database (14/14); also 7/7 in the clean clone |
| Acceptance check on a fresh instance | **21/21 passed** |
| Backend lint / format / `alembic check` | passed / passed / no drift |
| Frontend lint / typecheck / build | clean / clean / built |
| `pip-audit` / `npm audit` (runtime dependencies) | no known vulnerabilities / 0 vulnerabilities |
| Migrations | 0001-0006 down to base and back up |

## Totals across the project

- **Detection:** 10 rules. On the synthetic attack dataset (6,620 lines) they produce exactly the 13 expected alerts, with every evidence line labelled malicious. On the 24-hour benign dataset (23,632 lines) they produce 0 alerts.
- **App:** 12 screens; a REST API with OpenAPI docs, every endpoint behind authentication and CSRF (enforced by a test that enumerates the schema).
- **Data:** 6 database migrations.

## Remaining limitations (also in docs/deployment.md)
- **Status:** a local MVP, not load-tested or penetration-tested. Detection thresholds are tuned on synthetic data only.
- **Not built:** single sign-on, MFA, email password reset, live log streaming, PDF reports. Markdown and JSON reports are provided.
- **Settings are read-only in the app:** operational settings come from environment variables and are shown read-only. Detection thresholds and retention are editable in the app.
- **Database role:** Compose connects as the database owner. A least-privilege application role is documented but not configured by default.
- **Compose not run locally:** the Docker Compose setup is verified in CI; it could not be run on this machine.
- **Known race:** a retention purge running at the same time as a detection re-scan of the same old time range can make that detection run fail. It is recorded as failed and can be re-run.
