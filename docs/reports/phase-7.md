# Phase 7 Report: Retention, Failure Handling, Security Checks and Test Hardening

Date: 2026-10-15 · Result: **Gate passed locally**. CI confirmation is pending on push.

## What was built

### Data retention (spec section 8)
- **Service** (`app/services/retention.py`) with explicit eligibility rules:
  - **alerts:** resolved/false positive, last seen before the cutoff, not in an incident, no notes
  - **events:** before the cutoff, not evidence for a kept alert, not referenced by a note
  - **rejected-line records:** of imports finished before the cutoff
  - **stored uploads:** uploaded before the cutoff, all imports finished, content not shared with an upload that is not eligible
- **Never removed:** incidents, notes, users, sources, file and job metadata, rule history, the audit log.
- **Safety:**
  - preview first
  - minimum period (`ST_RETENTION_MIN_DAYS`, default 7)
  - batched deletes, each in its own transaction, so it is safe to interrupt and re-run
  - one audit entry with the totals
  - the database still rejects deletes of the audit log and of notes, so even a bug in this code could not remove them
- **Three ways to run it:**
  - CLI: `python -m app.cli purge --older-than-days N [--execute]`; preview is the default.
  - Admin API and a **Data retention** page: preview, then type `PURGE` to confirm.
  - Optional daily automatic purge by the worker (`ST_RETENTION_AUTO_DAYS`), tracked in `app_config`.
- **Migration `0006`:**
  - `imported_files.content_purged_at` marks uploads whose bytes were removed (the metadata stays).
  - A partial index on `investigation_notes.event_id` keeps the "is this event referenced" check fast.
- **Retrying a failed job:**
  - Now refused (409, with the reason) if retention removed its upload.
  - Also refused if notes reference its events. Before, that retry would have hit a database error.

### Failure handling
- **Worker:**
  - A failed iteration (for example, the database is unreachable) is logged and retried with exponential backoff (2 s, 4 s, 8 s … capped at 60 s) instead of crashing.
  - The loop resets after the first success.
- **API, database outage:** returns `503` with `Retry-After: 5` and a generic message. The connection error goes to the server log, never to the client.
- **API, upload with a full disk:** `ENOSPC` or `EDQUOT` returns `507` with guidance, and the staged file is discarded. Any other storage error stays a generic `500` with no path or message leaked.
- **Settings:** an empty value (`ST_X=` in `.env` or Compose) now means "use the default" instead of failing startup.

### Security checks
- **Content-Security-Policy:**
  - Tightened to no inline styles: `style-src 'self'`; scripts were already same-origin only.
  - The same header is now sent by `vite preview`, so the E2E run uses the production policy.
  - A new E2E test opens every screen and fails on any CSP violation or page error.
  - API responses send `default-src 'none'; frame-ancestors 'none'`. The interactive docs page is exempt.
- **Export and report limit:**
  - At most 10 per user per minute (`ST_EXPORT_RATE_PER_MINUTE`); over the limit returns `429` with `Retry-After`.
  - Counted from the audit log, so the limit holds across processes and restarts.
- **Dependency audits:**
  - New CI job running `pip-audit` (pinned 2.10.1) on the locked runtime dependencies with hash checking, and `npm audit --omit=dev --audit-level=high`.
  - Both report **no known vulnerabilities** today.
- **Security regression tests:**
  - injection probes on ten filters (treated as literal text or rejected with 422, never executed)
  - validation errors that do not echo input
  - session cookie flags
  - security headers on errors

### Test data and coverage
- **Benign-only dataset** (`datasets/synthetic/benign/`, deterministic generator, 23,632 lines):
  - 24 hours of legitimate traffic: browsing, a crawler, an uptime monitor, REST clients, a busy office network, password typos, a broken-link page, a password-manager sync, tricky search terms
  - **The default rules raise zero alerts on it.**
  - A second test lowers two thresholds slightly and checks that exactly the near-miss entities then alert (4 typos in 5 minutes; about 280 requests/minute). This shows the zero result is close to the limits, not trivially far from them.
- **Coverage** is measured and enforced in CI:
  - backend **96%** of lines (CI fails below 92%)
  - frontend **87% lines / 83% statements / 75% branches** (CI thresholds slightly below)

### End-to-end test stability
- **Wrong-credentials test:**
  - It now uses an unknown username; the message is identical, so no account information leaks.
  - Repeated runs no longer trip the login rate limit for the admin account; before this, five quick runs locked admin out for 15 minutes.
- **Investigation test:** it now finds its alert in "Recent high-severity alerts" instead of the top-10 IP list, which depends on what else is in the database.

## Test results (all run locally)

| Check | Result |
|---|---|
| Backend tests (`uv run pytest --cov=app`, PostgreSQL 16) | **378 passed** (38 new), coverage **96.3%** |
| — retention (eligibility, shared uploads, idempotency, batches, limits, API, CLI, auto-run, retry guards) | 13 |
| — resilience (worker backoff and cap, `--once`, 503, 507, generic 500) | 7 |
| — security (headers, export limits, 10 injection probes, input echo, cookies) | 15 |
| — benign dataset (clean import, zero alerts, near-misses) | 3 |
| Backend lint / format / `alembic check` / migration `0006` down + up | passed / passed / no drift / passed |
| Frontend tests (Vitest) | **83 passed** (2 new), coverage 86.5% lines |
| Frontend lint / typecheck / build | clean / clean / built |
| End-to-end (Playwright, real API + worker) | **7 passed**, repeated 3× in one run against the same database (21/21) |
| `pip-audit` / `npm audit` (runtime dependencies) | no known vulnerabilities / 0 vulnerabilities |

**Mutation checks:**
- Removing the "in an incident" protection from alert eligibility failed 7 retention tests.
- Removing the shared-upload guard failed 2.
- The code was restored in both cases.

## Outstanding issues / limitations
- **Retention and running detection:** if detection re-scans an old time range while a purge is deleting the same events, that detection run can fail on a foreign key. It is recorded as failed and can be re-run. Avoid running both at once over the same range.
- **Kept alerts can lose events:** an alert's `event_count` stays as recorded, but its events beyond the evidence cap (500) are not protected by retention.
- **The audit log grows forever** by design. Archive it externally if size becomes a concern.
- **Coverage gaps:** the custom nginx log-format parser (78%) and parts of the worker's signal handling are the least-covered backend areas.
- **Docker Compose** is verified in CI; it was not run locally.

## Next: Phase 8
- Run the whole system from a clean checkout with the documented steps.
- Walk through the acceptance criteria in the spec one by one, with evidence.
- Fix any defects found, and write the final installation, deployment-hardening and acceptance report.
