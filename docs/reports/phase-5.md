# Phase 5 Report: Dashboard, Event Explorer, Alert Queue and Investigation UI

Date: 2026-10-13 · Result: **Gate passed** locally and in CI (backend, frontend, end-to-end and Docker Compose jobs).

## What was built

### Backend
- **Migration `0004`:** enables `pg_trgm` and adds a GIN trigram index on `events.raw_line`, so free-text search over the original log line stays fast as the table grows. The index is also declared on the model, so `alembic check` reports no drift.
- **`GET /api/dashboard?range=24h|7d|30d|90d|all`** (viewer and up). Every figure is computed live from the database; nothing is cached or hard-coded.
  - totals: events in range, alerts active in range, open alerts, open high/critical alerts, log sources, imported files
  - alerts by severity and by status
  - events and alerts over time, zero-filled, bucketed by hour (≤ 7 days), day (≤ 180 days) or week
  - top 10 source IPs by alert count (with event count and highest severity), top rules, recent high/critical alerts, recent ingestion jobs
  - the first and last event time, so the UI can suggest "all time" when the chosen range is empty
  - "all" spans from the first to the last event, so historical imports render properly
- **`GET /api/events`** (event explorer):
  - filters: text search (`q`, case-insensitive, `%` `_` `\` treated literally), time range (time zone required), source IP **or CIDR**, event type, HTTP status code or class (`4xx`), method, username, source, flagged / not flagged by detection, alert severity, alert id
  - keyset pagination ordered by `(event_time desc, id desc)` with an opaque cursor, so paging is stable while new data arrives
  - optional match count, capped at 10,000 (`count_capped`) so counting never dominates the request
  - each event carries its alert count and highest alert severity
- **`GET /api/events/{id}`:** the full normalized event, its parser attributes, the file and line number it came from, the import job, and every alert that links it (with the matched indicator).
- **`PATCH /api/alerts/{id}`** (analyst and admin): change status with an optional note (≤ 1,000 characters). Each change writes an `alert.status_change` audit entry with from/to/note/rule. Setting the current status again is a no-op and is not audited. Re-running detection keeps the analyst's status.
- **`GET /api/alerts?q=`:** case-insensitive title search.

### Frontend
- **Security overview** (new landing page for anyone who can read events):
  - range selector stored in the URL
  - stat tiles that link to the matching filtered views
  - events-over-time and alerts-over-time charts; clicking a bar opens the explorer or alert queue for that time slice; each chart has a "view as table" toggle
  - severity and status breakdowns, top source IPs, top rules, recent high/critical alerts and recent imports, each a drill-down link
  - an empty-range notice that offers "Show all time" when older data exists
  - the charting library loads in a separate chunk, so other pages don't pay for it
- **Alert queue:** filters (status, severity, rule, source IP, title text, time window) kept in the URL so views can be shared and bookmarked; keyset "load older alerts".
- **Alert investigation page:**
  - what was observed, why this confidence level, recommended investigation steps
  - evidence: the original log lines with the matched indicator, paginated, and a link to the same events in the explorer
  - facts panel (time span, event count, rule window, source IP pivots, account, top endpoint), rule-specific details, and links to member alerts for correlation alerts
  - triage controls (shown only with `alerts:triage`) with an optional audit note
- **Event explorer:** URL-backed filter form, newer/older paging with a cursor stack, match count, and a detail panel with the raw line, every normalized field, parser attributes and linked alerts.
- **Untrusted content:** log lines, user agents and paths are always rendered as text, never as HTML. A test feeds an `<img onerror>` payload and asserts it shows literally.

### Chart colour
- Severity is ordinal, so it uses one red ramp from light (low) to dark (critical) instead of four unrelated hues. The palette passes the ordinal colour-vision and contrast checks against the dark surface. Single-series charts use one blue.
- Severity is never shown by colour alone: badges carry a label, the legend has fixed order with plain text, and every chart has a table view.

### Operations
- **Worker health check.** The worker touches a heartbeat file after each database poll, and `python -m app.worker --check-health` reports whether it is recent. Docker Compose uses this instead of a disabled health check. This fixes the CI Compose job, which had failed since Phase 3 because `docker compose up --wait` could not treat the worker as ready.
- **CI diagnostics.** When the Compose job fails, the image build output, `docker compose ps` and each container's recent logs are published as job annotations. Playwright failures are reported the same way.
- **E2E stability.** Navigation clicks are scoped to the main menu (the overview's tiles are links too), and the audit-log step waits for its page before filling the filter.

## Test results (all run locally)

| Check | Result |
|---|---|
| Backend tests (`uv run pytest -q`, PostgreSQL 16) | **300 passed** (43 new) |
| — dashboard figures vs independent SQL, ranges, empty DB, permissions | 5 |
| — explorer filters, CIDR, status classes, wildcard escaping, keyset walk, count cap, validation | 25 |
| — event detail, alert status + audit, status survives re-detection, viewer blocked, title search | 8 |
| — worker heartbeat and health check | 5 |
| Backend lint / format / `alembic check` | passed / passed / no drift |
| Frontend tests (Vitest) | **59 passed** (18 new) |
| Frontend lint / typecheck / build | clean / clean / built |
| End-to-end (Playwright, real API + worker) | **5 passed**, repeated 3× in one run against the same database (15/15) |

### Highlights of what is tested
- **The dashboard agrees with raw SQL.** Totals, open and high/critical counts and per-severity counts are each checked against an independent query, and the time series must sum to the totals.
- **Keyset pagination** walks 35 events (including 10 with an identical timestamp) in pages of 7: every event exactly once, in order, in 5 pages.
- **Filter edge cases:** `100%` matches only the literal text; `203.0.113.0/24` matches the subnet; `4xx` vs `404`; naive timestamps, `6xx`, bad cursors and one-character searches are rejected with 422.
- **Triage:** the PATCH sends the CSRF header; viewers get 403 from the server, not only a hidden button; the audit entry records the note.
- **New end-to-end investigation journey:** import a log with SQL injection attempts from a unique IP → wait for detection → find the IP on the overview → open the alert → see the raw evidence → mark it investigating with a note → confirm the audit entry → pivot to the event explorer and see exactly the two attack requests.

## Performance (indicative, single run)

| Query over 500,006 events | Time |
|---|---|
| Dashboard, all time (all widgets) | ~0.3 s |

## Outstanding issues / limitations
- **Assignment, notes threads, incidents and rule editing in the UI** are Phase 6. Status changes with a note are available now.
- **Text search** is a substring match over the raw line, not a query language.
- **Match counts stop at 10,000** and show as "10,000+".
- **Dashboard time buckets are UTC.** Times are displayed in the browser's local time zone.
- **Docker Compose** is verified in CI (it now passes); it was not run locally.

## Next: Phase 6
- incidents that group related alerts
- the rule management UI (enable/disable, thresholds, version history)
- alert assignment and analyst notes
- audit history views and CSV/JSON exports
