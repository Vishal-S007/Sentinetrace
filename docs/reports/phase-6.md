# Phase 6 Report: Incidents, Rule Management, Audit History and Exports

Date: 2026-10-14 · Result: **Gate passed locally**. CI confirmation is pending on push.

## What was built

### Schema (migration `0005`)
- **`incidents`:** title, summary, status (`open`, `investigating`, `contained`, `resolved`, `closed`), severity, owner, creator, timestamps, `closed_at`. Check constraints on status and severity; indexes on `(status, updated_at)` and owner.
- **`incident_alerts`:** which alerts belong to which incident (an alert may be in more than one), who linked it and when. Indexed by alert for "which incidents include this alert".
- **`investigation_notes`:** a note, an action taken, or an evidence reference (optionally pointing at an event) on exactly one alert or one incident. A check constraint enforces "exactly one parent". **Append-only:** a database trigger rejects `UPDATE` and `DELETE`, the same way as the audit log.
- **Audit log index** on `(target_type, target_id, id)`, so the history of one alert or incident is a cheap lookup.
- The migration downgrades and re-upgrades cleanly, and `alembic check` reports no drift.

### Alerts
- **Owner:** `PATCH /api/alerts/{id}` now accepts `assigned_to` (or `null` to clear) alongside `status`. Only active analysts and admins can own alerts. Each change is audited as `alert.assign` with the previous and new owner.
- **Notes:** `POST /api/alerts/{id}/notes` (analyst and admin). Audited as `alert.note`.
- **Activity:** `GET /api/alerts/{id}/activity` returns the notes, the alert's change history (from the audit log) and the incidents it belongs to. Readable by anyone who can read alerts.
- **Queue:** new `assigned_to=me|none|<id>` filter; each alert now carries its owner's name.
- **`GET /api/assignees`:** active users who may own alerts and incidents.

### Incidents (`/api/incidents`)
- List with filters (status, open only, severity, owner, title) and keyset pagination.
- Create with linked alerts. Severity defaults to the highest severity among them. Unknown alert ids are rejected and nothing is created.
- Update title, summary, status, severity and owner, with an optional reason. Only changed fields are recorded; an update that changes nothing is not audited. `closed_at` is set on resolve/close and cleared on reopen.
- Link alerts (idempotent: already-linked alerts are skipped and not audited) and remove alerts. At most 200 per request and 1,000 per incident.
- Notes, actions and evidence references.
- **Timeline:** merges when each linked alert was first and last observed, every change (from the audit log) and every note, in time order.
- **Report:** `GET /api/incidents/{id}/report?format=markdown|json` (needs `reports:export`). Contains the incident details, linked alerts with their reasons and first five evidence lines, the timeline and the notes, plus a statement that alerts are indicators, not confirmed compromise. Log lines are placed in a code fence longer than any backtick run they contain, so log content cannot break the report's formatting. Each download is audited as `incident.export`.

### Exports
- **`GET /api/alerts/export`, `/api/events/export`, `/api/audit/export`**, each as CSV or JSON.
- **Same filters as the screens:** the list endpoints and the exports share one filter dependency each, so an export always holds exactly what the screen shows.
- **Limits:** 50,000 alerts, 100,000 events, 100,000 audit entries. `X-Export-Rows` and `X-Export-Truncated` headers report what was written.
- **Bounded memory:** rows are read in batches and written to a spooled temporary file, which is then streamed, so no database session is held open while the download is sent.
- **Spreadsheet formula injection:** CSV cells starting with `=`, `+`, `-`, `@`, tab or CR get a leading `'`. Plain numbers (including negatives) and a lone `-` are left alone. JSON keeps the original values.
- **Audited** as `export.alerts`, `export.events` or `export.audit` with format, row count, truncation and the filters used.
- Permissions: exports need `reports:export` plus read access to the data; the audit export is admin-only.

### Audit history
- The audit log API and screen gained **target type** and **target ID** filters (for example every change to one alert or incident) and an export.

### Operations
- **Quieter logs:** successful `/api/health` and `/api/ready` calls (the container health check runs every few seconds) are no longer written to the access log. Failed checks still are.

### Frontend
- **Incidents:** list with filters, "New incident" (pre-filled when coming from selected alerts), and an incident page with summary editing, linked alerts (link by ID, remove), the timeline, a note/action/evidence composer, a manage panel (status, severity, owner, reason) and report downloads.
- **Alert queue:** owner filter and column; checkboxes to select alerts and create an incident from them; CSV/JSON export with the current filters.
- **Alert page:** owner picker, investigation notes, incidents the alert belongs to with "Add to incident" (new or existing), and a history panel.
- **Detection rules:** list with state, version and open alerts, and "Re-run detection" for admins. Rule page with description, recommended steps, a settings form generated from the rule's schema (numbers with their limits, switches, lists), a change note, and version history showing what changed between versions. Viewers and analysts see the settings read-only.
- **Event explorer and audit log:** export links with the current filters; the audit log has target filters.
- Every screen was checked at 1360 px for horizontal overflow (none). The incident page was checked at 390 px (no horizontal scroll).

## Test results (all run locally)

| Check | Result |
|---|---|
| Backend tests (`uv run pytest -q`, PostgreSQL 16) | **340 passed** (40 new) |
| — assignment, notes (incl. database append-only), incidents, timeline, permissions, reports | 14 |
| — exports vs database and screens, caps, formula injection, auditing, permissions, quiet health logs | 26 |
| Backend lint / format / `alembic check` / migration down + up | passed / passed / no drift / passed |
| Frontend tests (Vitest) | **81 passed** (22 new) |
| Frontend lint / typecheck / build | clean / clean / built |
| End-to-end (Playwright, real API + worker) | **5 passed**, run twice in a row against the same database (10/10) |

### Highlights of what is tested
- **Exports contain the right records.** The alert CSV is compared row by row with a SQL query; the event export is compared with the explorer's own results for the same filters; the audit export with the audit list.
- **Formula injection:** an event whose User-Agent is `=HYPERLINK(...)` and whose log line starts with `@SUM(...)` exports as text in CSV and unchanged in JSON.
- **Append-only notes:** raw SQL `UPDATE` and `DELETE` on a note fail in the database, and the note is unchanged.
- **Atomic creation:** creating an incident with one unknown alert id creates nothing.
- **Mutation checks:** making default severity pick the lowest instead of the highest, using a fixed-length code fence in reports, and removing the CSV formula protection each made a test fail. The code was then restored.
- **End-to-end journey (extended):** import → alert → triage → explorer → create incident from the alert → record an action → mark contained → download the Markdown report and check it contains the evidence line and the action → export the alerts for the IP and check every row.

## Outstanding issues / limitations
- **Data retention and purge** (required by the spec's database section) are not built yet; planned for Phase 7.
- **Notes cannot be edited or deleted** by design. A mistaken note is corrected by adding another.
- **No notifications:** assigning an alert or incident does not notify the new owner.
- **Reports are Markdown and JSON**, not PDF. Markdown converts to PDF or Word with standard tools.
- **Rule changes apply to new imports.** Existing events are re-evaluated only when an admin re-runs detection.
- **Docker Compose** is verified in CI; it was not run locally.

## Next: Phase 7
- data retention strategy and a safe purge command
- broader failure handling (database loss during a job, worker restarts, oversized and malformed input)
- additional security checks: dependency audit, security headers, rate limits on expensive endpoints
- more synthetic fixtures and negative tests
