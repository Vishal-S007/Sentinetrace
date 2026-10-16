# Acceptance Matrix

Each requirement in [REQUIREMENTS.md](REQUIREMENTS.md) is listed with where it is implemented and the evidence that it works. "Acceptance check" refers to `scripts/acceptance.py`; its full output from the clean-checkout run is in the [Phase 8 report](reports/phase-8.md).

## 14. Final delivery criteria

| # | Criterion | Evidence | Result |
|---|---|---|---|
| 1 | Documented setup works | Fresh `git clone` from GitHub, README "Local development" steps followed exactly; Docker Compose setup verified by the CI `compose` job on every push (build, migrations, login through nginx, upload, detection) | ✅ |
| 2 | Frontend, backend and database start | Acceptance check §1-2; CI `compose` job waits for every container to be healthy | ✅ |
| 3 | Authentication and permissions verified | Acceptance check §3 (7 role checks, logout); `test_auth.py`, `test_authz_coverage.py` (every endpoint needs auth + CSRF), `test_users_and_audit.py`; E2E `auth.spec.ts` | ✅ |
| 4 | Synthetic log imported and parsed | Acceptance check §4: 6,331 + 81 + 208 lines, 0 rejected, duplicate refused (409) | ✅ |
| 5 | Known patterns trigger evidence-backed alerts | Acceptance check §5: 13/13 expected alerts, none missing or unexpected, every alert with raw log lines, reason, confidence and steps; `test_synthetic_dataset.py` (precision = recall = 1.0) | ✅ |
| 6 | Normal traffic does not trigger every rule | Acceptance check §6: 23,632 benign events → 0 alerts; 44 benign IPs in the attack dataset → 0 alerts; `test_benign_dataset.py` incl. near-miss test | ✅ |
| 7 | Alerts investigated, updated, persisted | Acceptance check §7: status, owner, note and incident read back in a new session and found in the audit log; E2E `investigation.spec.ts` | ✅ |
| 8 | Dashboard figures match database queries | `test_dashboard_events.py::test_dashboard_matches_independent_sql`; acceptance check §8 (API paths); raw SQL vs dashboard on the clean instance (Phase 8 report) | ✅ |
| 9 | Exports contain the correct records | `test_exports.py` (row-by-row vs SQL and vs screens); acceptance check §9 | ✅ |
| 10 | Automated tests run and reported | Phase reports 1-8 with commands and counts; CI on every push | ✅ |
| 11 | Setup and troubleshooting guide | README (Quick start, Local development, Troubleshooting), [deployment.md](deployment.md) | ✅ |
| 12 | Limitations documented | "Outstanding issues" in every phase report; [deployment.md](deployment.md#known-limitations) | ✅ |

## 3. Required screens

| Screen | Where | Tests |
|---|---|---|
| Login and logout | `/login`, sidebar Sign out | `App.test.tsx`, E2E `auth.spec.ts` |
| Security overview | `/dashboard` | `DashboardPage.test.tsx`, E2E investigation |
| Log sources and file import | `/sources` | `SourcesPage.test.tsx`, E2E `ingestion.spec.ts` |
| Ingestion jobs and errors | `/jobs`, `/jobs/:id` | `JobsPage`/`JobDetailPage` tests, E2E ingestion |
| Event explorer | `/events` | `EventsPage.test.tsx`, E2E investigation |
| Alert queue | `/alerts` | `AlertsPage.test.tsx` |
| Alert investigation and evidence | `/alerts/:id` | `AlertDetailPage.test.tsx`, E2E investigation |
| Detection rules management | `/rules`, `/rules/:id` | `RulesPage.test.tsx` |
| Incident workspace | `/incidents`, `/incidents/:id` | `IncidentDetailPage`/`IncidentsPage` tests, E2E investigation |
| Reports and exports | Export links on alerts, events, audit; incident report | `test_exports.py`, E2E investigation |
| Users, roles and audit | `/admin/users`, `/admin/audit` | `UsersPage`/`AuditPage` tests, E2E auth |
| Settings and health status | `/status`, `/admin/retention` | `StatusPage.test.tsx`, `RetentionPage.test.tsx` |

E2E `security.spec.ts` opens every screen under the production Content-Security-Policy and fails on any violation or page error.

## 4. Ingestion

| Requirement | Evidence |
|---|---|
| Apache combined, Nginx common/custom, JSON, auth log | `test_parsers.py`, `test_ingestion.py::test_pipeline_per_format`; [log-formats.md](log-formats.md) |
| Detection and explicit format | `test_ingestion.py::test_undetectable_format_fails_with_guidance`, `test_upload_format_override` |
| Type, size, encoding validation; limits | `test_upload_type_validation`, `test_upload_size_limit`, `test_body_size_middleware_rejects_before_parsing`, `test_invalid_utf8_is_replaced_and_flagged`, `test_line_limit_fails_job_with_partial_counts` |
| Raw line kept; ingestion vs event time | `test_events_preserve_raw_line_and_separate_times` |
| Parsed / rejected / duplicate counts; error details | `test_job_status_and_error_details_api`, `test_overlapping_files_count_duplicates`, `test_csv_export_neutralizes_formula_injection` |
| Malformed timestamps and lines | `test_parsers.py` (e.g. `test_clf_requires_offset_and_rejects_future`), `test_overlong_lines_are_rejected_not_fatal` |
| Path traversal, unsafe files, duplicates | `test_malicious_filenames_are_never_used_as_paths`, `test_resolve_storage_path_blocks_traversal`, `test_same_file_twice_is_rejected` |
| Log content never executed or rendered as HTML | Parsers treat input as data; frontend tests assert `<img onerror>` / `<script>` show as text |

## 5. Detection engine

All 10 rules (each with an ID, description, severity, enabled state, logic, thresholds and steps) are in `app/detection/rules/` and [detection-rules.md](detection-rules.md). `test_detection_rules.py` has positive and benign near-miss cases for each rule. Alert grouping and deduplication: `test_detection_engine.py` (one alert per entity per bucket, idempotent re-runs, results independent of how the time range is split). Alert content (rule, reason, first/last seen, IP and endpoint, count and window, evidence IDs and lines, confidence with explanation, next action) is checked for every alert by the acceptance check §5.

## 6-7. Dashboard, explorer, investigation

- **Dashboard:** widgets are computed live from the database (`dashboard.py`), and every figure has a drill-down link (`DashboardPage.test.tsx`).
- **Event explorer:** server-side filters and keyset pagination (`test_dashboard_events.py`, 25 tests).
- **Investigation:**
  - alert status, owner and notes
  - incidents with linked alerts, evidence references, actions taken and a timeline
  - incident report export
  - covered by `test_incidents.py`, the E2E investigation journey and the acceptance check §7
- **Append-only records:** database triggers protect `audit_log` and `investigation_notes` (`test_notes_are_append_only_in_the_database`, audit trigger tests).

## 8. Database

The schema is normalized with foreign keys, unique and check constraints and indexes. Migrations 0001-0006 each round-trip (`test_migrations_upgrade_downgrade_upgrade`; the Phase 8 clean run took all six down and back up), and `alembic check` reports no drift. Retention and safe purge: `app/services/retention.py`, `test_retention.py`, README "Data retention".

## 9. Security

| Requirement | Evidence |
|---|---|
| Password hashing | Argon2id (`test_password_hashing`) |
| Login rate limiting | `test_sixth_failed_login_is_rate_limited`, `test_rate_limit_per_ip_across_usernames` |
| Server-side authorization, RBAC | `test_authz_coverage.py` (every endpoint enumerated from OpenAPI), permission tests per feature |
| Sessions and logout | `test_logout_invalidates_session_server_side`, `test_deactivated_user_session_stops_working` |
| CSRF | `test_all_unsafe_operations_require_csrf`, `test_csrf_token_from_another_session_is_rejected` |
| Input validation and output encoding | Pydantic schemas with `extra="forbid"`; `test_validation_errors_do_not_echo_input`; frontend renders untrusted text only as text |
| Upload restrictions | See section 4 |
| SQL injection | ORM / parameterized queries only; `test_security.py::test_injection_probes_are_inert` (10 probes) |
| Secrets via environment | `.env` git-ignored; no committed credentials; DB password never returned (`test_system_settings_and_health`) |
| Safe errors | `test_unhandled_error_hides_internals`, `test_database_outage_returns_503_without_details` |
| Audit logging | Every state change and export audited (`test_*_audited*` across suites) |
| Restrictive CORS, secure defaults | CORS off unless configured; CSP on app and API (`test_api_responses_forbid_documents_and_framing`, E2E CSP check) |
| Dependency vulnerabilities | CI `security` job (`pip-audit`, `npm audit`); none known |

## 10. API

OpenAPI documentation is served at `/api/docs`. Every endpoint validates its input with Pydantic and requires authentication, except health, readiness and login (`test_authz_coverage.py`). Exports and administrative operations require their own permissions (`test_export_permissions`, `test_api_is_admin_only`).

## 11. Required tests

| Required | Where |
|---|---|
| Valid and malformed parsing | `test_parsers.py`, `test_ingestion.py` |
| Timestamps and time zones | `test_parsers.py` (`test_syslog_year_inference_across_new_year`, `test_dst_aware_source_timezone`) |
| Duplicate imports | `test_same_file_twice_is_rejected`, `test_overlapping_files_count_duplicates` |
| Every rule, positive and negative | `test_detection_rules.py` |
| Alert deduplication | `test_detection_engine.py` |
| Persistence and migrations | `test_migrations_and_units.py` |
| Authentication and session invalidation | `test_auth.py` |
| RBAC and unauthorized access | `test_authz_coverage.py`, `test_users_and_audit.py` |
| Pagination and filtering | `test_dashboard_events.py` |
| Export correctness | `test_exports.py` |
| Upload limits and malicious filenames | `test_ingestion.py` |
| Frontend interaction and error states | `frontend/src/**/*.test.tsx` |
| End-to-end ingestion → alert investigation | `frontend/e2e/investigation.spec.ts` |
