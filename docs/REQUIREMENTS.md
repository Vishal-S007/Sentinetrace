# SentinelTrace — Project Requirements

**SentinelTrace** is a complete Log Analysis & Threat Detection Platform. It must be an executable, testable software project, not a prototype consisting of static screens, mock buttons or hardcoded dashboard numbers.

## 1. Mission

Develop a security monitoring application that ingests supported web server and authentication logs, normalizes the events, detects suspicious patterns, correlates related events, presents evidence-backed alerts and supports investigation and reporting.

The primary objective is a fully functioning local MVP with a clean architecture that can be extended into a larger security analytics platform.

Do not claim production readiness, perfect detection accuracy or real-world threat prevention without evidence.

## 2. Mandatory technology stack

- Frontend: React, TypeScript and Vite.
- Styling: Tailwind CSS.
- Charts: Recharts.
- Backend: Python and FastAPI.
- Database: PostgreSQL.
- ORM and migrations: SQLAlchemy and Alembic.
- Authentication: secure server-managed sessions or JWT in HttpOnly cookies, with appropriate CSRF protection where required.
- Backend testing: Pytest.
- Frontend testing: Vitest and React Testing Library.
- End-to-end testing: Playwright.
- Local orchestration: Docker Compose.

Use maintained, compatible dependency versions. Pin or lock dependencies. Do not silently replace PostgreSQL with another database or change the mandated architecture. If an essential dependency is unavailable, document the blocker and agree any stack change before making it.

## 3. Required application screens

Implement all screens with real backend integration.

1. Login and logout.
2. Security overview dashboard.
3. Log source and file import management.
4. Ingestion jobs with processing status and error details.
5. Searchable, filterable security event explorer.
6. Alert queue with severity and status filters.
7. Alert investigation and evidence view.
8. Detection rules management.
9. Incident investigation workspace.
10. Reports and exports.
11. User, role and audit management.
12. Application settings and health status.

Every visible control must perform its advertised function. Include loading, empty, success and error states. No dead buttons, placeholder links, fake success messages or permanently hardcoded metrics.

## 4. Log ingestion and normalization

Support at minimum:

- Apache combined access logs.
- Nginx access logs in common and documented custom formats.
- Structured JSON security and application logs.
- A documented authentication-log format with representative fixtures.

Implement format detection where reliable and allow explicit format selection.

For every imported file:

- Validate the file type, size and encoding.
- Enforce configurable upload and processing limits.
- Parse events into a normalized schema.
- Preserve the original source line for investigation.
- Record ingestion time separately from event time.
- Report successfully parsed, rejected and duplicate records.
- Provide downloadable or inspectable error details.
- Handle malformed timestamps, missing fields and invalid lines safely.
- Prevent path traversal, unsafe file handling and duplicate reprocessing.

Treat uploaded log content as untrusted data. Never execute commands or code contained in log lines.

## 5. Detection engine

Implement a modular, deterministic rule-based detection engine with configurable thresholds and test fixtures.

Include:

- Repeated authentication failures.
- Potential brute-force activity.
- Suspicious SQL injection indicators in request data.
- Potential reflected or stored XSS indicators visible in logs.
- Path traversal indicators.
- High-frequency request bursts.
- Repeated HTTP 401 and 403 responses.
- Unusual 404 bursts and reconnaissance-like request sequences.
- Suspicious HTTP methods and malformed requests.
- Configurable combinations of events from the same source IP within a time window.

Each rule must include a unique identifier, description, severity, enabled state, detection logic, threshold configuration and recommended investigation steps.

Each alert must include:

- Detection rule and reason.
- First-seen and last-seen timestamps.
- Relevant source IP and affected endpoint, when available.
- Event count and time window.
- Supporting event IDs and source log evidence.
- Confidence or evidence strength, with an explanation.
- Recommended next investigative action.

Do not treat a suspicious string as proof that an attack succeeded. Clearly distinguish observed indicators from confirmed compromise.

Implement deduplication and alert grouping so a single burst does not create thousands of identical alerts. Make detection results reproducible.

## 6. Dashboard and event explorer

Build a professional dark SOC interface with restrained accent colors, legible typography, responsive layouts and useful information density.

Dashboard widgets must be calculated from actual database records:

- Total ingested events.
- Alerts by severity.
- Events over time.
- Top source IPs by alert count.
- Most frequently triggered detection rules.
- Recent ingestion jobs.
- Recent high-severity alerts.
- Detection trends across selectable time ranges.

The event explorer must support pagination, text search and filters for date range, source IP, event type, HTTP status, severity and detection status where applicable.

Use server-side filtering and pagination. Avoid loading an unbounded event dataset into the browser.

Clicking a chart segment, source IP or alert must navigate to the corresponding filtered records or investigation view.

## 7. Investigation and incident management

Allow authenticated users to:

- Open and review alerts.
- Mark alerts as new, investigating, resolved or false positive.
- Assign an alert to a user.
- Add investigation notes.
- Link related alerts into an incident.
- Record evidence references and actions taken.
- Review the timeline of an incident.
- Export an incident report.

Persist all state changes. Record important actions in an append-only application audit trail. Do not allow ordinary users to silently rewrite historical audit records.

## 8. Database requirements

Create normalized database models and migrations for:

- Users and roles.
- Log sources and ingestion jobs.
- Imported file metadata.
- Normalized events.
- Detection rules and rule versions.
- Alerts and supporting evidence.
- Incidents, assignments and investigation notes.
- Audit records.
- Application configuration.

Add appropriate foreign keys, uniqueness constraints, indexes and transactional operations.

Design for large event tables. Use bounded queries and efficient indexes. Document a retention strategy and provide a safe method to purge eligible data without accidentally deleting unrelated records.

## 9. Security requirements

Implement:

- Secure password hashing.
- Login rate limiting.
- Server-side authorization on every protected endpoint.
- Role-based access control.
- Secure session handling and logout invalidation.
- CSRF protection where applicable.
- Input validation and output encoding.
- Upload size and type restrictions.
- SQL injection prevention through parameterized ORM operations.
- Secrets through environment variables, never committed credentials.
- Safe error messages that do not expose stack traces to clients.
- Audit logging for important administrative actions.
- Restrictive CORS configuration.
- Secure default configuration and documented deployment hardening.

Use synthetic logs and authorized data only. This is a defensive analysis tool, not an exploitation engine.

## 10. API design

Implement documented, validated endpoints for:

- Authentication and current-user information.
- Log upload and ingestion job status.
- Event listing, search, filtering and pagination.
- Alert listing, details and status updates.
- Detection rule listing and controlled configuration updates.
- Incident creation and investigation notes.
- Reports and exports.
- User and role administration.
- Application health and readiness.

Provide OpenAPI documentation. Apply authorization checks to every endpoint, including exports and administrative operations.

## 11. Testing and acceptance criteria

Write real automated tests. Do not substitute screenshots, generated code, successful imports or mock responses for verification.

Required tests include:

- Valid and malformed log parsing.
- Timestamp normalization and timezone handling.
- Duplicate import handling.
- Every detection rule with positive and negative fixtures.
- Alert deduplication.
- Database persistence and migrations.
- Authentication and session invalidation.
- Role-based authorization and unauthorized access attempts.
- Pagination and filtering.
- Export correctness.
- Upload limits and malicious filenames.
- Frontend interaction and error states.
- End-to-end ingestion-to-alert investigation workflow.

Create a synthetic test dataset with known expected results. Report precision, recall and false-positive rate only when the ground truth supports those calculations.

## 12. Development phases

Phase 0: Inspect the environment and create a written implementation plan.

Phase 1: Scaffold the frontend, backend, database, Docker Compose configuration and health checks.

Phase 2: Implement authentication, database models, migrations and authorization.

Phase 3: Implement parsers, ingestion jobs, normalization and persistence.

Phase 4: Implement detection rules, alert grouping and evidence linkage.

Phase 5: Implement the dashboard, event explorer and alert investigation UI.

Phase 6: Implement incidents, rule management, audit history and exports.

Phase 7: Add automated tests, security checks, synthetic fixtures and failure handling.

Phase 8: Run the entire system, fix verified defects, document installation and deployment, and provide a final acceptance report.

Each phase ends with a written report (changes, commands run, test results, outstanding issues, next phase) and must pass its verification gate before the next phase starts.

## 13. Engineering standards

- Never overwrite unrelated files or delete user data.
- Report a command or check as successful only when its output confirms it.
- Run real commands and tests wherever the environment permits.
- Fix root causes rather than hiding errors or weakening tests.
- Never disable security checks merely to obtain a passing test.
- Do not leave essential features as TODOs or simulated functionality.
- If an external service, credential or system is unavailable, implement the legitimate local functionality and clearly document the limitation.
- Do not invent test results, performance measurements, vulnerabilities or success metrics.
- Maintain a README, environment example, database migration instructions, test instructions and troubleshooting guide.
- Never expose secrets in logs or commit them to source control.

## 14. Final delivery criteria

The project is complete only when:

1. The documented setup procedure works in the target environment.
2. The frontend, backend and database start successfully.
3. Authentication and permissions are verified.
4. A supplied synthetic log file can be imported and parsed.
5. Known suspicious patterns trigger the expected evidence-backed alerts.
6. Normal traffic fixtures do not incorrectly trigger every rule.
7. Alerts can be investigated, updated and persisted.
8. Dashboard figures match database queries.
9. Exports contain the correct records.
10. Automated tests have actually run and their results are reported.
11. A clean setup and troubleshooting guide is provided.
12. Remaining limitations and unverified claims are explicitly documented.
