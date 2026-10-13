# Phase 4 Report: Detection Engine, Alert Grouping and Evidence

Date: 2026-10-13 · Result: **Gate passed locally**, including an end-to-end run through the API and the real worker. CI confirmation is pending on push.

## What was built

### Schema (migration `0003`)
- **`detection_rules`:** runtime state per rule (enabled, severity, validated JSON config, version).
- **`detection_rule_versions`:** the full configuration history. It is seeded with version 1 for all 10 rules. A test asserts the migration seed equals the code defaults.
- **`alerts`:** unique on `(rule_id, group_key)`. Has check constraints for severity, status and confidence, and indexes on `last_seen`, `(status, severity)`, `source_ip` and the bucket.
- **`alert_events`:** evidence links (`alert_id`, `event_id`, matched indicator), with an index on `event_id` for "which alerts reference this event".
- **`detection_runs`:** queued, auditable detection work.

### Engine (`backend/app/detection/`)
- **10 rules:**
  - ST-AUTH-001/002
  - ST-WEB-001…007
  - ST-CORR-001
- **What each rule declares:** id, name, category, description, default severity, a pydantic config schema, recommended investigation steps, and deterministic logic.
- **Grouping:** fixed, epoch-aligned buckets per (rule, entity).
- **Sliding windows:** `(t − W, t]` with 2W lookback. A window can cross a bucket boundary, and events are never double-counted across consecutive alerts.
- **Upsert by `(rule_id, group_key)`:**
  - Re-runs refresh alerts in place and report created / updated / unchanged.
  - Analyst fields (status, assignee) are preserved.
- **Evidence:**
  - each linked event carries its matched indicator
  - the cap (default 500) is shown via `evidence_truncated`
  - `event_count` stays exact
- **Confidence:** every alert has a confidence level with a written reason.
- **Indicator-only wording:** every alert's reason states that it is an indicator, not confirmed compromise. A test checks this for every alert produced from the synthetic dataset.
- **Correlation:** combines member alerts from different rules for the same IP and bucket.

### Pipeline
- When ingestion completes, a detection run is queued for that job's time range. The worker processes ingestion jobs first, then detection runs.
- Manual rescans: `POST /api/detection/runs` (admin, audited).
- Retrying an ingestion job also removes evidence links to its partial events.

### API
- **Rules:**
  - `GET /api/rules`, `GET /api/rules/{id}` (with version history): viewer and up.
  - `PATCH /api/rules/{id}`: admin only. Partial config merge, then full schema validation, then a new version row, then an audit entry. A no-op change doesn't bump the version.
- **Detection runs:** `POST /api/detection/runs` (admin) and `GET /api/detection/runs`.
- **Alerts:**
  - `GET /api/alerts`: filter by status, severity, rule, IP and time, with keyset pagination.
  - `GET /api/alerts/{id}`: reason, confidence explanation, recommended steps.
  - `GET /api/alerts/{id}/evidence`: paginated, each item with its original log line.

## Test results (all run locally)

| Check | Result |
|---|---|
| Backend tests (`uv run pytest -q`, PostgreSQL 16) | **257 passed** (114 new) |
| — per-rule positive/negative fixtures (`test_detection_rules.py`) | 74 |
| — engine: idempotency, split-range independence, grouping, analyst fields, runs, seeds | 16 |
| — API, permissions, validation, ingestion→detection pipeline | 19 |
| — synthetic dataset end-to-end | 5 |
| Backend lint / `alembic check` | passed / no drift |
| Frontend tests / lint / build (unchanged this phase) | 41 passed / clean / built |
| CI detection step executed locally against the real API + worker | passed (8 expected web detections) |

### Highlights of what is tested
- **Every rule** has positive and negative cases, including benign near-misses:
  - 4 failures
  - failures 6 minutes apart
  - 299 requests in 60 s
  - steady 60 req/min
  - occasional favicon 404s
  - normal HTTP methods
  - benign search terms: `select your size`, `O'Brien`, `union station`, `it's--great`, `drop shipping`, `javascript book`, `etc passwords manager`, …
- **Window semantics are pinned exactly.** Events exactly W apart do not count; events just inside do.
- **Mutation-checked:**
  - breaking the UNION pattern failed 4 tests
  - doubling the window failed 2 tests (after adding boundary tests, which the first mutation run showed were missing)
- **Deduplication:** a 5,000-request burst produces **1 alert** with `event_count=5000`, 500 evidence links and `evidence_truncated=true`.
- **Boundary handling:**
  - a burst straddling 10:59:30–11:00:30 produces one alert, in the 11:00 bucket, with all 300 events
  - two hours of continuous failures produce 2 alerts whose counts sum exactly to the event total
- **Reproducibility:**
  - a second run reports 0 created and 0 updated, with an identical alert and evidence snapshot
  - processing buckets separately in reverse order equals processing them together

### Synthetic dataset evaluation (`datasets/synthetic/`, `test_synthetic_dataset.py`)
- **Benign traffic** (6 hours):
  - 6,331 web lines, 81 auth lines and 208 application lines
  - 44 benign entities, including tricky-but-benign requests, a health monitor and a busy NAT just under the burst threshold
- **Attacks:** 8 scripted scenarios
- **Ground truth:** 743 malicious lines and 13 expected alerts

| Metric | Value |
|---|---|
| Alerts expected / produced | 13 / 13 |
| True positives / false positives / false negatives | 13 / 0 / 0 |
| Precision / recall (alert level) | **1.0 / 1.0** |
| Benign entities alerted (false-positive rate) | **0 of 44 (0.0)** |
| Evidence events labelled malicious | 642 of 642 (1.0). 642 < 743 because the flood's evidence is capped at 500 |

**Caveat:** this dataset was written alongside the rules to exercise them. A perfect score shows the rules behave as specified on known scenarios and known benign look-alikes. It does **not** estimate real-world precision or recall, which would need labelled production data.

### Measured performance (local development machine: 2 vCPU, PostgreSQL 16)
These are single-run figures and indicative only. They show the effect of a profiling-driven optimization:

| Detection over 500,006 events (all 10 rules, full rescan) | Time | Throughput |
|---|---|---|
| First implementation | 95.1 s | ~5,300 events/s |
| After optimization | **17.8 s** | **~28,000 events/s** |

What changed:
- the IP is returned as text, via SQL `host()`, instead of being parsed per row
- only the needed JSON attribute is extracted
- rules with the same SQL prefilter share one fetch
- decode+scan results are memoized per field value

All 257 tests pass on the optimized path.

**End to end:** the synthetic web log (6,331 lines) was imported and detection completed in about 2.4 s through the API and the real worker.

## Outstanding issues / limitations
- **No UI for alerts and rules yet.** The alert queue and investigation UI are Phase 5; rule management, incidents and status changes are Phase 6. The APIs exist and are tested.
- **Bucketed alerts:** grouping is per hour by default, so a long attack yields one alert per hour.
- **Indicator rules see only logged request data,** not POST bodies.
- **Alerts are never auto-deleted.** If thresholds are raised, older alerts remain until an analyst resolves them.
- **Docker Compose** is still verified only in CI. The new CI step asserts that detection works inside the worker container.

## Next: Phase 5
- the dashboard, with widgets computed from the database and clickable drill-downs
- the event explorer, with server-side search, filters and pagination
- the alert queue
- the alert investigation and evidence view
