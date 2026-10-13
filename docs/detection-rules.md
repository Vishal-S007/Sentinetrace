# Detection Rules

SentinelTrace's detection engine is **deterministic and rule-based**. Given the same events and the same rule configuration, it always produces the same alerts.

Every alert describes an **observed indicator**. No alert claims that an attack succeeded. Each alert's `reason` text says this explicitly. Confirming compromise is an analyst decision.

## How detection runs
- **After each import:** when an ingestion job completes, a detection run is queued for that job's event time range. The worker processes it right after the import.
- **Manual:** an admin can queue a rescan with `POST /api/detection/runs` (`since` and `until` are optional; the default is all events), for example after changing thresholds.
- **Chunking:** large ranges are processed in chunks of `ST_DETECTION_CHUNK_HOURS` (default 24).

## Grouping and deduplication
- **One alert per group:** alerts are grouped by **rule, entity and time bucket**:
  - Buckets are fixed `ST_ALERT_GROUP_MINUTES` intervals (default 60) aligned to the Unix epoch.
  - The entity is the source IP, or user+IP for ST-AUTH-001.
  - A burst of 5,000 requests therefore produces **one** alert, with an exact `event_count` and up to `ST_MAX_EVIDENCE_PER_ALERT` (default 500) linked evidence events.
  - `evidence_truncated` shows when the evidence cap was reached.
- **Fixed buckets** make results independent of import order and of how a time range is split. Processing two hours separately or together yields identical alerts (tested).
- **Sliding windows** are `(t − W, t]`. A window may reach back into the previous bucket, so bursts that straddle a bucket boundary are still detected. The alert belongs to the bucket where the threshold was crossed. Events already counted by an earlier bucket's alert are **not counted again**.
- **Re-running detection is idempotent:**
  - existing alerts are refreshed in place
  - a re-run with no new data reports 0 created and 0 updated
  - analyst-owned fields (status, assignee) are never overwritten
- **Disabled rules:** rules disabled after an alert was created leave that alert in place. Alerts are only ever closed by analysts.

## Alert contents

| Field | Meaning |
|---|---|
| `rule_id`, `rule_version` | Which rule, and which configuration version, produced it |
| `title`, `reason` | What was observed, with counts and time span, and the "indicator only" caveat |
| `first_seen`, `last_seen`, `event_count`, `window_seconds` | Time span, total supporting events, rule window |
| `source_ip`, `username`, `endpoint` | Entity and most-targeted endpoint, when available |
| `confidence`, `confidence_reason` | `low`, `medium` or `high`, plus the reason it was assigned |
| `recommended_action` + rule `recommended_steps` | What to check next |
| evidence (`/api/alerts/{id}/evidence`) | Linked event IDs, each with the matched indicator and the **original log line** |
| `details` | Rule-specific facts, e.g. indicator types, status codes, targeted users, scanner paths, member alerts |

## Rules
Defaults are shown. Every threshold is editable by an admin (`PATCH /api/rules/{id}`):
- Each change is validated against the rule's schema.
- Each change creates a new **version**, and the full history is kept.
- Each change is audited.

| ID | Name | Default severity | Logic (defaults) |
|---|---|---|---|
| ST-AUTH-001 | Repeated authentication failures | medium | ≥ 5 `auth_failure` events for the same **user + IP** within 300 s |
| ST-AUTH-002 | Potential brute force / password spraying | high | From one IP within 600 s: ≥ 20 failures **or** failures against ≥ 5 distinct accounts. A later `auth_success` from the same IP is linked and raises confidence |
| ST-WEB-001 | SQL injection indicators | high | Any request whose path, query, User-Agent or Referer matches: UNION SELECT, tautology (`' OR '1'='1`), comment terminator, time-delay (`sleep(`, `pg_sleep`, `WAITFOR DELAY`), stacked query, schema probe (`information_schema`…), error-based (`extractvalue`, `updatexml`), `xp_cmdshell` |
| ST-WEB-002 | XSS indicators | medium | `<script`, event handlers in tags (`onerror=`…), `javascript:` URIs, `<svg`/`<img`/`<iframe` injection, DOM access (`document.cookie`, `alert(`…) |
| ST-WEB-003 | Path traversal indicators | high | `../` or `..\` (after decoding), double-encoded dots (`%252e`), sensitive files (`/etc/passwd`, `win.ini`, `/proc/self/`, `.htpasswd`, `id_rsa`…) |
| ST-WEB-004 | High-frequency request burst | medium | ≥ 300 requests from one IP within 60 s |
| ST-WEB-005 | Repeated HTTP 401/403 | medium | ≥ 15 responses with status 401 or 403 to one IP within 300 s |
| ST-WEB-006 | 404 burst / reconnaissance | medium | From one IP within 300 s: ≥ 30 404s **or** ≥ 20 distinct missing paths. Known scanner paths (`/.env`, `/.git`, `/wp-admin`…) raise confidence |
| ST-WEB-007 | Suspicious methods / malformed requests | low | Method outside the allowed list (GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS), or a malformed request line |
| ST-CORR-001 | Multi-stage activity from one IP | high | Alerts from ≥ 2 **different** rules in the configured list, for the same IP in the same bucket. The evidence is the union of the member alerts' evidence |

**Indicator matching** (ST-WEB-001/002/003):
- Values are URL-decoded repeatedly, up to 3 times, to catch double encoding, and then lowercased.
- Header scanning (User-Agent, Referer) can be turned off per rule with `include_headers`.
- `min_matches` sets how many matching requests per IP and bucket are needed.

### Confidence

| Rule type | `high` when | `low` when |
|---|---|---|
| Indicator rules | A known attack-tool User-Agent (e.g. sqlmap), ≥ 2 distinct strong indicator types, or ≥ 5 matching requests | Only weak indicators matched (a lone quote-plus-comment for SQLi; a plain `<img` tag for XSS; only malformed requests for ST-WEB-007) |
| Threshold rules | The peak in the window is ≥ 2× the threshold, plus the rule-specific signals noted above | — |

Correlation alerts are always `high`, because independent rules agree.

### Known limitations (by design)
- **Events with no source IP** are ignored by IP-based rules.
- **Bucket boundaries:** alerts are per bucket, so a long-running attack yields one alert per hour.
- **Request data only:** the indicator rules see only what the log recorded. POST bodies are not in access logs, so payloads sent in bodies cannot be detected.
- **Patterns are not proof:** they are tuned to avoid common benign text (tested with "select your size", "O'Brien", "union station", "it's--great", "javascript book" and others). They can still match unusual legitimate input, and they can miss obfuscated payloads.

## Evaluation on the synthetic dataset
`datasets/synthetic/generate.py` deterministically generates:
- **Traffic:** six hours of benign web, auth and application traffic, including deliberately tricky benign requests, a health monitor, and a busy office NAT just below the burst threshold.
- **Attacks:** eight attack scenarios.
- **Ground truth:** `ground_truth.json` lists every malicious line and the exact expected alerts.

`backend/tests/test_synthetic_dataset.py` imports the dataset through the real API and worker functions and compares the results. Run it with `-s` to print the metrics.

These figures describe behaviour on this **synthetic, purpose-built** dataset only. They are not a measure of real-world accuracy. See the Phase 4 report for the numbers.
