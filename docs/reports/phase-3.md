# Phase 3 Report: Log Ingestion, Parsing and Normalization

Date: 2026-10-12 · Result: **Gate passed locally** (backend, frontend, Playwright E2E with a real worker). CI confirmation is pending on push.

## What was built

### Database (migration `0002`)
- **Tables:** `log_sources`, `imported_files`, `ingestion_jobs`, `ingestion_errors`, `events`.
- **Check constraints:**
  - source format
  - job status
  - `nginx_custom` requires a pattern
- **Unique constraints:**
  - `(source_id, sha256)` on files
  - `fingerprint` on events
- **Event indexes**, designed for large tables:
  - BRIN on `event_time`
  - B-tree on `(source_ip, event_time)`, `(event_type, event_time)`, `(http_status, event_time)`, `(source_id, event_time)` and `job_id`
  - Verified: `EXPLAIN ANALYZE` for an IP plus time-range query uses an index-only scan (0.05 ms).

### Parsers (`backend/app/ingestion/parsers/`)
| Format | Notes |
|---|---|
| `apache_combined` / `nginx_combined` | Offset required. Malformed request lines kept and flagged (detection signal). Escaped quotes handled |
| `nginx_common` (CLF) | |
| `nginx_custom` | Compiles the nginx `log_format` string to an anchored regex. Known variables are mapped; others go to attributes |
| `json` (JSON Lines) | Flattens nested objects (ECS-style). Alias lookup for each field. ISO / epoch seconds / epoch ms timestamps. Classifies auth success/failure, HTTP request and app log |
| `auth_log` | rsyslog RFC 3164 and RFC 3339 headers. Recognizes sshd failed/accepted/invalid user/max attempts, pam_unix failures, and sudo failures/commands |

Further details:
- **Timestamps:**
  - Everything is normalized to UTC.
  - Values without an offset use the source's IANA time zone, including daylight-saving time.
  - Syslog year inference handles New Year.
  - Timestamps before 1990, or more than one day in the future, are rejected.
- **Format detection:** the best format must parse at least 80% of a 50-line sample, with no tie. Otherwise the job fails with guidance to choose a format explicitly.
- **Full reference:** [docs/log-formats.md](../log-formats.md).

### Upload and storage safety
- **Streaming upload:** the file is streamed to a temp file while being SHA-256 hashed and size-checked.
- **Two size limits:**
  - An ASGI middleware enforces the body limit *before* parsing. It checks Content-Length and also counts streamed bytes, so chunked requests can't bypass it.
  - The upload code enforces it again.
- **Type check:** the bytes themselves are inspected for compressed or binary magic numbers, NUL bytes and control-character density. The client's Content-Type is ignored.
- **Encoding:** UTF-8, with or without BOM. Invalid bytes are replaced and flagged.
- **Filenames:** stored content-addressed as `files/ab/cd/<sha256>`. The client filename is sanitized and used for display only, never as a path. Path resolution refuses anything outside the storage root.
- **Duplicates:** the same file uploaded to the same source gets **409**.

### Processing pipeline
- **Queue:**
  - A DB-backed job queue with `FOR UPDATE SKIP LOCKED`, so multiple workers are safe.
  - The worker process is `python -m app.worker`, with a heartbeat and stale-job recovery capped by max attempts.
- **Integrity:** the stored file's SHA-256 is re-verified before processing.
- **Bulk load:**
  - Rows are loaded with `COPY` into a temp staging table, then one `INSERT … SELECT … ON CONFLICT (fingerprint) DO NOTHING`.
  - The statements are composed with `psycopg.sql`.
- **Live progress:** counters update after every batch.
- **Duplicate semantics:**
  - The fingerprint is SHA-256(source, raw line, occurrence-within-file).
  - Overlapping (rotated) files count overlaps as duplicates.
  - Genuinely repeated requests inside one file are all kept.
- **Limits:**
  - Lines over the length limit are rejected individually.
  - Exceeding the line limit fails the job, keeping the counts processed so far.
  - Stored error rows are capped, with an exact rejected count.
- **Job statuses:** `queued`, `running`, `completed`, `completed_with_errors`, `failed`. A failed job can be retried; this deletes its partial events and errors first, so reprocessing is idempotent.

### API
- `GET /api/formats`, `GET /api/sources` (with file and event counts), `POST /api/sources`, `PATCH /api/sources/{id}`.
- `POST /api/sources/{id}/files` (multipart, optional per-upload format override).
- `GET /api/jobs` (filters and keyset pagination), `GET /api/jobs/{id}`, `GET /api/jobs/{id}/errors` (paginated), `GET /api/jobs/{id}/errors.csv`, `POST /api/jobs/{id}/retry`.
- **Permissions:** viewers can read; analysts and admins can create sources, upload and retry.
- **CSV exports** neutralize formula injection.
- **Audited actions:** `source.create`, `source.update`, `file.upload` (with SHA-256 and size), `job.retry`.

### Frontend
- **Log sources:**
  - list with format, time zone, file and event counts and last upload
  - create form (log_format field only for nginx_custom, with an example for each format)
  - enable or disable a source
  - per-source upload with optional format override, which links straight to the job
- **Ingestion jobs:**
  - status filter in the URL
  - live auto-refresh only while jobs are queued or running
  - keyset "Load older"
- **Job detail:**
  - counts, format, encoding, timings, failure reason
  - rejected lines rendered strictly as text
  - CSV download
  - Retry (permission-gated)
- Viewers see read-only versions of these pages.

### Infrastructure
- **Compose:** a `worker` service shares the storage volume and starts after the backend is healthy, i.e. after migrations have run.
- **CI:**
  - The `e2e` job starts the worker.
  - The `compose` job uploads a fixture through nginx and asserts the worker container produced the expected counts: completed_with_errors, 5 parsed, 3 rejected.

## Commands executed and results

| Check | Result |
|---|---|
| Backend tests (`uv run pytest -q`, real PostgreSQL 16) | **143 passed** (79 new: 31 parser unit + 48 ingestion integration) |
| Backend lint/format, `alembic check` | passed, no model/migration drift |
| Migration round trip incl. `0002` | passed (also covered by the scratch-DB test) |
| Frontend tests (`npx vitest run`) | **41 passed** (17 new) |
| Frontend lint / build | 0 warnings / built |
| **E2E (Playwright, Chromium, live API + worker + PostgreSQL)** | **4 passed** (auth ×3, ingestion ×1) |
| Compose config | valid |

### Measured ingestion throughput (local development machine: 2 vCPU, PostgreSQL 16)
Test file: a synthetic Apache combined log of **200,000 lines (21 MB)**, uploaded through the API and processed by the real worker.

| Version | Processing time | Throughput |
|---|---|---|
| First implementation (ORM multi-row `INSERT … VALUES`) | 129.9 s | 1,540 lines/s |
| Core executemany (`insertmanyvalues`) | — | ~3,960 lines/s (20k-line sample) |
| **Final: `COPY` → staging table → `INSERT … ON CONFLICT`** | **20.5 s** | **9,767 lines/s** |

- **How the bottleneck was found:** profiling showed about 70% of time went to SQLAlchemy compiling a 22,000-parameter statement per batch, then psycopg re-splitting large queries. These figures are from a single run on this machine; they are indicative only, not a benchmark.
- **Unchanged behaviour:** duplicate counting and retry semantics are the same, and all 143 tests pass on the final path.

### Key tests
- **Parsers:**
  - every fixture parses with its exact counts and field values
  - offset and time-zone conversion, including daylight-saving time
  - syslog New Year rollover
  - future and ancient timestamps rejected
  - malformed request lines kept and flagged
  - IPv6
  - hostname kept as an attribute
  - truncation flags
  - nginx log_format compiler: validation, multi-line strings, `${var}` syntax
  - JSON: ECS nesting, epoch ms, naive timestamps, deep nesting bounded, invalid values
  - format detection, including the "not confident" case
- **Pipeline (per format):** the expected (total, parsed, rejected, status) for all 6 formats plus auto-detection.
  - raw line and line numbers preserved
  - `ingested_at` stored separately from `event_time`
- **Duplicates:**
  - same file → 409
  - the same file into another source is allowed
  - overlapping files → parsed 2, duplicates 3, with internal repeats kept
- **Safety:**
  - `../../etc/passwd`, Windows paths and absolute paths are stored by hash, with no writes outside storage and no leftover temp files
  - path resolution refuses traversal
  - gzip, gz extension, NUL bytes, control-character noise → 415
  - empty file → 422
  - over-limit file → 413 from the handler; 413 from the middleware before parsing (also for JSON bodies over 1 MB)
  - invalid UTF-8 replaced and flagged
  - BOM and CRLF handled
  - CSV formula injection neutralized
- **Failure handling:**
  - undetectable format
  - wrong format, with nothing parsing
  - format override
  - tampered file (integrity check) → retry → missing file → retry → success, with `attempts=3`
  - retry clears partial results
  - stale-job recovery and the max-attempts failure
  - line limit with partial counts
  - error-storage cap
  - small batches give identical counts
- **Permissions and validation:**
  - viewers can read sources, jobs and formats but get 403 when creating or uploading
  - source validation: pattern required, invalid pattern, bad time zone, bad format, blank name
  - duplicate source names → 409
  - disabled sources refuse uploads
- **Authorization coverage:** the OpenAPI-enumerated tests automatically cover every new endpoint for 401 without a session and 403 without CSRF.

## Outstanding issues / limitations
- **Compressed uploads** (`.gz`) are refused with a clear message, not decompressed. This is documented.
- **Duplicate-detection memory bound:** the per-file occurrence counter tracks the most recent 200,000 distinct lines (documented in log-formats.md).
- **Partial results after failure:** if a job fails partway, the events already committed remain until it is retried. The job page makes the failure visible. Detection (Phase 4) will run only on completed jobs.
- **Docker Compose** is still verified only in CI, because image pulls were blocked in the local development environment.

## Next: Phase 4
The deterministic detection engine:
- rules for authentication failures, brute force, SQL injection, XSS, path traversal, request bursts, repeated 401/403, 404 recon, suspicious methods and malformed requests, and multi-signal correlation
- configurable thresholds with rule versions
- alert grouping and deduplication
- evidence linkage to event IDs and raw lines
- confidence explanations
- positive and negative fixtures for every rule
- a synthetic dataset with ground truth
