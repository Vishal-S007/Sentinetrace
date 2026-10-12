# Supported Log Formats

SentinelTrace parses each uploaded file line by line into a normalized event. Every event keeps:
- its original line (`raw_line`) and line number
- `event_time`, when it happened, normalized to UTC
- `ingested_at`, when it was stored

Representative fixtures for every format are in [`backend/tests/fixtures/logs/`](../backend/tests/fixtures/logs/).

## Normalized event fields

| Field | Meaning |
|---|---|
| `event_time` | When the event happened (UTC) |
| `ingested_at` | When SentinelTrace stored it |
| `event_type` | `http_request`, `auth_failure`, `auth_success`, `auth_other`, `app_log` |
| `source_ip` | Client IP (IPv4/IPv6); non-IP values such as hostnames go to `attributes.remote_host` |
| `username` | Authenticated / attempted user |
| `http_method`, `path`, `query`, `http_version`, `http_status`, `bytes_sent` | HTTP request details. `path` and `query` are stored as logged, without decoding |
| `referrer`, `user_agent`, `host` | Request metadata. For `auth_log`, `host` is the server name |
| `severity`, `message` | Application log level and message |
| `attributes` | Everything else, e.g. `malformed_request`, `truncated_fields`, `encoding_replaced`, custom fields |
| `raw_line` | The original line, unchanged |

Long values are truncated, and the field name is recorded in `attributes.truncated_fields`. The caps are:
- `path`: 2048 characters
- user agent: 1024
- message: 4096

## Formats

### `apache_combined` / `nginx_combined`
These are the Apache `combined` format and Nginx's default `combined` format, which are identical:
```
203.0.113.9 - alice [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "https://ref/" "Mozilla/5.0"
```
- The timestamp **must** include an offset (`+0000`). It is converted to UTC.
- Request lines that are not `METHOD target HTTP/x.y` are **kept**, with `attributes.malformed_request = true`, because malformed requests are a detection signal. Examples are `"-"` and raw TLS bytes like `"\x16\x03\x01"`. The method and path are filled in where they can be recovered.
- Escaped quotes (`\"`) inside quoted fields are unescaped.

### `nginx_common` (CLF)
This is the Common Log Format: the same as combined but without referrer and user agent.
```
192.0.2.2 - bob [10/Oct/2026:08:00:01 +0000] "GET /admin HTTP/1.1" 403 153
```

### `nginx_custom`
Paste the `log_format` string from `nginx.conf` into the source settings, for example:
```
$remote_addr [$time_iso8601] "$request" $status $body_bytes_sent rt=$request_time ua="$http_user_agent"
```
- The string is compiled into an anchored regular expression:
  - a variable inside `"…"` matches a quoted value
  - a variable inside `[…]` matches up to `]`
  - otherwise a variable matches a run of non-spaces
- **Required:** `$time_local`, `$time_iso8601` or `$msec`.
- **Mapped variables:**
  - `remote_addr`, `remote_user`
  - `request` (or `request_method`, `request_uri` / `uri`, `args`, `server_protocol`)
  - `status`, `body_bytes_sent` / `bytes_sent`
  - `http_referer`, `http_user_agent`, `host` / `http_host`
- **Other variables** (e.g. `request_time`, `http_x_forwarded_for`) are stored in `attributes`. A `-` value means absent.
- **Limits:** at most 2000 characters and 60 variables.

### `json`
JSON Lines: one JSON object per line.
- **Nested objects** are flattened to dotted keys, up to depth 3. This means flat application logs and Elastic Common Schema documents both work.
- **Field lookup:** each normalized field is taken from the first key present in its alias list:

| Field | Keys tried (in order) |
|---|---|
| time (required) | `@timestamp`, `timestamp`, `time`, `ts`, `datetime`, `date`, `event.created` |
| source IP | `source.ip`, `client.ip`, `src_ip`, `source_ip`, `client_ip`, `remote_addr`, `remote_ip`, `clientip`, `ip` |
| user | `user.name`, `username`, `user_name`, `user`, `login`, `account` |
| method / path / query | `http.request.method`, `method` … / `url.path`, `path`, `uri`, `url` … / `url.query`, `query` … |
| status | `http.response.status_code`, `status`, `status_code`, `http_status`, `response_code` |
| level / message | `log.level`, `level`, `severity` … / `message`, `msg`, `log`, `text` |
| action / outcome | `event.action`, `event`, `action`, `event_type`, `type` / `event.outcome`, `outcome`, `result` |

- **Timestamps** may be any of:
  - ISO 8601, with or without an offset. Values without an offset use the source time zone.
  - Unix epoch seconds.
  - Unix epoch milliseconds.
- **Classification:**
  - Login-type actions (e.g. `login_failed`, or an `*login*` action with outcome `failure`) become `auth_failure`.
  - A successful login becomes `auth_success`.
  - Lines with an HTTP method or status become `http_request`.
  - Everything else becomes `app_log`.
- **Non-numeric `status`** (e.g. `"ok"`) is treated as the outcome.
- **Rejected lines:** missing timestamp, invalid JSON, a value that isn't an object, or an HTTP status outside 100–599.

### `auth_log` (documented authentication format)
Linux `auth.log` / `secure` lines written by rsyslog. Two header styles are accepted:
```
Oct 10 10:15:32 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2
2026-10-10T10:19:00.123456+05:30 web01 sshd[1270]: Failed password for bob from 198.51.100.7 port 51000 ssh2
```
The traditional header has **no year and no time zone**:
- **Time zone:** the source's configured time zone is used. Set it to the server's zone.
- **Year:** inferred from the upload time. If that would put the event more than a day in the future, the previous year is used. This handles logs that span New Year.

Recognized messages:

| Message | event_type | `attributes.auth_event` |
|---|---|---|
| `Failed password/publickey for [invalid user] X from IP port N` | auth_failure | `failed_password`, … |
| `Accepted password/publickey for X from IP port N` | auth_success | `accepted_publickey`, … |
| `Invalid user X from IP` | auth_failure | `invalid_user` |
| `pam_unix(...): authentication failure; … rhost=IP user=X` | auth_failure | `pam_failure` |
| `maximum authentication attempts exceeded for X from IP` | auth_failure | `max_attempts_exceeded` |
| `sudo: X : … incorrect password attempts` | auth_failure | `sudo_failure` |
| `sudo: X : TTY=… ; USER=root ; COMMAND=…` | auth_success | `sudo_command` |

Any other line with a valid syslog header is kept as `auth_other`. Lines without a valid header are rejected.

## Format detection
A source's format can be `auto`. In that case:
- The first 50 non-blank lines of each file are tried against `json`, `apache_combined`, `nginx_common` and `auth_log`.
- The format that parses the largest share wins, but only if it parses **at least 80%** of the lines and doesn't tie.
- Otherwise the job fails with "Could not detect the log format reliably. Choose the format explicitly."
- `nginx_custom` is never auto-detected.

You can also pick a format per upload, which overrides the source's format.

## Timestamps
- **Normalization:** all times are stored as UTC.
- **Missing offsets:** timestamps without an offset use the source's IANA time zone, e.g. `Asia/Kolkata`. Daylight-saving time is handled.
- **Rejected as implausible:** timestamps before 1990, or more than one day after the upload time.

## Validation, limits and safety

| Check | Behaviour |
|---|---|
| File size | `ST_MAX_UPLOAD_BYTES` (default 50 MB) gives **413**. Oversized bodies are cut off while streaming, before they are fully read |
| File type | Compressed or binary content (gzip, zip, PDF, ELF…), NUL bytes or mostly control characters gives **415**. The content is inspected; the client's Content-Type is ignored |
| Encoding | UTF-8, with or without BOM. Invalid bytes are replaced (U+FFFD), the file is marked `utf-8 (invalid bytes replaced)`, and affected events get `attributes.encoding_replaced` |
| Empty file | **422** |
| Filename | Never used as a path. Files are stored as `storage/files/ab/cd/<sha256>`. The original name is sanitized for display only |
| Same file twice into one source | **409**, identified by SHA-256 |
| Line length | Over `ST_MAX_LINE_BYTES` (16 KB): the line is rejected, and the rest of the file continues |
| Lines per file | `ST_MAX_LINES_PER_FILE` (5,000,000): the job fails after processing that many lines |
| Stored error details | First `ST_MAX_ERRORS_PER_JOB` (10,000) rejected lines. Counts stay exact |
| Integrity | The worker re-checks the stored file's SHA-256 before processing |

Uploaded content is treated as untrusted data. It is never executed or interpreted, and the UI renders it as plain text. The CSV export neutralizes spreadsheet formula injection (cells starting with `=`, `+`, `-` or `@`).

## Duplicate records
An event's fingerprint is **SHA-256(source id, raw line, n)**, where `n` counts earlier identical lines in the same file. The fingerprint is unique in the database. This gives the following behaviour:
- **Overlapping files:** re-importing an overlapping file (e.g. a rotated log that repeats the tail of the previous one) counts the overlapping lines as **duplicates** rather than storing them twice.
- **Repeated lines in one file:** genuinely repeated identical requests inside one file are **all kept**. This matters for burst detection.
- **Bounded memory:** the per-file counter tracks the most recent 200,000 distinct lines. Identical lines further apart than that could be mis-counted as duplicates. With second-resolution timestamps in the line, this is not expected in practice.

## Processing model
- **Upload:** the API stores the file and creates an `ingestion_jobs` row with status `queued`.
- **Worker** (`python -m app.worker`):
  - claims jobs with `SELECT … FOR UPDATE SKIP LOCKED`, so several workers are safe
  - inserts events in batches with `ON CONFLICT (fingerprint) DO NOTHING`
  - updates the job's counters after each batch
- **Job statuses:** `queued` → `running` → one of:
  - `completed`
  - `completed_with_errors`: some lines were rejected
  - `failed`: nothing parsed, a missing or tampered file, an undetectable format, or the line limit was exceeded
- **Retry:** a failed job can be retried. This deletes its partial events and errors first, so reprocessing is idempotent.
- **Crash recovery:** a job whose worker died (no heartbeat for `ST_JOB_STALE_MINUTES`) is requeued, up to `ST_MAX_JOB_ATTEMPTS` attempts.
