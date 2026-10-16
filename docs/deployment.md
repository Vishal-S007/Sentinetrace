# Deployment and Hardening Guide

SentinelTrace is a **local MVP**: it has been run and tested on a developer machine, in CI and with Docker Compose. It has not been load-tested, penetration-tested or operated in production. This guide covers what to change before running it anywhere shared, and what it does not do yet.

## What runs

| Service | Image / command | Purpose |
|---|---|---|
| `frontend` | nginx serving the built SPA | Static files, security headers, proxies `/api` to the backend. The only published port, bound to `127.0.0.1:8080` by default. |
| `backend` | `uvicorn app.main:app` | REST API. Runs `alembic upgrade head` on start. |
| `worker` | `python -m app.worker` | Imports uploaded files and runs detection. Can be scaled: `docker compose up -d --scale worker=3` (jobs are claimed with `FOR UPDATE SKIP LOCKED`). |
| `db` | `postgres:16-alpine` | All state. Not published to the host. |

Uploads live in the `storage` volume, shared by the backend and the worker.

## Before exposing it to a network

1. **HTTPS.** Put a TLS-terminating reverse proxy (Caddy, Traefik, nginx, a cloud load balancer) in front of the `frontend` container. Keep port 8080 bound to `127.0.0.1` or a private network.
2. **`ST_ENVIRONMENT=production`.** This makes session and CSRF cookies `Secure`, so browsers only send them over HTTPS. It is the only behaviour this setting changes. You can also set `ST_COOKIE_SECURE=true` directly.
3. **HSTS.** Add `Strict-Transport-Security: max-age=31536000` at the TLS proxy once HTTPS works. It is not sent by default, because it would break plain-HTTP local use.
4. **Forwarded IPs.** The backend trusts `X-Forwarded-For` from any address (`FORWARDED_ALLOW_IPS: "*"` in Compose), because only the nginx container can reach it. If you change the network layout, restrict this to your proxy's address. Login rate limiting per IP depends on it.
5. **Secrets.**
   - Generate `ST_PG_PASSWORD` randomly and keep `.env` out of version control (it is git-ignored).
   - No other secrets are needed: session tokens are random and stored only as SHA-256 hashes.
6. **API docs.** `/api/docs` and `/api/openapi.json` require no login; they describe the API but expose no data. Block them at the proxy if you do not want the API shape public.
7. **First admin.** Create it with `docker compose exec backend python -m app.cli create-admin --username <name>` and a strong password (12+ characters). Give everyone else the lowest role they need (viewer, analyst).

## Database

- **Least privilege (recommended, not configured by default).**
  - Compose connects as the database owner, which can also disable triggers.
  - For a stronger audit guarantee, run migrations as the owner but run the app as a role with only `SELECT, INSERT, UPDATE, DELETE` on the tables. With that role it could not alter the triggers that make `audit_log` and `investigation_notes` append-only.
- **Backups.**
  - Back up the database and the upload storage together:
    ```bash
    docker compose exec -T db pg_dump -U sentineltrace -Fc sentineltrace > sentineltrace-$(date +%F).dump
    docker run --rm -v sentineltrace_storage:/data -v "$PWD":/backup alpine tar czf /backup/storage-$(date +%F).tgz -C /data .
    ```
  - Restore with `pg_restore --clean` into an empty database, then put the storage files back.
  - Test restores. Uploads are optional for viewing data (events are in the database), but are needed to re-process a failed import.
- **Size.**
  - Events are the large table. It has a BRIN index on time and B-tree indexes on IP, type and status, plus a trigram index for text search.
  - Use [data retention](../README.md#data-retention) to bound growth, or let the worker purge daily with `ST_RETENTION_AUTO_DAYS`.

## Upgrades

1. Back up (above).
2. `git pull`, then `docker compose up -d --build`. The backend applies any new migrations on start; watch `docker compose logs backend`.
3. Every migration has a downgrade, so `docker compose exec backend alembic downgrade -1` reverses one migration. Restoring the backup is the safer rollback.

## Monitoring

- **Endpoints:** `GET /api/health` (process alive) and `GET /api/ready` (database reachable; returns `503` when it is not). Successful checks are not written to the access log.
- **Worker:** a container health check reads a heartbeat file the worker updates after each database poll. When the database is down the worker logs `Worker iteration failed … retrying` with growing back-off, and recovers by itself.
- **In the app:** **Settings & status** (admins) shows database size, row counts, queued, running and failed imports, the last detection run, upload storage and free disk.
- **Logs:**
  - Logs go to stdout and stderr; collect them with your container platform.
  - API errors are logged with a request ID, which is also returned to the client.

## Limits and settings

All settings are environment variables prefixed `ST_` (see `.env.example`), and their effective values are listed on **Settings & status**. Ones worth reviewing:

| Setting | Default | Note |
|---|---|---|
| `ST_MAX_UPLOAD_BYTES` | 50 MB | Keep nginx `client_max_body_size` (60 MB) above it |
| `ST_MAX_LINES_PER_FILE` | 5,000,000 | Larger files fail with partial counts |
| `ST_SESSION_IDLE_MINUTES` / `ST_SESSION_ABSOLUTE_HOURS` | 60 / 12 | |
| `ST_LOGIN_MAX_FAILURES_PER_USER` / `_PER_IP` | 5 / 20 per 15 min | |
| `ST_EXPORT_RATE_PER_MINUTE` | 10 | Exports and incident reports per user |
| `ST_RETENTION_AUTO_DAYS` | off | Daily automatic purge |

## Known limitations

- **No single sign-on, MFA or password reset by email.** Admins set passwords; users change their own.
- **No live log streaming.** Logs are imported as files, and detection runs after each import.
- **Detection is rule-based** and tuned on synthetic data. Thresholds need adjusting for real traffic; expect false positives and misses.
- **One API process** by default. The per-user export limit and login limits are database-backed, so more API processes would still share them, but this has not been load-tested.
- **The audit log is never purged.** Archive it externally if it grows too large.
