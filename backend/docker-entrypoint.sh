#!/bin/sh
# Apply database migrations, then start the API.
set -e
/app/.venv/bin/alembic upgrade head
exec /app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers
