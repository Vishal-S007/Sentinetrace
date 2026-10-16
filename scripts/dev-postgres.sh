#!/usr/bin/env bash
# Start a local PostgreSQL 16 cluster for development/testing WITHOUT Docker.
# Data lives in ./.pgdata (git-ignored). Safe to re-run: it only initialises once.
#
# Usage:   scripts/dev-postgres.sh start|stop|status
# Env:     ST_PG_PORT (default 5432), ST_PG_PASSWORD (required on first start),
#          ST_PG_DATA (default ./.pgdata)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${ST_PG_DATA:-$ROOT/.pgdata}"
PORT="${ST_PG_PORT:-5432}"
DB_USER="sentineltrace"

find_bin() {
  if command -v pg_ctl >/dev/null 2>&1; then dirname "$(command -v pg_ctl)"; return; fi
  for d in /usr/lib/postgresql/16/bin /opt/homebrew/opt/postgresql@16/bin \
           /usr/local/opt/postgresql@16/bin; do
    [[ -x "$d/pg_ctl" ]] && { echo "$d"; return; }
  done
  echo "PostgreSQL 16 server binaries not found (need pg_ctl/initdb)." >&2; exit 1
}
BIN="$(find_bin)"

# PostgreSQL refuses to run as root; drop to the 'postgres' user if needed.
as_pg() {
  if [[ $EUID -eq 0 ]]; then
    chown -R postgres "$DATA" 2>/dev/null || true
    runuser -u postgres -- "$@"
  else
    "$@"
  fi
}

# When run as root the server runs as 'postgres', which must be able to reach $DATA.
check_access() {
  [[ $EUID -eq 0 ]] || return 0
  local parent; parent="$(dirname "$DATA")"
  if ! runuser -u postgres -- test -x "$parent"; then
    echo "The 'postgres' user cannot reach $parent (a parent directory is private)." >&2
    echo "Clone the project somewhere it can reach, or set ST_PG_DATA to such a directory." >&2
    exit 1
  fi
}

case "${1:-}" in
  start)
    check_access
    if [[ ! -f "$DATA/PG_VERSION" ]]; then
      : "${ST_PG_PASSWORD:?Set ST_PG_PASSWORD for the first start}"
      mkdir -p "$DATA"; chmod 700 "$DATA"
      pwfile="$(mktemp)"; printf '%s' "$ST_PG_PASSWORD" > "$pwfile"
      [[ $EUID -eq 0 ]] && chown postgres "$DATA" "$pwfile"
      as_pg "$BIN/initdb" -D "$DATA" -U "$DB_USER" -A scram-sha-256 \
        --pwfile="$pwfile" --encoding=UTF8 >/dev/null
      rm -f "$pwfile"
      echo "Initialised cluster in $DATA (superuser: $DB_USER)"
    fi
    as_pg "$BIN/pg_ctl" -D "$DATA" -o "-p $PORT -k /tmp -c listen_addresses=127.0.0.1" \
      -l "$DATA/server.log" -w start
    for db in sentineltrace sentineltrace_test; do
      PGPASSWORD="${ST_PG_PASSWORD:-}" psql -h 127.0.0.1 -p "$PORT" -U "$DB_USER" -d postgres \
        -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1 \
        || PGPASSWORD="${ST_PG_PASSWORD:-}" createdb -h 127.0.0.1 -p "$PORT" -U "$DB_USER" "$db"
    done
    echo "PostgreSQL ready on 127.0.0.1:$PORT (databases: sentineltrace, sentineltrace_test)"
    ;;
  stop)   as_pg "$BIN/pg_ctl" -D "$DATA" -m fast stop ;;
  status) as_pg "$BIN/pg_ctl" -D "$DATA" status ;;
  *) echo "Usage: $0 start|stop|status" >&2; exit 2 ;;
esac
