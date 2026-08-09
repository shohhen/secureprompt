#!/usr/bin/env bash
#
# Apply the ClickHouse DDL in secureprompt-api/clickhouse/migrations/ over HTTP.
#
# WHY THIS EXISTS: the migrations are applied by the WORKER at boot
# (secureprompt-worker/src/main.rs::apply_migrations), not by the API. CI runs
# tests against the API without ever starting a worker, so without this script
# `tests/clickhouse_schema_probe.rs` (10 tests) and the analytics paths fail on
# a schema mismatch against an empty database.
#
# This is a faithful shell port of apply_migrations(): same lexicographic file
# order, same `_schema_migrations` bookkeeping, same "strip `--` line comments
# BEFORE splitting on `;`" rule. That rule is load-bearing — a comment
# containing a semicolon (001 has several) cuts a statement in half if you
# split first, and ClickHouse then chokes on the orphaned tail.
#
# Env: CLICKHOUSE_URL (default http://localhost:8123)
#      CLICKHOUSE_DB  (default sp_analytics)
#      CLICKHOUSE_MIGRATIONS_DIR (default secureprompt-api/clickhouse/migrations)
set -euo pipefail

CLICKHOUSE_URL="${CLICKHOUSE_URL:-http://localhost:8123}"
CLICKHOUSE_DB="${CLICKHOUSE_DB:-sp_analytics}"
MIGRATIONS_DIR="${CLICKHOUSE_MIGRATIONS_DIR:-secureprompt-api/clickhouse/migrations}"

# WS6-5 turned ClickHouse authentication ON and this script was not updated,
# so every statement started coming back `403` — including the `CREATE DATABASE`
# on line one, which made the failure look like a missing database rather than a
# refused credential. The worker applies the same migrations through the Rust
# client, which DOES authenticate, so the gap only showed up when running the
# script directly (CI, or an operator following the release notes).
#
# Credentials travel in headers, not the URL: `?user=&password=` would land in
# ClickHouse's own query_log and in any proxy access log in front of it.
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"
CH_AUTH=(-H "X-ClickHouse-User: ${CLICKHOUSE_USER}")
if [ -n "${CLICKHOUSE_PASSWORD}" ]; then
  CH_AUTH+=(-H "X-ClickHouse-Key: ${CLICKHOUSE_PASSWORD}")
fi

ch() {
  # $1 = SQL. Fails the script on any non-2xx or ClickHouse-reported error.
  local body
  body=$(curl -sS --fail-with-body "${CH_AUTH[@]}" \
    --data-binary "$1" \
    "${CLICKHOUSE_URL}/?database=${CLICKHOUSE_DB}") || {
      echo "ClickHouse statement failed:" >&2
      echo "  ${1:0:200}" >&2
      echo "  response: ${body}" >&2
      return 1
    }
  printf '%s' "$body"
}

ch_nodb() {
  curl -sS --fail-with-body "${CH_AUTH[@]}" --data-binary "$1" "${CLICKHOUSE_URL}/" >/dev/null
}

echo "==> waiting for ClickHouse at ${CLICKHOUSE_URL}"
for i in $(seq 1 60); do
  if curl -sS -o /dev/null "${CLICKHOUSE_URL}/ping"; then break; fi
  if [ "$i" = 60 ]; then echo "ClickHouse never came up" >&2; exit 1; fi
  sleep 2
done

echo "==> ensuring database ${CLICKHOUSE_DB}"
ch_nodb "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB}"

echo "==> ensuring _schema_migrations"
ch "CREATE TABLE IF NOT EXISTS _schema_migrations (version String, applied_at DateTime DEFAULT now()) ENGINE = MergeTree() ORDER BY version" >/dev/null

applied=0
skipped=0
for path in $(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | sort); do
  version="$(basename "$path")"

  count="$(ch "SELECT count() FROM _schema_migrations WHERE version = '${version}'" | tr -d '[:space:]')"
  if [ "${count:-0}" != "0" ]; then
    echo "    skip   ${version} (already applied)"
    skipped=$((skipped + 1))
    continue
  fi

  # Strip `--` line comments first, then split on `;` — see header.
  stripped="$(sed 's/--.*$//' "$path")"

  # shellcheck disable=SC2001
  echo "$stripped" | tr '\n' ' ' | tr ';' '\n' | while IFS= read -r stmt; do
    trimmed="$(echo "$stmt" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$trimmed" ] && continue
    ch "$trimmed" >/dev/null
  done

  ch "INSERT INTO _schema_migrations (version) VALUES ('${version}')" >/dev/null
  echo "    apply  ${version}"
  applied=$((applied + 1))
done

echo "==> ClickHouse migrations done (applied=${applied} skipped=${skipped})"

# Fail loudly if the schema the tests probe is still missing, rather than
# letting the suite fail later with a confusing column error.
for tbl in request_events token_usage policy_events latency_samples; do
  n="$(ch "SELECT count() FROM system.tables WHERE database = '${CLICKHOUSE_DB}' AND name = '${tbl}'" | tr -d '[:space:]')"
  if [ "$n" != "1" ]; then
    echo "FAIL: expected table ${CLICKHOUSE_DB}.${tbl} to exist after migrations" >&2
    exit 1
  fi
done
echo "==> schema verified"
