#!/usr/bin/env bash
# check-mart-only.sh — CI gate for analytics.rs mart-only FROM clauses.
#
# Runs ripgrep on ONLY secureprompt-api/src/http/routes/dashboard/analytics.rs
# (NOT the entire dashboard/ directory — Pitfall #5 in 05-PATTERNS.md).
# Fails if any raw/staging table reference is found.
set -euo pipefail

FILE="secureprompt-api/src/http/routes/dashboard/analytics.rs"

if [ ! -f "$FILE" ]; then
    echo "ERROR: $FILE not found — was it created?" >&2
    exit 1
fi

# Fail if any raw or staging table reference is found.
if rg -n 'FROM\s+(request_events|policy_events|latency_samples|token_usage|stg_|raw\.|_raw)' "$FILE"; then
    echo "ERROR: $FILE must only SELECT from mart_* tables" >&2
    exit 1
fi

# Warn (but do not fail) if no mart_ reference found at all — likely a stub.
if ! rg -q 'FROM\s+mart_' "$FILE"; then
    echo "WARNING: $FILE has no mart_ reference — unexpected" >&2
fi

echo "check-mart-only: OK — $FILE contains only mart_* FROM clauses"
