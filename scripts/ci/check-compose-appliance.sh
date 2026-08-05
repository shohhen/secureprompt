#!/usr/bin/env bash
#
# check-compose-appliance.sh — WS6-5.
#
# WHY THIS EXISTS
# ---------------
# The PRD makes the Compose single-VM appliance the PRIMARY documented install
# path — the one that matches actual bank installs. Nothing in this pipeline
# had ever rendered a compose file. `helm-render` exists because grep could not
# see a Helm conditional; `${VAR:-default}` interpolation, `extends`, and
# multi-file overlays are exactly the same class of thing, and
# docker-compose.onprem.yml is an OVERLAY whose merged result nobody had looked
# at.
#
# STATE AT fb5e1df, rendered with `docker compose config`:
#   * redis (valkey 8.1.6) — no --requirepass. Any process that can reach
#     6379 is authenticated. Port 6379 is PUBLISHED to the host.
#   * clickhouse — CLICKHOUSE_USER=default with no password. Ports 8123/9000
#     PUBLISHED. Measured against the pinned image: `curl --data 'SELECT 1'
#     http://localhost:8123/` returns 200 and the answer.
#   * 0 of 16 services carried any cpu or memory limit. One runaway container
#     takes the appliance VM down with it, and the ML sidecar peaks at ~5 GB
#     while loading four models.
#   * docker-compose.onprem.yml pins api/worker/web/prometheus/alertmanager to
#     `pull_policy: never` but leaves secureprompt-ml, clickhouse, postgres,
#     redis, qdrant, grafana and the librechat trio on `build:`/registry pulls,
#     so an air-gapped host cannot bring the full file up.
#
# WHAT THIS ASSERTS
#   1. Every compose file, and the base+onprem overlay, renders (`config -q`).
#   2. Every service in the primary appliance file has a memory AND a cpu
#      limit.
#   3. Redis requires a password, and every consumer's REDIS_URL carries one.
#   4. ClickHouse requires a password, and every Rust consumer carries
#      CLICKHOUSE_USER + CLICKHOUSE_PASSWORD.
#   5. The redis healthcheck is not vacuous. MEASURED: under --requirepass,
#      `redis-cli ping` prints "NOAUTH Authentication required." and EXITS 0,
#      so the healthcheck the stack shipped would have reported a
#      password-protected-but-unreachable Redis as healthy.
#   6. In the air-gap overlay every service resolves to an `image:` with a
#      non-pulling policy — nothing may be left on `build:`.
#   7. PREMISE: the render contains the api service. An empty render would
#      satisfy 2-6 for free.
set -uo pipefail

cd "$(dirname "$0")/../.."

if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: 'docker compose' is not available — this check cannot be skipped silently." >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is not on PATH — this check parses the rendered compose, it does not grep it." >&2
    exit 2
fi

# `docker compose config` interpolates ${VAR:?...}, so the required secrets
# must be present. Use throwaway values: this renders, it does not run.
# Deliberately NOT sourcing a developer .env — the render must be reproducible.
export SECUREPROMPT_APP_DB_PASSWORD="render-only-not-a-secret"
export SECUREPROMPT_JWT_SECRET="render-only-not-a-secret"
export SECUREPROMPT_PROVIDER_KEY="render-only-not-a-secret-2"
export ML_SIDECAR_INTERNAL_TOKEN="render-only-not-a-secret"
export KMS_FILE_KEY="cmVuZGVyLW9ubHktbm90LWEtc2VjcmV0LTMyYnl0ZXMh"
export NEXTAUTH_SECRET="render-only-not-a-secret"
export REDIS_PASSWORD="render-only-not-a-secret"
export CLICKHOUSE_PASSWORD="render-only-not-a-secret"

FAIL=0

render() {
    # shellcheck disable=SC2068
    docker compose $@ config 2>/dev/null
}

check() {
    local label="$1" mode="$2"; shift 2
    local rendered
    rendered="$(render "$@")"
    if [ -z "$rendered" ]; then
        echo "ERROR: [$label] docker compose config produced nothing." >&2
        # Re-run without suppression so the operator sees why.
        # shellcheck disable=SC2068
        docker compose $@ config >/dev/null || true
        FAIL=1
        return
    fi
    if ! printf '%s\n' "$rendered" | python3 scripts/ci/compose_appliance_lib.py "$label" "$mode"; then
        FAIL=1
    fi
}

# The primary appliance file — full assertions.
check "docker-compose.yml (appliance)" full          -f docker-compose.yml
# The air-gap overlay — must additionally leave nothing on `build:`.
check "onprem overlay"                 airgap        -f docker-compose.yml -f docker-compose.onprem.yml
# The cut-down evaluation profile — renders and limits only. It deliberately
# ships no ML sidecar and no ClickHouse, so the datastore-auth assertions do
# not apply to services it does not have; the ones it DOES have are checked.
check "docker-compose.simple.yml"      simple        -f docker-compose.simple.yml

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "compose appliance OK: all files render; limits, datastore auth and air-gap pinning hold."
