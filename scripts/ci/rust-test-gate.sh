#!/usr/bin/env bash
#
# SecurePrompt Rust test gate (WS6-1).
#
# Runs every test binary in the workspace ONE AT A TIME, reports all of them,
# and cross-checks every skipped test against scripts/ci/quarantine.tsv.
#
# =============================================================================
# READ THIS BEFORE "OPTIMISING" THE SCRIPT. Each rule below is here because it
# already cost this project debugging time. None of them is hypothetical.
# =============================================================================
#
# RULE 1 — Never rely on a single `cargo test -p <pkg>` invocation.
#   cargo is fail-fast ACROSS test binaries: the first binary that fails aborts
#   the run and every later binary is never executed, so its results never
#   appear. Measured on this workspace: `cargo test -p secureprompt-api`
#   exited 101 after reporting 9 of 15 binaries and "3 failed". The true count
#   was 6, across 4 suites. Three real failures were invisible.
#   → This script runs each binary in its own cargo invocation and keeps going
#     (`rc` accumulated in FAILED_SUITES), so every suite always reports.
#
# RULE 2 — Never use bare `--no-fail-fast` across the package.
#   It is the obvious fix for Rule 1 and it is a trap. It does not serialise
#   anything: cargo still launches all test binaries CONCURRENTLY, and every
#   `#[sqlx::test]` provisions its own throwaway database. Postgres runs out of
#   backends and the run produces ~111 spurious `PoolTimedOut` failures that
#   have nothing to do with the code under test.
#   → This script gets Rule 1's benefit by looping, not by --no-fail-fast.
#
# RULE 3 — Never run two test binaries against one Postgres at the same time.
#   sqlx test-database CREATE/DROP contends across concurrent cargo processes.
#   Measured: the same database-backed test took 2.00s and passed when run
#   alone, and 60.03s and FAILED under contention — with Postgres sitting at
#   only 6 of 100 connections, so it is lock/catalog contention, not pool
#   exhaustion, and raising max_connections does not help.
#   → The loop below is strictly sequential, and TEST_THREADS bounds the
#     in-binary concurrency too. Do not add `&`, `xargs -P`, or a CI matrix
#     that shards these onto parallel jobs sharing one database.
#
# Env:
#   DATABASE_URL, REDIS_URL, CLICKHOUSE_URL, CLICKHOUSE_DB — service endpoints.
#   TEST_THREADS — in-binary test concurrency (default 4). See Rule 3.
set -uo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
QUARANTINE_FILE="scripts/ci/quarantine.tsv"
TEST_THREADS="${TEST_THREADS:-4}"

# --------------------------------------------------------------------------
# Suite discovery. Deliberately derived from the filesystem rather than a
# hand-maintained list: a newly added tests/*.rs is gated automatically, so
# nobody can add a test file that quietly never runs.
# --------------------------------------------------------------------------
SUITES=()
for pkg in secureprompt-common secureprompt-api; do
  SUITES+=("-p ${pkg} --lib")
  if [ -d "${pkg}/tests" ]; then
    for f in "${pkg}"/tests/*.rs; do
      [ -e "$f" ] || continue
      SUITES+=("-p ${pkg} --test $(basename "$f" .rs)")
    done
  fi
done
# Binary-only crates: their tests live in src/ behind #[cfg(test)].
for pkg in secureprompt-worker secureprompt-mcp sp-agent; do
  SUITES+=("-p ${pkg} --bins")
done

# --------------------------------------------------------------------------
# Quarantine manifest: expected `ignored` count per cargo selector.
# Looked up with awk rather than an associative array so this runs on bash 3.2
# (macOS /bin/bash) as well as the bash 5 in the CI image — a gate you cannot
# reproduce on your laptop is a gate nobody trusts.
# --------------------------------------------------------------------------
if [ ! -f "$QUARANTINE_FILE" ]; then
  echo "FAIL: ${QUARANTINE_FILE} is missing. The gate refuses to run without" >&2
  echo "      a quarantine manifest — that is how skips stay visible." >&2
  exit 2
fi

expected_ignored_for() {
  awk -F'\t' -v want="$1" '
    /^[[:space:]]*(#|$)/ { next }
    $1 == want { n++ }
    END { print n + 0 }
  ' "$QUARANTINE_FILE"
}

# Every selector named in the manifest must be one the gate actually runs,
# otherwise a typo'd row silently excuses nothing and hides a real skip.
awk -F'\t' '/^[[:space:]]*(#|$)/ { next } { print $1 }' "$QUARANTINE_FILE" | sort -u > "${TMPDIR:-/tmp}/ws61_manifest_selectors"

echo "============================================================"
echo " QUARANTINED / SKIPPED TESTS — these are NOT gating this MR"
echo "============================================================"
grep -vE '^\s*(#|$)' "$QUARANTINE_FILE" | awk -F'\t' '{printf "  [%s] %s\n      %s\n      %s\n", $3, $2, $1, $4}'
echo "  (full rationale + follow-up: ${QUARANTINE_FILE})"
echo

# --------------------------------------------------------------------------
# Sequential run. See Rules 1-3.
# --------------------------------------------------------------------------
FAILED_SUITES=()
MANIFEST_DRIFT=()
: > "${TMPDIR:-/tmp}/ws61_gate_selectors"
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_IGNORED=0

for suite in "${SUITES[@]}"; do
  log="$(mktemp)"
  start=$(date +%s)
  # shellcheck disable=SC2086
  cargo test $suite -- --test-threads="${TEST_THREADS}" >"$log" 2>&1
  rc=$?
  dur=$(( $(date +%s) - start ))

  result_line="$(grep -E '^test result:' "$log" | tail -1)"
  passed=$(sed -nE 's/.* ([0-9]+) passed.*/\1/p' <<<"$result_line")
  failed=$(sed -nE 's/.* ([0-9]+) failed.*/\1/p' <<<"$result_line")
  ignored=$(sed -nE 's/.* ([0-9]+) ignored.*/\1/p' <<<"$result_line")
  passed=${passed:-0}; failed=${failed:-0}; ignored=${ignored:-0}

  TOTAL_PASS=$((TOTAL_PASS + passed))
  TOTAL_FAIL=$((TOTAL_FAIL + failed))
  TOTAL_IGNORED=$((TOTAL_IGNORED + ignored))

  if [ "$rc" -eq 0 ]; then
    printf 'PASS  %4ds  %-52s %s pass / %s ignored\n' "$dur" "$suite" "$passed" "$ignored"
  else
    printf 'FAIL  %4ds  %-52s %s pass / %s fail / %s ignored\n' \
      "$dur" "$suite" "$passed" "$failed" "$ignored"
    FAILED_SUITES+=("$suite")
    echo "----- failure detail: $suite -----"
    sed -n '/^failures:$/,$p' "$log" | head -60
    echo "----- end detail -----"
  fi

  # Quarantine cross-check: cargo's own `N ignored` must equal the number of
  # rows the manifest declares for this selector. An undeclared #[ignore] is a
  # silent skip and fails the gate; a stale manifest row does too.
  expected="$(expected_ignored_for "$suite")"
  echo "$suite" >> "${TMPDIR:-/tmp}/ws61_gate_selectors"
  if [ "$ignored" != "$expected" ]; then
    MANIFEST_DRIFT+=("$suite: cargo reports ${ignored} ignored, ${QUARANTINE_FILE} declares ${expected}")
  fi

  rm -f "$log"
done

# A manifest row naming a selector the gate never runs excuses nothing while
# looking like it does. Treat it as drift.
while IFS= read -r sel; do
  # `--` is required: every selector starts with `-p`, which grep would
  # otherwise parse as an option.
  if ! grep -Fxq -- "$sel" "${TMPDIR:-/tmp}/ws61_gate_selectors"; then
    MANIFEST_DRIFT+=("${QUARANTINE_FILE} names selector '${sel}', which this gate never runs")
  fi
done < "${TMPDIR:-/tmp}/ws61_manifest_selectors"

echo
echo "============================================================"
printf ' TOTAL: %d passed, %d failed, %d ignored (quarantined)\n' \
  "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_IGNORED"
echo "============================================================"

status=0

if [ "${#MANIFEST_DRIFT[@]}" -gt 0 ]; then
  echo
  echo "FAIL: quarantine manifest drift — a test is being skipped without being"
  echo "      declared, or a declaration outlived the skip. Fix ${QUARANTINE_FILE}"
  echo "      and the #[ignore] attribute together."
  printf '  - %s\n' "${MANIFEST_DRIFT[@]}"
  status=1
fi

if [ "${#FAILED_SUITES[@]}" -gt 0 ]; then
  echo
  echo "FAIL: ${#FAILED_SUITES[@]} suite(s) failed:"
  printf '  - %s\n' "${FAILED_SUITES[@]}"
  status=1
fi

[ "$status" -eq 0 ] && echo && echo "OK: all suites green."
exit "$status"
