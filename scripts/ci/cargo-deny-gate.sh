#!/usr/bin/env bash
#
# SecurePrompt cargo-deny gate (WS6-2).
#
# Runs all four cargo-deny checks — advisories, bans, licenses, sources —
# against deny.toml. The policy, the measured baseline and the reason for every
# `ignore` entry live in deny.toml, next to the thing they configure; this
# script is only the runner, plus the one piece of judgement below.
#
# ---------------------------------------------------------------------------
# THE ADVISORY DATABASE IS A THIRD-PARTY NETWORK DEPENDENCY, AND IS TREATED
# LIKE ONE.
#
# `cargo deny check advisories` needs https://github.com/rustsec/advisory-db.
# That host is not ours. If reaching it is a hard failure, then a GitHub outage
# turns every merge request in this repository red without anyone having
# changed a line — which is the exact shape `.gitlab-ci.yml`'s `bench` job
# declines to take on ("goes red for a noisy neighbour, a cold cache or a slow
# spot instance ... a flaky gate does not just fail to catch regressions — it
# teaches people to ignore the gates beside it"), and the shape that emptied
# .github/workflows-retired/.
#
# THIS WAS NOT HYPOTHETICAL WHEN THE SCRIPT WAS WRITTEN. The first version of
# this file did hard-fail on a failed fetch, and on 2026-08-04 it fired for
# real on the author's machine:
#     fatal: unable to access 'https://github.com/RustSec/advisory-db/':
#     Failed to connect to github.com port 443 after 2032 ms
# with a perfectly good database already on disk. That is the bug this
# structure fixes.
#
# SO:
#   fetch succeeds            -> check against a fresh database.
#   fetch fails, DB on disk   -> check against the cached database, and say
#                                LOUDLY how old it is. Everything known as of
#                                that date is still enforced; only advisories
#                                published since are missed.
#   fetch fails, no DB at all -> FAIL. Nothing was checked, and a green result
#                                would be a lie.
# An actual advisory always fails the gate. Only the *freshness* of the
# database degrades to a warning.
# ---------------------------------------------------------------------------
set -uo pipefail

cd "$(dirname "$0")/../.."

if [ ! -f deny.toml ]; then
  echo "FAIL: deny.toml missing — the gate will not run without a policy." >&2
  exit 2
fi

echo "cargo-deny: $(cargo deny --version)"

# `db` is the RustSec advisory database. (`cargo deny fetch`'s valid sources are
# db, index, std-replacement, all — `advisories` is NOT one of them and exits 1
# with "invalid value", which is how this guard was first proven to fire.)
# `check_args` is empty on the happy path. When the fetch fails we add
# `--offline`, because `cargo deny check` otherwise re-attempts the same fetch
# itself and dies — measured: without it the degraded path printed the warning
# below and then still failed with "produced no four-check summary", because
# cargo-deny aborted before running a single check.
check_args=()

if cargo deny fetch db; then
  echo "advisory-db: fetched."
else
  # cargo-deny clones the database under $CARGO_HOME/advisory-dbs/.
  db_root="${CARGO_HOME:-$HOME/.cargo}/advisory-dbs"
  db_dir="$(find "$db_root" -maxdepth 1 -type d -name 'advisory-db-*' 2>/dev/null | head -1)"

  if [ -z "$db_dir" ] || [ ! -d "$db_dir/.git" ]; then
    echo >&2
    echo "FAIL: the RustSec advisory database could not be fetched AND no" >&2
    echo "      cached copy exists at ${db_root}." >&2
    echo "      Nothing would be audited, so this is a hard failure rather" >&2
    echo "      than a green run. Check the runner's egress to github.com." >&2
    exit 2
  fi

  check_args+=(--offline)
  db_date="$(git -C "$db_dir" log -1 --format=%cs 2>/dev/null || echo unknown)"
  echo
  echo "=================================================================="
  echo "WARNING: could not fetch the RustSec advisory database."
  echo "         Auditing against the CACHED copy, last updated ${db_date}."
  echo "         Advisories published after that date are NOT covered by"
  echo "         this run. This is deliberately a warning and not a failure:"
  echo "         see this script's header."
  echo "=================================================================="
  echo
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# One invocation, so the summary line reports all four checks together and a
# failure in one does not hide the state of the others.
cargo deny "${check_args[@]+"${check_args[@]}"}" check 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"

echo
# cargo-deny's last line is of the form
#   "advisories ok, bans ok, licenses ok, sources ok"
# A run that produced no such line did not complete, whatever its exit code.
# Without this, a cargo-deny that died early could exit 0 and be read as green
# — the same "0 passed, exit 0" trap the test:audit-export-doc job guards
# against with `grep -q "2 passed"`.
if ! grep -qE 'advisories (ok|FAILED), bans (ok|FAILED), licenses (ok|FAILED), sources (ok|FAILED)' "$log"; then
  echo "FAIL: cargo-deny produced no four-check summary — it did not complete." >&2
  exit 2
fi

if [ "$status" -ne 0 ]; then
  echo "FAIL: cargo-deny reported a violation (see above)."
  echo
  echo "  advisories  a NEW RustSec advisory affects a crate in Cargo.lock."
  echo "              Prefer the fix: cargo-deny prints a Solution: line, and"
  echo "              three of the six advisories present when this gate landed"
  echo "              were patch-level bumps. Only if 'No safe upgrade is"
  echo "              available!' add an [advisories] ignore entry — WITH the"
  echo "              RUSTSEC id, today's date, the measured reason, and what"
  echo "              would retire it. See deny.toml's header for the rule."
  echo "  licenses    a dependency carries a licence not in the allow list."
  echo "              Do not add copyleft to that list without a decision"
  echo "              recorded outside this repo."
  echo "  sources     a git dependency from a host that is not sp-license."
  echo "              Treat as hostile until proven otherwise."
  echo "  bans        a wildcard version on a registry dependency."
  exit "$status"
fi

echo "OK: cargo-deny clean (advisories, bans, licenses, sources)."
