#!/usr/bin/env bash
#
# SecurePrompt clippy gate (WS6-1) — deny-by-default with an explicit,
# enumerated debt allowlist.
#
# WHY NOT `cargo clippy --workspace -- -D warnings`:
#   Cargo.toml sets `[workspace.lints.clippy] pedantic = "warn"` and
#   `nursery = "warn"`. Measured on this workspace, plain clippy emits 631
#   warnings, essentially all pedantic/nursery style opinions. `-D warnings`
#   promotes every one of them to an error, so that command fails on
#   secureprompt-common before it even reaches the API crate. That is precisely
#   what `.github/workflows/phase-05-ci.yml` Gate 2 ran, and it is why nobody
#   looked at it.
#
# WHAT THIS RUNS INSTEAD:
#   `-D warnings` (so anything new is a hard failure) with pedantic and nursery
#   dialled back to advisory, plus a NAMED allowlist of the 19 default-level
#   lints that the tree currently trips. Measured: 44 default-level warnings
#   across those 19 lints. Each is listed individually rather than hidden
#   behind a category, so the list is reviewable, greppable, and shrinks
#   file-by-file as debt is paid.
#
#   The point of the allowlist being explicit: introduce a NEW default-level
#   clippy lint — including a real bug class like `clippy::await_holding_lock`
#   in a file that does not have it today — and the gate fails, because the
#   lint fires somewhere the allowlist does not cover... with the honest caveat
#   below.
#
# HONEST CAVEAT: `-A <lint>` is workspace-wide, not per-file. Allowlisting
#   `clippy::await_holding_lock` to accommodate the one existing occurrence
#   means a NEW occurrence elsewhere also passes. The allowlist is a ledger of
#   debt, not a per-site suppression. Shrinking it is the fix; the highest-value
#   entry to retire first is `await_holding_lock` (1 site), then
#   `result_large_err` (1) — those two are behavioural, the rest are cosmetic.
#
# TO PAY DOWN DEBT: fix every occurrence of a lint, delete its `-A` line, and
# the gate then enforces it forever.
set -euo pipefail

cd "$(dirname "$0")/../.."

# SQLX_OFFLINE: clippy must not need a live Postgres to expand the sqlx macros.
# The cached query metadata lives in .sqlx/sqlx-data.json.
export SQLX_OFFLINE="${SQLX_OFFLINE:-true}"

exec cargo clippy --workspace --all-targets -- \
  -D warnings \
  `# Style opinions, advisory only — see header.` \
  -A clippy::pedantic \
  -A clippy::nursery \
  `# --- default-level debt allowlist (44 occurrences / 19 lints) --------` \
  `# behavioural — retire these first` \
  -A clippy::await_holding_lock \
  -A clippy::result_large_err \
  `# correctness-adjacent but cosmetic in context` \
  -A clippy::assertions_on_constants \
  -A clippy::clone_on_copy \
  -A clippy::field_reassign_with_default \
  -A clippy::match_like_matches_macro \
  -A clippy::redundant_closure \
  -A clippy::single_match \
  -A clippy::unnecessary_map_or \
  -A clippy::manual_repeat_n \
  -A clippy::manual_str_repeat \
  -A clippy::too_many_arguments \
  -A clippy::module_inception \
  -A clippy::double_must_use \
  `# rustdoc formatting` \
  -A clippy::doc_lazy_continuation \
  -A clippy::doc_overindented_list_items \
  -A clippy::empty_line_after_doc_comments \
  `# test-support helpers that only some suites use` \
  -A dead_code \
  -A unused_imports
