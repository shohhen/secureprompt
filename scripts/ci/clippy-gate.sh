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
#   dialled back to advisory, plus a NAMED allowlist of the default-level lints
#   that the tree currently trips. Each is listed individually rather than
#   hidden behind a category, so the list is reviewable, greppable, and shrinks
#   file-by-file as debt is paid.
#
#   MEASURED 2026-08-02 (`cargo clippy --workspace --all-targets --
#   -A clippy::pedantic -A clippy::nursery`, counted from the JSON output):
#   117 default-level warnings across 17 lints. The header said "44 across
#   those 19", which was stale in both numbers and in the count of lints: two
#   allowlisted entries — `clone_on_copy` and `field_reassign_with_default` —
#   had ZERO occurrences and have been retired, so the gate now enforces them.
#   The largest remaining entries are `dead_code` (39) and
#   `too_many_arguments` (32).
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
  `# --- default-level debt allowlist (117 occurrences / 17 lints) -------` \
  `# behavioural — retire these first` \
  -A clippy::await_holding_lock \
  -A clippy::result_large_err \
  `# THIS ONE IS NOT COSMETIC, and it was filed as such.` \
  `# assertions_on_constants is the lint that fires on a constant compared` \
  `# against itself — one of the vacuous-test shapes the MR2/MR3 reviews` \
  `# found in this tree by hand. Allowlisting it means the gate cannot.` \
  `# MEASURED: 6 occurrences, at jwt_auth.rs:1018, request_hygiene.rs:280,` \
  `# telemetry.rs:103-105 and tests/inbound_deadline_streaming.rs:120.` \
  `# Retiring it is a 6-site job across the middleware and telemetry` \
  `# surfaces and is the highest-value entry left on this list.` \
  -A clippy::assertions_on_constants \
  `# cosmetic in context` \
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
  `# dead_code / unused_imports — NOT "test-support helpers that only some` \
  `# suites use", which is what this heading used to say. MEASURED: 39` \
  `# dead_code sites, and four of them are production items with zero` \
  `# callers, not test scaffolding:` \
  `#   analytics/dashboard_reader.rs:656  fn map_ch_error` \
  `#   http/middleware/api_key_auth.rs:88 fn make_headers` \
  `#   secureprompt-mcp/src/main.rs:97    field tool_router` \
  `# (two more were fixed rather than excused: the worker's STATUS_QUEUED,` \
  `# which only the tests use and is now #[cfg(test)], and a zero-caller` \
  `# helper in tests/leak_report.rs, deleted.) dead_code detects a` \
  `# zero-caller function, which is` \
  `# exactly the shape behind the documented false comment "used by the` \
  `# logout handler" on a function nobody called. The rest genuinely are` \
  `# tests/support/mod.rs helpers used by a subset of suites.` \
  -A dead_code \
  -A unused_imports
