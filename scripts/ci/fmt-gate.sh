#!/usr/bin/env bash
#
# SecurePrompt rustfmt gate (WS6-1) — ratcheting, not big-bang.
#
# WHY NOT PLAIN `cargo fmt --all --check`:
#   Measured on fix/ws1-security-cluster: 83 files / 432 hunks of pre-existing
#   drift. Turning that into a required check on day one gives you a stage that
#   is red on every MR from the first minute, which is exactly the failure this
#   workstream exists to end — a permanently-red gate teaches everyone to scroll
#   past failures. Reformatting all 83 in this MR is also off the table: it
#   would bury the CI change under thousands of unrelated diff lines.
#
# WHAT THIS DOES INSTEAD:
#   fmt-baseline.txt records the files that were already unformatted when the
#   gate landed. The gate fails if
#     (a) a file NOT in the baseline is unformatted — all new and newly touched
#         code must be `cargo fmt` clean; or
#     (b) a file IN the baseline is now clean — the baseline must shrink as
#         debt is paid, or it rots into a permanent excuse list.
#   Both directions fail, so the list can only go down and can never quietly
#   grow.
#
# TO PAY DOWN DEBT: `cargo fmt -p <pkg>`, delete the fixed paths from
# fmt-baseline.txt, commit both together.
#
# KNOWN LIMIT: `cargo fmt` walks the module tree, not the filesystem, so a .rs
# file that no `mod` declaration reaches is invisible to this gate. Such a file
# is also not compiled, so it cannot break the build — but do not read a green
# fmt stage as proof that every .rs file on disk was checked.
set -uo pipefail

cd "$(dirname "$0")/../.."
BASELINE="scripts/ci/fmt-baseline.txt"

if [ ! -f "$BASELINE" ]; then
  echo "FAIL: ${BASELINE} missing — the gate will not run without a baseline." >&2
  exit 2
fi

current="$(mktemp)"
baseline="$(mktemp)"
trap 'rm -f "$current" "$baseline"' EXIT

cargo fmt --all --check 2>/dev/null \
  | grep -oE '^Diff in [^:]*' \
  | sed "s|^Diff in ||; s|^${PWD}/||" \
  | sort -u > "$current"

grep -vE '^\s*(#|$)' "$BASELINE" | sort -u > "$baseline"

new_offenders="$(comm -23 "$current" "$baseline")"
newly_clean="$(comm -13 "$current" "$baseline")"

echo "rustfmt debt: $(wc -l < "$baseline" | tr -d ' ') file(s) in baseline, $(wc -l < "$current" | tr -d ' ') unformatted now."

status=0

if [ -n "$new_offenders" ]; then
  echo
  echo "FAIL: these files are not rustfmt-clean and are not in the baseline."
  echo "      Run: cargo fmt -- \$(echo <files>)  (or cargo fmt -p <pkg>)"
  echo "$new_offenders" | sed 's/^/  + /'
  status=1
fi

if [ -n "$newly_clean" ]; then
  echo
  echo "FAIL: these files are now rustfmt-clean but are still listed in"
  echo "      ${BASELINE}. Delete those lines so the baseline keeps shrinking."
  echo "$newly_clean" | sed 's/^/  - /'
  status=1
fi

[ "$status" -eq 0 ] && echo "OK: no new rustfmt drift."
exit "$status"
