#!/usr/bin/env bash
#
# SecurePrompt gitleaks gate (WS6-2) — ratcheting, not big-bang.
#
# Scans the COMMITTED tree for secrets. The policy, the custom SecurePrompt
# key rule, and the reasoning about scope (tracked files only; history
# deliberately not gated) live in .gitleaks.toml. This script is the runner and
# the ratchet.
#
# WHY NOT A BARE `gitleaks dir .`:
#   MEASURED 2026-08-04 with gitleaks 8.30.1 — 204 findings, 13.88 GB read,
#   9m 3s, including the developer's own untracked `.env`. Against the
#   committed tree instead: 68 findings, 39.53 MB, 4.8s. A gate that is red on
#   every merge request from minute one, and that reports a developer's local
#   credentials as leaks, is a gate that gets muted — the failure documented
#   four times over in .github/workflows-retired/README.
#
# WHAT THIS DOES INSTEAD:
#   gitleaks-baseline.tsv records the findings already in the tree when the gate
#   landed, EACH ONE inspected by hand and classified (see that file's header —
#   none is a live credential). The gate fails if
#     (a) a finding is NOT in the baseline — new secret, or a new file with an
#         old fixture in it; or
#     (b) a baseline row is no longer found — the fixture was cleaned up, so
#         the row must go, or the list rots into a permanent excuse column.
#   Both directions fail, so the list can only shrink. Same shape as
#   scripts/ci/fmt-gate.sh.
#
# THE FINGERPRINT, and why it is not gitleaks' own:
#   gitleaks fingerprints a `dir` finding as `file:rule:startLine`. Line numbers
#   move whenever anything above them is edited, so a baseline keyed on that
#   would go stale on unrelated changes — a self-inflicted flaky gate. This uses
#       <path>:<ruleID>:<first 16 hex of sha256(secret)>
#   which is stable under line moves and under reformatting, and still
#   distinguishes two different secrets in the same file under the same rule.
set -uo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
BASELINE="scripts/ci/gitleaks-baseline.tsv"

if [ ! -f "$BASELINE" ]; then
  echo "FAIL: ${BASELINE} missing — the gate will not run without a baseline." >&2
  exit 2
fi
if [ ! -f .gitleaks.toml ]; then
  echo "FAIL: .gitleaks.toml missing — refusing to scan with default config." >&2
  exit 2
fi

echo "gitleaks: $(gitleaks version 2>&1)"

workdir="$(mktemp -d)"
report="$workdir/report.json"
current="$workdir/current.txt"
baseline="$workdir/baseline.txt"
tree="$workdir/tree"
trap 'rm -rf "$workdir"' EXIT

# Exactly the committed tree — no build output, no gitignored files, no sibling
# worktrees. See .gitleaks.toml's header for the measurement that motivated it.
mkdir -p "$tree"
if ! git archive HEAD | tar -x -C "$tree"; then
  # macOS note: extracting this repository on a case-INSENSITIVE filesystem
  # prints "Failed to restore metadata: File exists" for graphify-out/ entries
  # that differ only in case, and tar exits non-zero even though every file was
  # written. CI is Linux (case-sensitive) and does not hit it. Fall back rather
  # than fail, but say so, because a silently partial tree is a silently
  # incomplete scan.
  echo "WARNING: git archive|tar reported errors (case-insensitive filesystem?)."
  echo "         Continuing; verify the file count below looks sane."
fi

file_count="$(find "$tree" -type f | wc -l | tr -d ' ')"
tracked_count="$(git ls-files | wc -l | tr -d ' ')"
echo "scanned:  ${file_count} files extracted from HEAD (${tracked_count} tracked)"

# A tree that failed to extract must not read as "no leaks found".
if [ "$file_count" -lt 100 ]; then
  echo "FAIL: only ${file_count} files were extracted — the tree is not intact." >&2
  echo "      Refusing to report a clean scan against it." >&2
  exit 2
fi

# --exit-code 0 so a finding is not itself the failure; this script decides,
# after comparing against the baseline.
gitleaks dir "$tree" \
  --config "$REPO_ROOT/.gitleaks.toml" \
  --no-banner \
  --report-format json \
  --report-path "$report" \
  --exit-code 0 2>&1 | grep -vE '^\s*$' || true

if [ ! -s "$report" ]; then
  echo "FAIL: gitleaks produced no report file — it did not complete." >&2
  exit 2
fi

python3 - "$report" "$tree" > "$current" <<'PY'
import hashlib, json, sys
report, tree = sys.argv[1], sys.argv[2]
prefix = tree.rstrip('/') + '/'
rows = set()
for f in json.load(open(report)):
    path = f['File']
    if path.startswith(prefix):
        path = path[len(prefix):]
    digest = hashlib.sha256(f['Secret'].encode('utf-8', 'replace')).hexdigest()[:16]
    rows.add(f"{path}\t{f['RuleID']}\t{digest}")
for r in sorted(rows):
    print(r)
PY

grep -vE '^\s*(#|$)' "$BASELINE" | cut -f1,2,3 | sort -u > "$baseline"

new_findings="$(comm -23 "$current" "$baseline")"
gone_findings="$(comm -13 "$current" "$baseline")"

echo "findings: $(wc -l < "$baseline" | tr -d ' ') in baseline, $(wc -l < "$current" | tr -d ' ') found now."

status=0

if [ -n "$new_findings" ]; then
  echo
  echo "FAIL: these secrets are NOT in the baseline."
  echo
  echo "  If this is a REAL credential:  rotate it first, then remove it."
  echo "  Removing it from the diff is not enough — assume it is compromised"
  echo "  the moment it is pushed."
  echo
  echo "  If it is a test fixture or placeholder: add a row to ${BASELINE}"
  echo "  with the reason, in this merge request, where a reviewer sees it."
  echo "$new_findings" | sed 's/^/  + /'
  status=1
fi

if [ -n "$gone_findings" ]; then
  echo
  echo "FAIL: these baseline rows no longer match anything in the tree."
  echo "      The fixture was removed or changed. Delete the rows so the"
  echo "      baseline keeps shrinking."
  echo "$gone_findings" | sed 's/^/  - /'
  status=1
fi

[ "$status" -eq 0 ] && echo "OK: no new secrets."
exit "$status"
