#!/usr/bin/env bash
#
# SecurePrompt container image scan gate (WS6-2) — ratcheting, and SCHEDULED
# rather than per-merge-request.
#
# Scans every image listed in scripts/ci/scan-images.txt with trivy and
# compares the findings against scripts/ci/trivy-baseline.tsv.
#
# ---------------------------------------------------------------------------
# WHY THIS RUNS ON A SCHEDULE AND NOT IN THE MERGE-REQUEST GATE
#
# Container vulnerabilities are a function of TIME, not of your diff. An image
# that was clean when it was built acquires CVEs while sitting in the registry,
# because upstream published an advisory — no commit involved. Two consequences,
# and they point the same way:
#
#   1. Per-MR is the WRONG CADENCE. It would block a one-line documentation
#      change on a CVE disclosed overnight in a base image that MR never
#      touched. That is the "red through no fault of yours" shape that emptied
#      .github/workflows-retired/, and the same reasoning the `bench` job's
#      header gives for refusing a wall-clock threshold.
#   2. Per-MR is also INSUFFICIENT. `build` is `when: manual`, so between
#      publishes there may be weeks in which nothing scans the images that are
#      actually deployed. Only a schedule catches that.
#
# So: scheduled (and manually runnable), NOT in `build`'s `needs:`, and it does
# not gate merges. A failure here is a work item, not a blocked pipeline.
#
# ---------------------------------------------------------------------------
# WHY --ignore-unfixed, WHICH IS THE MOST ARGUABLE FLAG HERE
#
# A vulnerability with no released fix cannot be acted on by this repository:
# there is no version to bump to. Gating on it produces a job that is red until
# a third party ships a patch, for a duration nobody here controls — a
# permanently-red gate by construction. `--ignore-unfixed` therefore scopes the
# gate to what someone can actually do something about today.
#
# THE COST, stated plainly: an unfixed CRITICAL is invisible to this gate. That
# is a real gap, not a technicality. The mitigation is that the job writes a
# FULL report (all severities, fixed and unfixed) as a CI artifact on every
# run, so the unfixed set is one click away even though it is not gating.
# ---------------------------------------------------------------------------
set -uo pipefail

cd "$(dirname "$0")/../.."

IMAGES_FILE="scripts/ci/scan-images.txt"
BASELINE="scripts/ci/trivy-baseline.tsv"
REPORT_DIR="${TRIVY_REPORT_DIR:-trivy-reports}"

for f in "$IMAGES_FILE" "$BASELINE"; do
  [ -f "$f" ] || { echo "FAIL: ${f} missing — the gate will not run without it." >&2; exit 2; }
done

echo "trivy: $(trivy --version 2>/dev/null | head -1)"
mkdir -p "$REPORT_DIR"

workdir="$(mktemp -d)"
current="$workdir/current.txt"
baseline="$workdir/baseline.txt"
trap 'rm -rf "$workdir"' EXIT
: > "$current"

# Read the image list.
#
# NOT `mapfile`: that is bash 4+, and macOS ships bash 3.2, so a developer
# running this locally would get "mapfile: command not found" and an unbound
# variable rather than a scan. A while-read loop works on both.
#
# `envsubst` expands $CI_REGISTRY_IMAGE so the published-image lines work
# unchanged once uncommented. It comes from gettext and is not universally
# installed (notably absent on a stock macOS), so it is used only if present —
# the entries that need it are all commented out today.
images=()
if command -v envsubst >/dev/null 2>&1; then
  expand() { envsubst; }
else
  expand() { cat; }
fi
while IFS= read -r line; do
  [ -n "$line" ] && images+=("$line")
done < <(grep -vE '^\s*(#|$)' "$IMAGES_FILE" | expand)

if [ "${#images[@]}" -eq 0 ]; then
  echo "FAIL: ${IMAGES_FILE} lists no images — nothing would be scanned." >&2
  exit 2
fi

scanned=0
for img in "${images[@]}"; do
  slug="$(echo "$img" | tr '/:@' '___')"
  gate_json="$workdir/${slug}.json"
  full_json="$REPORT_DIR/${slug}.full.json"

  echo
  echo "--- scanning ${img}"

  # The GATING scan: fixable HIGH/CRITICAL only. See the header.
  if ! trivy image --scanners vuln \
        --severity HIGH,CRITICAL --ignore-unfixed \
        --quiet --format json --output "$gate_json" "$img"; then
    echo "FAIL: trivy could not scan ${img}." >&2
    echo "      Refusing to treat an unscannable image as clean." >&2
    exit 2
  fi

  # The ARTIFACT scan: everything, including unfixed, so the gap the gating
  # flags create is visible to a human even though it is not enforced.
  trivy image --scanners vuln \
      --quiet --format json --output "$full_json" "$img" 2>/dev/null || true

  python3 - "$gate_json" "$img" >> "$current" <<'PY'
import json, sys
path, img = sys.argv[1], sys.argv[2]
doc = json.load(open(path))
rows = set()
for res in (doc.get('Results') or []):
    for v in (res.get('Vulnerabilities') or []):
        rows.add(f"{img}\t{v['PkgName']}\t{v['VulnerabilityID']}")
for r in sorted(rows):
    print(r)
PY
  scanned=$((scanned + 1))
done

# A run that scanned nothing must not report "no new vulnerabilities".
if [ "$scanned" -ne "${#images[@]}" ]; then
  echo "FAIL: scanned ${scanned} of ${#images[@]} images." >&2
  exit 2
fi

sort -u -o "$current" "$current"
grep -vE '^\s*(#|$)' "$BASELINE" | cut -f1,2,3 | sort -u > "$baseline"

new_findings="$(comm -23 "$current" "$baseline")"
gone_findings="$(comm -13 "$current" "$baseline")"

echo
echo "images:  ${scanned} scanned"
echo "findings: $(wc -l < "$baseline" | tr -d ' ') in baseline, $(wc -l < "$current" | tr -d ' ') found now (fixable HIGH/CRITICAL)"
echo "reports: ${REPORT_DIR}/ (all severities, including unfixed)"

status=0

if [ -n "$new_findings" ]; then
  echo
  echo "FAIL: these fixable HIGH/CRITICAL vulnerabilities are NOT in the baseline."
  echo "      Each has a released fix, so each is actionable: rebuild on a"
  echo "      newer base tag, or bump the package."
  echo "$new_findings" | sed 's/^/  + /'
  status=1
fi

if [ -n "$gone_findings" ]; then
  echo
  echo "FAIL: these baseline rows are no longer reported — they were fixed"
  echo "      (usually by an upstream base-image rebuild). Delete the rows so"
  echo "      the baseline keeps shrinking."
  echo "$gone_findings" | sed 's/^/  - /'
  status=1
fi

[ "$status" -eq 0 ] && echo "OK: no new fixable HIGH/CRITICAL image vulnerabilities."
exit "$status"
