#!/usr/bin/env bash
#
# SecurePrompt pip-audit gate (WS6-2) — ratcheting, not big-bang.
#
# Audits secureprompt-ml/requirements.txt, the Python ML sidecar's dependency
# set, against the PyPI advisory database.
#
# WHY NOT A BARE `pip-audit -r requirements.txt`:
#   MEASURED 2026-08-04 with pip-audit 2.10.1: 34 unique (package, advisory)
#   pairs across 4 packages, out of 104 resolved. A plain invocation exits 1,
#   so wiring it in directly would put a red job on every merge request from
#   the first minute — the failure `.github/workflows-retired/README` documents
#   four times over, and the reason `fmt` and `clippy` are ratchets here.
#
# WHAT THIS DOES INSTEAD:
#   pip-audit-baseline.tsv records the advisories that were already present when
#   the gate landed, with IDs, CVEs and fix versions. The gate fails if
#     (a) an advisory NOT in the baseline is reported — a new CVE, or a new
#         dependency that brought one; or
#     (b) an advisory IN the baseline is no longer reported — it was fixed, so
#         the row must go, or the list rots into a permanent excuse column.
#   Both directions fail, so the list can only shrink.
#
# TO PAY DOWN DEBT: bump the pin in requirements.txt, delete the matching rows
# here, commit both together. The baseline's header carries the recommended
# order and why.
#
# KNOWN LIMITS, stated rather than discovered later:
#   * NETWORK. pip-audit resolves the full dependency tree against PyPI and
#     queries the advisory API. With no egress this gate cannot run at all —
#     unlike scripts/ci/cargo-deny-gate.sh, there is no on-disk database to
#     fall back to, so a PyPI outage fails this job. It is a `lint`-stage job
#     and does not gate `build`; see the .gitlab-ci.yml job header.
#   * SCOPE. Only secureprompt-ml/requirements.txt. The repository has six other
#     Python requirement sets (requirements-dvc.txt, scripts/requirements-*.txt,
#     secureprompt-analytics/, secureprompt-ml/requirements-optional.txt,
#     secureprompt-py/). None of them ships in a served container; the sidecar
#     is the one that does. Widening this list is WS6-2-FU2 — and widen it the
#     way test:ml-sidecar widens its file list, one confirmed-runnable set at a
#     time.
#   * RESOLUTION DRIFT. Three constraints in requirements.txt are ranges, so the
#     resolved versions move over time. That is why the baseline key is
#     (package, advisory) and not (package, version, advisory).
set -uo pipefail

cd "$(dirname "$0")/../.."

REQ="secureprompt-ml/requirements.txt"
BASELINE="scripts/ci/pip-audit-baseline.tsv"

if [ ! -f "$BASELINE" ]; then
  echo "FAIL: ${BASELINE} missing — the gate will not run without a baseline." >&2
  exit 2
fi
if [ ! -f "$REQ" ]; then
  echo "FAIL: ${REQ} missing." >&2
  exit 2
fi

echo "pip-audit: $(pip-audit --version 2>&1)"
echo "auditing:  ${REQ}"

report="$(mktemp)"; current="$(mktemp)"; baseline="$(mktemp)"
trap 'rm -f "$report" "$current" "$baseline"' EXIT

# JSON, not the human table: the table collapses duplicate rows inconsistently
# (the same advisory is printed once per path that reaches the package), which
# is not a stable thing to diff.
pip-audit -r "$REQ" --progress-spinner off --format json > "$report" 2>/dev/null
audit_status=$?

# A resolution failure and a clean audit both exit 0/1 in ways that are easy to
# confuse, so verify the report is real JSON with a dependency list before
# drawing any conclusion from it. An empty or truncated report must not read as
# "no vulnerabilities".
if ! python3 -c "
import json,sys
d=json.load(open('$report'))
deps=d.get('dependencies')
assert isinstance(deps,list) and len(deps)>0, 'no dependencies resolved'
print(f'resolved:  {len(deps)} packages')
" 2>/dev/null; then
  echo >&2
  echo "FAIL: pip-audit produced no usable report (exit ${audit_status})." >&2
  echo "      Refusing to treat that as 'no vulnerabilities'. Check egress to" >&2
  echo "      pypi.org, and re-run by hand:" >&2
  echo "        pip-audit -r ${REQ}" >&2
  exit 2
fi

# Key: package<TAB>advisory. See the baseline header for why the version is not
# part of the key.
python3 -c "
import json
d=json.load(open('$report'))
out=set()
for p in d['dependencies']:
    for v in p.get('vulns',[]):
        out.add((p['name'],v['id']))
for n,i in sorted(out): print(f'{n}\t{i}')
" > "$current"

grep -vE '^\s*(#|$)' "$BASELINE" | cut -f1,2 | sort -u > "$baseline"

new_findings="$(comm -23 "$current" "$baseline")"
fixed_findings="$(comm -13 "$current" "$baseline")"

echo "advisories: $(wc -l < "$baseline" | tr -d ' ') in baseline, $(wc -l < "$current" | tr -d ' ') reported now."

status=0

if [ -n "$new_findings" ]; then
  echo
  echo "FAIL: these advisories are NOT in the baseline."
  echo "      Either upgrade the package, or — if it genuinely cannot be"
  echo "      upgraded today — add a row to ${BASELINE} with the CVE, the fix"
  echo "      version and the reason, in this merge request, where a reviewer"
  echo "      sees it."
  echo "$new_findings" | sed 's/^/  + /'
  status=1
fi

if [ -n "$fixed_findings" ]; then
  echo
  echo "FAIL: these advisories are in ${BASELINE} but are no longer reported."
  echo "      They were fixed. Delete the rows so the baseline keeps shrinking."
  echo "$fixed_findings" | sed 's/^/  - /'
  status=1
fi

[ "$status" -eq 0 ] && echo "OK: no new Python advisories."
exit "$status"
