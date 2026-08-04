#!/usr/bin/env bash
#
# SecurePrompt SBOM generation + gate (WS6-2).
#
# Emits a Software Bill of Materials for a RELEASE, in two formats, and then
# asserts that what was emitted is actually a bill of materials rather than a
# well-formed empty document.
#
# ---------------------------------------------------------------------------
# WHY THERE ARE ASSERTIONS AT ALL — AN SBOM JOB IS THE EASIEST THING IN A
# PIPELINE TO GET SILENTLY WRONG.
#
# `syft scan dir:<path>` against a path that does not exist, or that contains
# no lockfiles, exits 0 and writes a perfectly valid SPDX document with zero
# packages. Ship that to a customer as your compliance artifact and it is
# worse than shipping nothing, because it looks like an answer. It is the same
# trap this repository already guards against twice — `grep -q "2 passed"` in
# test:audit-export-doc, because `cargo test -- --exact <typo>` prints
# "0 passed" and exits 0.
#
# So this script generates, then PROVES the generation:
#   * the document parses;
#   * it carries packages from every ecosystem this product actually ships;
#   * and the Rust count is cross-checked against Cargo.lock itself, so a
#     broken cataloger cannot pass by producing a plausible-looking subset.
#
# ---------------------------------------------------------------------------
# WHAT IS SCANNED: the COMMITTED tree at the tagged commit, via `git archive`,
# for the same reason the gitleaks gate does it — `syft scan dir:.` in a
# working directory would catalog `target/`, sibling worktrees and any stray
# node_modules, so the SBOM would describe the machine rather than the release.
#
# WHAT IS *NOT* IN IT, stated rather than left to be discovered by whoever
# reads the SBOM in an audit:
#   * transitively resolved Python versions. syft reads requirements.txt as
#     written, so a range like `Pillow>=10.4,<12` is recorded as the range.
#     The RESOLVED set is what scripts/ci/pip-audit-gate.sh audits (104
#     packages on 2026-08-04 vs the 27 lines syft sees).
#   * anything added by a Dockerfile after the source is copied — OS packages,
#     the CPU torch wheel, the spacy/GLiNER model downloads. Those live in the
#     image, and an image SBOM (`syft <image>`) is the artifact that covers
#     them. WS6-2-FU6, and it needs a published image, like the trivy job.
set -uo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
OUT_DIR="${SBOM_OUT_DIR:-sbom}"

# The release identifier that goes into the artifact names. A tag when this is
# a release pipeline; otherwise the short SHA, so a manual run is still
# traceable to a commit.
VERSION="${CI_COMMIT_TAG:-${CI_COMMIT_SHORT_SHA:-$(git rev-parse --short HEAD)}}"

echo "syft:    $(syft version 2>/dev/null | awk '/^Version:/{print $2}')"
echo "version: ${VERSION}"

mkdir -p "$OUT_DIR"
tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT

if ! git archive HEAD | tar -x -C "$tree"; then
  # See scripts/ci/gitleaks-gate.sh for the macOS case-insensitive-filesystem
  # note; CI is Linux and does not hit it. The package-count assertions below
  # are what actually protect against a partial tree.
  echo "WARNING: git archive|tar reported errors (case-insensitive filesystem?)."
fi

base="${OUT_DIR}/secureprompt-${VERSION}"

# TWO FORMATS, because they have two different consumers and shipping only one
# means answering the other by hand:
#   SPDX 2.3      the ISO/IEC 5962 lineage; what procurement and compliance
#                 reviews ask for by name.
#   CycloneDX 1.6 the OWASP format the security tooling ecosystem consumes
#                 (dependency-track, grype, trivy all read it).
# The native syft format is also kept: it is the only one that round-trips
# every cataloger detail, and it is what the assertions below parse.
syft scan "dir:${tree}" -q \
  -o "spdx-json=${base}.spdx.json" \
  -o "cyclonedx-json=${base}.cdx.json" \
  -o "json=${base}.syft.json"

for f in "${base}.spdx.json" "${base}.cdx.json" "${base}.syft.json"; do
  if [ ! -s "$f" ]; then
    echo "FAIL: ${f} was not written, or is empty." >&2
    exit 2
  fi
done

# Cross-check input: the number of packages Cargo.lock declares. If syft's Rust
# cataloger silently stops working, this is what notices.
cargo_lock_crates="$(grep -c '^name = ' Cargo.lock)"

python3 - "${base}.syft.json" "${base}.spdx.json" "${base}.cdx.json" "$cargo_lock_crates" <<'PY'
import collections, json, sys

syft_path, spdx_path, cdx_path, cargo_lock_crates = sys.argv[1:5]
cargo_lock_crates = int(cargo_lock_crates)

doc = json.load(open(syft_path))
artifacts = doc.get("artifacts") or []
counts = collections.Counter(a["type"] for a in artifacts)

print(f"packages: {len(artifacts)}")
for kind, n in counts.most_common():
    print(f"  {n:6d}  {kind}")

failures = []

# An SBOM with no packages is the failure mode this script exists for.
if len(artifacts) < 100:
    failures.append(f"only {len(artifacts)} packages catalogued — the SBOM is effectively empty")

# Every ecosystem this product ships must be represented. A floor rather than
# an exact count for npm/python, because their lockfiles move independently of
# this gate; the Rust count is checked exactly, below.
for kind, floor in (("rust-crate", 1), ("npm", 500), ("python", 10)):
    if counts.get(kind, 0) < floor:
        failures.append(f"{kind}: {counts.get(kind, 0)} catalogued, expected at least {floor}")

# THE LOAD-BEARING ASSERTION. Cargo.lock is the ground truth for the Rust
# dependency set, and syft must agree with it exactly. A cataloger that breaks,
# or a tree that extracted partially, diverges here instead of producing a
# plausible-looking subset nobody checks.
if counts.get("rust-crate", 0) != cargo_lock_crates:
    failures.append(
        f"rust-crate count {counts.get('rust-crate', 0)} != Cargo.lock's {cargo_lock_crates} "
        "— syft and the lockfile disagree about the dependency set"
    )

# Both published formats must independently carry the packages. Writing the
# assertions against the syft-native document only would not notice a broken
# SPDX or CycloneDX encoder, which is what actually gets shipped.
spdx = json.load(open(spdx_path))
n_spdx = len(spdx.get("packages") or [])
if n_spdx < 100:
    failures.append(f"SPDX document carries {n_spdx} packages")

cdx = json.load(open(cdx_path))
n_cdx = len(cdx.get("components") or [])
if n_cdx < 100:
    failures.append(f"CycloneDX document carries {n_cdx} components")

print(f"spdx:     {n_spdx} packages")
print(f"cyclonedx:{n_cdx} components")

if failures:
    print()
    print("FAIL: the SBOM did not pass its own sanity checks.")
    for f in failures:
        print(f"  * {f}")
    sys.exit(1)
PY
rc=$?

if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

echo
echo "OK: SBOM generated and verified."
ls -la "$OUT_DIR"
