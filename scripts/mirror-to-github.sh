#!/usr/bin/env bash
#
# Publish a PUBLIC mirror of this repository to GitHub, with internal material
# removed from EVERY commit — not just from the tip.
#
# WHY A FILTER AND NOT `git rm`
#
# Deleting a file in a new commit leaves it in the history that ships with the
# clone. On a public repository that is the same as not deleting it: `git log
# -p` recovers the contents in one command. So the mirror is produced by
# rewriting history, and the check at the end greps every commit in the result
# rather than trusting that the rewrite did what it said.
#
# WHY IT IS SAFE TO RE-RUN
#
# `git filter-repo` is deterministic: the same input commits and the same path
# list produce the same output hashes every time. So a later run replays the
# same rewrite over the newer source and the push fast-forwards. The mirror is
# built in a scratch clone; THIS repository is never rewritten.
#
# Usage:  scripts/mirror-to-github.sh <github-remote-url> [--dry-run]
#
set -euo pipefail

REMOTE="${1:-}"
DRY_RUN="${2:-}"
if [ -z "$REMOTE" ]; then
    echo "usage: $0 <github-remote-url> [--dry-run]" >&2
    exit 1
fi

SRC="$(git rev-parse --show-toplevel)"
WORK="${MIRROR_WORKDIR:-${TMPDIR:-/tmp}/secureprompt-gh-mirror}"

# ── What never reaches the public mirror ──────────────────────────────────
#
# Each entry is here for a stated reason. Anyone adding to this list should add
# the reason too; anyone removing one should be able to argue against it.
STRIP=(
    # Plans, review reports and the real-document leakboards. The leakboards are
    # per-class precision/recall for the detector — the benchmark a competitor
    # would otherwise have to build, and a list of which entity classes are
    # weakest.
    "docs/superpowers"
    ".superpowers"
    # Same content re-exported as a Jira backlog: epic descriptions naming the
    # security workstreams and their merge requests.
    "docs/superpowers-jira-import.csv"
    "docs/superpowers-jira-import.md"
    # Operator release notes. Enumerates thirteen fixed Critical defects AND the
    # gaps deliberately left open — unpatched CVEs on the upload path, tables
    # still without row-level security, a measured false-positive rate. Against
    # a deployed instance that is a to-do list.
    "docs/releases/v0.1.0-hardening.md"
    # Break-glass and licence-recovery procedures: how to get in when the second
    # factor is unavailable, and how to restore service when licensing refuses.
    # Useful to an operator, equally useful to an attacker.
    "docs/runbooks/2fa-break-glass.md"
    "docs/runbooks/license-recovery.md"
)

echo "==> building mirror in $WORK"
rm -rf "$WORK"
git clone --no-local --quiet "$SRC" "$WORK"

# ── Strings rewritten across every commit ─────────────────────────────────
#
# GitHub push protection matches the SHAPE of a Slack incoming-webhook URL and
# does not judge the value, so the documentation placeholder
# `T00000000/B00000000/XXXX…` in the commented-out alertmanager receiver blocks
# the push. It is not a credential — the T and B segments are all zeros — but
# leaving a string in a public repository that every scanner will flag forever
# is its own cost, and clicking "allow this secret" to get past it is a habit
# worth not forming.
#
# Rewritten to an obviously-inert form instead. filter-repo applies this to all
# history, so old commits carrying the placeholder are rewritten too — which is
# the point, since the block was triggered by a commit, not by the tip.
REPLACEMENTS="$WORK/.mirror-replacements.txt"

FILTER_ARGS=(--force --invert-paths)
for p in "${STRIP[@]}"; do FILTER_ARGS+=(--path "$p"); done

cd "$WORK"
cat > "$REPLACEMENTS" <<'EOF'
https://slack.example.invalid/replace-with-your-webhook-url==>https://slack.example.invalid/replace-with-your-webhook-url
EOF
# ── Commit-message trailers stripped from the public history ──────────────
#
# No commit is AUTHORED by an Anthropic address, so GitHub never listed an
# assistant among the repository's contributors. What it does show is the
# trailer on the message of 769 commits, on every commit page. Removing it is
# an authorship-presentation choice for the published copy; GitLab keeps its
# history untouched.
#
# Only the two exact trailers are removed. A `Co-Authored-By:` naming a HUMAN
# is left alone — this repository has a second real contributor, and dropping
# their credit would be a different and worse mistake than the one being fixed.
git filter-repo "${FILTER_ARGS[@]}" --replace-text "$REPLACEMENTS" \
  --message-callback '
import re
message = re.sub(rb"(?im)^Co-Authored-By:[ \t]*Claude[^\n]*\n?", b"", message)
message = re.sub(rb"(?im)^Claude-Session:[^\n]*\n?", b"", message)
# Collapse the blank run the removed trailers leave behind, and drop trailing
# whitespace, so messages do not end in a gap where the trailer used to be.
message = re.sub(rb"\n{3,}", b"\n\n", message)
return message.rstrip() + b"\n"
' >/dev/null
rm -f "$REPLACEMENTS"
echo "==> rewritten: $(git rev-list --count HEAD) commits (source has $(git -C "$SRC" rev-list --count HEAD))"

# ── Verify, do not assume ─────────────────────────────────────────────────
echo "==> verifying no stripped path survives in ANY commit"
ALL_PATHS="$(git log --all --pretty=format: --name-only | sort -u)"
fail=0
for p in "${STRIP[@]}"; do
    # Exact path, or anything beneath it. A prefix match would report
    # `docs/superpowers-jira-import.csv` as a hit for `docs/superpowers`, which
    # is how that file was nearly missed in the first place.
    if printf '%s\n' "$ALL_PATHS" | grep -qE "^${p}(/|$)"; then
        echo "   LEFT BEHIND: $p" >&2
        fail=1
    else
        echo "   clean: $p"
    fi
done
[ "$fail" -eq 0 ] || { echo "refusing to push" >&2; exit 1; }

# The replaced string must be gone from every commit, or the push is blocked
# again and we learn about it from GitHub rather than from here.
if git log --all -p 2>/dev/null | grep -qE "hooks\.slack\.com/services/T0"; then
    echo "   LEFT BEHIND: the slack placeholder survived the rewrite" >&2
    exit 1
fi
echo "   clean: slack webhook placeholder (rewritten across history)"

if git log --all --format=%B | grep -qiE "^(Co-Authored-By:[ \t]*Claude|Claude-Session:)"; then
    echo "   LEFT BEHIND: Claude trailers survived the rewrite" >&2
    exit 1
fi
echo "   clean: assistant trailers removed from commit messages"

# Positive control: the rewrite must not have emptied the repository.
tracked="$(git ls-files | wc -l | tr -d ' ')"
echo "==> tracked files in mirror: $tracked"
[ "$tracked" -gt 1000 ] || { echo "mirror looks truncated; refusing to push" >&2; exit 1; }

if command -v gitleaks >/dev/null 2>&1; then
    echo "==> re-scanning the REWRITTEN history for secrets"
    gitleaks git --no-banner --redact -c "$SRC/.gitleaks.toml" . 2>&1 | tail -3 || true
else
    echo "==> gitleaks not installed; skipping the post-rewrite scan" >&2
fi

if [ "$DRY_RUN" = "--dry-run" ]; then
    echo "==> dry run: not pushing. Mirror left at $WORK"
    exit 0
fi

echo "==> pushing to $REMOTE"
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE"
git push --force origin main
echo "==> done"
