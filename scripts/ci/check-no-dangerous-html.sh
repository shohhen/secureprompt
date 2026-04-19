#!/usr/bin/env bash
# check-no-dangerous-html.sh — CI gate for XSS-prone dangerouslySetInnerHTML usage.
#
# Phase 5 / Plan 05-04 Task T-05-04 XSS gate.
# Fails if any occurrence of dangerouslySetInnerHTML is found in the
# secureprompt-web/src directory. Detection chips and redaction previews
# must use React text nodes and <mark> elements instead.
set -euo pipefail

TARGET="secureprompt-web/src"

if [ ! -d "$TARGET" ]; then
    echo "WARNING: $TARGET not found — skipping check" >&2
    exit 0
fi

if rg -nE 'dangerouslySetInnerHTML' "$TARGET" 2>/dev/null; then
    echo "ERROR: dangerouslySetInnerHTML is forbidden in Phase 5 (T-05-04 XSS gate)" >&2
    exit 1
fi

echo "check-no-dangerous-html: OK — no dangerouslySetInnerHTML found in $TARGET"
