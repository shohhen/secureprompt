#!/usr/bin/env bash
#
# init-env.sh must leave NO placeholder behind, on either path.
#
# WHY THIS EXISTS
#
# `check-env-hygiene.sh` asserts the opposite end of the same contract: that
# .env.example still says CHANGEME, so a bare `cp .env.example .env` cannot boot
# with a shared secret. Nothing asserted that the script which replaces those
# placeholders actually replaces ALL of them.
#
# It did not. Measured on a fresh EC2 host, 2026-08-10, following the on-prem
# runbook exactly:
#
#     MONGO_PASSWORD=CHANGEME
#     LIBRECHAT_JWT_SECRET=CHANGEME
#     LIBRECHAT_JWT_REFRESH_SECRET=CHANGEME
#     LIBRECHAT_CREDS_KEY=CHANGEME
#     LIBRECHAT_CREDS_IV=CHANGEME
#
# Five left behind, and the script PRINTED them under the heading "Still
# CHANGEME and only needed for the LibreChat stack" — which was true when chat
# was optional and stopped being true when librechat joined docker-compose.yml.
# `MONGO_PASSWORD=CHANGEME` is not an inconvenience; it is a database reachable
# from every container on the compose network with a credential published in
# this repository.
#
# The two crypto values also have LENGTHS that matter. LibreChat reads
# CREDS_KEY as 32 bytes of hex and CREDS_IV as 16, so a generator that emits
# the wrong width produces a stack that boots and then fails to encrypt.
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
cd "$REPO"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Every invocation below is `|| true` on purpose: this script must survive the
# thing it is testing exiting non-zero, or `set -e` turns a real failure into
# no output at all.
fail=0
note() { echo "  $*"; }
bad()  { echo "  FAIL: $*" >&2; fail=1; }

# ── 1. A fresh .env has no placeholder anywhere ───────────────────────────
ENV_FILE="$TMP/fresh.env" ./scripts/init-env.sh >/dev/null 2>&1 || true
left="$(grep -cE '^[A-Z_]+=CHANGEME' "$TMP/fresh.env" || true)"
if [ "$left" -eq 0 ]; then
    note "fresh .env: no CHANGEME left"
else
    bad "fresh .env still has $left placeholder(s):"
    grep -nE '^[A-Z_]+=CHANGEME' "$TMP/fresh.env" >&2 || true
fi

# Positive control: the file must actually have content, or "no CHANGEME" is
# true of an empty file and this test proves nothing.
keys="$(grep -cE '^[A-Z_]+=' "$TMP/fresh.env" || true)"
[ "$keys" -ge 20 ] || bad "fresh .env has only $keys keys — generation looks broken"
note "fresh .env: $keys keys"

# ── 2. The crypto values are the widths their consumers require ───────────
width() { grep -E "^$1=" "$TMP/fresh.env" | head -1 | cut -d= -f2- | tr -d '\n' | wc -c | tr -d ' '; }
ck="$(width LIBRECHAT_CREDS_KEY)"; ci="$(width LIBRECHAT_CREDS_IV)"
[ "$ck" = "64" ] || bad "LIBRECHAT_CREDS_KEY is $ck chars, LibreChat needs 64 (32 bytes hex)"
[ "$ci" = "32" ] || bad "LIBRECHAT_CREDS_IV is $ci chars, LibreChat needs 32 (16 bytes hex)"
[ "$ck" = "64" ] && [ "$ci" = "32" ] && note "LibreChat crypto widths: key=64 iv=32"

# ── 3. Every secret is DISTINCT ───────────────────────────────────────────
# A loop that reuses one generated value would satisfy every check above.
dupes="$(grep -E '^[A-Z_]+=' "$TMP/fresh.env" | cut -d= -f2- | grep -E '^[A-Za-z0-9+/=]{32,}$' | sort | uniq -d | wc -l | tr -d ' ')"
[ "$dupes" = "0" ] || bad "$dupes generated value(s) repeat across keys"
[ "$dupes" = "0" ] && note "all generated secrets are distinct"

# ── 4. --fill-missing repairs an OLD .env that still carries placeholders ─
# The upgrade path. An operator who ran an earlier version has CHANGEME on
# disk; --fill-missing only ever appended ABSENT keys, so it walked straight
# past a present-but-placeholder value and reported success.
cp "$TMP/fresh.env" "$TMP/old.env"
sed -i.bak 's|^MONGO_PASSWORD=.*|MONGO_PASSWORD=CHANGEME|' "$TMP/old.env"; rm -f "$TMP/old.env.bak"
ENV_FILE="$TMP/old.env" ./scripts/init-env.sh --fill-missing >/dev/null 2>&1 || true
if grep -qE '^MONGO_PASSWORD=CHANGEME$' "$TMP/old.env"; then
    bad "--fill-missing left MONGO_PASSWORD=CHANGEME in place"
else
    note "--fill-missing repaired a placeholder left by an older run"
fi

# ── 5. ...but it still must not touch a REAL value ────────────────────────
# The whole point of --fill-missing, and what
# check-upgrade-path-is-nondestructive.sh asserts. Repairing placeholders must
# not become "rewrite everything".
before="$(grep -E '^SECUREPROMPT_JWT_SECRET=' "$TMP/old.env")"
ENV_FILE="$TMP/old.env" ./scripts/init-env.sh --fill-missing >/dev/null 2>&1 || true
after="$(grep -E '^SECUREPROMPT_JWT_SECRET=' "$TMP/old.env")"
[ "$before" = "$after" ] || bad "--fill-missing rewrote an existing real secret"
[ "$before" = "$after" ] && note "--fill-missing left a real secret byte-identical"

if [ "$fail" -eq 0 ]; then
    echo "OK: init-env.sh leaves no placeholder and preserves real values."
else
    echo "FAIL: init-env.sh contract broken (see above)." >&2
    exit 1
fi
