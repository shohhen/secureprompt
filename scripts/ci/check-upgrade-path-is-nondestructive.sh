#!/usr/bin/env bash
#
# check-upgrade-path-is-nondestructive.sh — MR7 I1.
#
# WHAT WENT WRONG, AND WHY IT NEEDS A CI STEP RATHER THAN A CAREFUL READER
# -----------------------------------------------------------------------
# The db-role-split runbook's FIRST upgrade command was
#
#     ./scripts/init-env.sh --force
#
# `--force` does `cp .env.example .env` and regenerates EVERY secret
# independently. `SECUREPROMPT_PROVIDER_KEY` is the AES-256-GCM key for
# `provider_credentials.encrypted_credential` (secureprompt-common/src/crypto.rs).
# Rotating it makes every stored provider credential PERMANENTLY undecryptable —
# there is no re-wrap step anywhere in this repo. `SECUREPROMPT_JWT_SECRET`
# rotation invalidates every session and refresh token, and `.env.example`
# carries no license token, CORS origins or provider config, so anything
# hand-edited into `.env` is lost as well.
#
# The upgrade needed exactly one new variable: SECUREPROMPT_APP_DB_PASSWORD.
#
# So this asserts two things a reviewer cannot keep asserting by eye:
#   1. `init-env.sh --fill-missing` adds what is missing and touches NOTHING
#      that already has a value.
#   2. No operator-facing document tells anyone to run `init-env.sh --force`
#      as part of an upgrade.
set -uo pipefail

cd "$(dirname "$0")/../.."

FAIL=0
fail() { echo "ERROR: $*" >&2; FAIL=1; }

# ---------------------------------------------------------------------------
# 1. --fill-missing preserves existing values.
# ---------------------------------------------------------------------------
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
target="$work/.env"

# An .env as an EXISTING deployment has it: real secrets in use, plus a
# hand-added key that .env.example does not carry at all, and without the new
# variable the upgrade introduces.
cat >"$target" <<'ENV'
SECUREPROMPT_JWT_SECRET=live_jwt_secret_do_not_rotate
SECUREPROMPT_PROVIDER_KEY=live_provider_key_do_not_rotate
NEXTAUTH_SECRET=live_nextauth_secret
ML_SIDECAR_INTERNAL_TOKEN=live_ml_token
SECUREPROMPT_LICENSE_TOKEN=hand.edited.license.token
ENV

if ! ENV_FILE="$target" ./scripts/init-env.sh --fill-missing >"$work/out" 2>&1; then
    fail "init-env.sh --fill-missing failed:"
    sed 's/^/       /' "$work/out" >&2
fi

while IFS= read -r line; do
    key="${line%%=*}"
    if ! grep -qxF "$line" "$target"; then
        now="$(grep -E "^${key}=" "$target" || echo '<removed>')"
        fail "init-env.sh --fill-missing changed ${key}."
        echo "       was: ${line}" >&2
        echo "       now: ${now}" >&2
        echo "       Rotating SECUREPROMPT_PROVIDER_KEY makes every stored" >&2
        echo "       provider credential permanently undecryptable." >&2
    fi
done <<'EXPECTED'
SECUREPROMPT_JWT_SECRET=live_jwt_secret_do_not_rotate
SECUREPROMPT_PROVIDER_KEY=live_provider_key_do_not_rotate
NEXTAUTH_SECRET=live_nextauth_secret
ML_SIDECAR_INTERNAL_TOKEN=live_ml_token
SECUREPROMPT_LICENSE_TOKEN=hand.edited.license.token
EXPECTED

if ! grep -qE '^SECUREPROMPT_APP_DB_PASSWORD=[0-9a-f]{64}$' "$target"; then
    fail "init-env.sh --fill-missing did not add a generated SECUREPROMPT_APP_DB_PASSWORD."
    echo "       That single variable is the whole of the role-split upgrade." >&2
fi

# ---------------------------------------------------------------------------
# 2. No document sends an operator through the destructive path.
# ---------------------------------------------------------------------------
# Anchored at the start of the line, so this catches a COMMAND an operator is
# meant to paste (in a fenced block, with or without a `$ ` prompt) and not
# prose that names `--force` in order to warn about it.
offenders="$(git ls-files -z 'docs/**/*.md' 'README.md' \
    | xargs -0 grep -nH -E '^[[:space:]]*(\$[[:space:]]+)?\.?/?(scripts/)?init-env\.sh[^`]*--force' || true)"
if [ -n "$offenders" ]; then
    fail "documentation tells an operator to run init-env.sh --force:"
    echo "$offenders" | sed 's/^/       /' >&2
    echo "       --force regenerates SECUREPROMPT_PROVIDER_KEY, which is the" >&2
    echo "       encryption key for stored provider credentials. Use" >&2
    echo "       --fill-missing on an existing deployment." >&2
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "upgrade-path OK: --fill-missing preserves existing secrets; no doc recommends --force."
