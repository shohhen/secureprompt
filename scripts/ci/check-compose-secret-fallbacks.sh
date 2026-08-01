#!/usr/bin/env bash
#
# check-compose-secret-fallbacks.sh — MR1 review I1.
#
# WHY THIS EXISTS
# ---------------
# WS1-3 added a boot gate that refuses to start on a known-placeholder secret,
# with the reasoning: "booting with one of these means the deployment is
# running on a secret that is public knowledge — `.env.example` sets
# `SECUREPROMPT_JWT_SECRET=CHANGEME`."
#
# True of `.env.example`. False of `docker-compose.yml`, the primary stack,
# which supplied its OWN fallbacks:
#
#     SECUREPROMPT_JWT_SECRET:   ${SECUREPROMPT_JWT_SECRET:-dev-jwt-secret-changeme-in-prod-1}
#     SECUREPROMPT_PROVIDER_KEY: ${SECUREPROMPT_PROVIDER_KEY:-dev-provider-key-changeme-in-prod}
#     NEXTAUTH_SECRET:           ${NEXTAUTH_SECRET:-changeme-dev-only}
#     KMS_FILE_KEY:              ${KMS_FILE_KEY:-c2VjdXJlcHJvbXB0LWRldi1rbXMta2V5LTMyYnl0ZXM=}
#
# so the var was never unset and never equalled CHANGEME. `docker compose up`
# with no `.env` booted on a JWT signing key committed to this repository.
#
# The same MR got this right for exactly one variable —
# `ML_SIDECAR_INTERNAL_TOKEN` uses `${VAR:?message}` in all five services — and
# did not apply the pattern to the JWT secret, the provider key, the NextAuth
# secret or the KMS key. This check is what stops the next one from drifting
# back: a `:-` fallback on a secret is a published credential, whatever the
# fallback's value looks like.
#
# `scripts/init-env.sh` generates real values for these, so `:?` costs a
# developer one command and buys a stack that cannot boot on a public secret.
set -uo pipefail

cd "$(dirname "$0")/../.."

# Env vars whose value is a credential. A `${VAR:-...}` default on any of these
# ships a secret; they must use `${VAR:?...}` so compose refuses to start.
SECRET_VARS=(
    SECUREPROMPT_JWT_SECRET
    SECUREPROMPT_PROVIDER_KEY
    NEXTAUTH_SECRET
    KMS_FILE_KEY
    ML_SIDECAR_INTERNAL_TOKEN
    SECUREPROMPT_APP_DB_PASSWORD
)

FILES=(docker-compose.yml)
for extra in docker-compose.simple.yml docker-compose.onprem.yml; do
    [ -f "$extra" ] && FILES+=("$extra")
done

FAIL=0

for file in "${FILES[@]}"; do
    for var in "${SECRET_VARS[@]}"; do
        # `${VAR:-default}` or `${VAR-default}` — a shipped fallback.
        offenders="$(grep -nE "\\\$\{${var}:?-" "$file" || true)"
        if [ -n "$offenders" ]; then
            echo "ERROR: ${file} gives ${var} a default value:" >&2
            printf '%s\n' "$offenders" | sed 's/^/       /' >&2
            echo "       A '\${VAR:-...}' fallback on a credential means the stack boots on a" >&2
            echo "       secret that is committed to this repository. Use \"\${${var}:?set it in .env — run scripts/init-env.sh}\"." >&2
            FAIL=1
        fi
    done
done

# Positive control: the pattern must actually be IN USE somewhere, or a typo in
# the grep above would make this check silently vacuous.
if ! grep -qE '\$\{ML_SIDECAR_INTERNAL_TOKEN:\?' docker-compose.yml; then
    echo "ERROR: docker-compose.yml no longer uses the \${VAR:?...} pattern for" >&2
    echo "       ML_SIDECAR_INTERNAL_TOKEN. That was the reference implementation" >&2
    echo "       this check generalises; without it the check proves nothing." >&2
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "compose secret hygiene OK: no credential carries a shipped default in ${FILES[*]}."
