#!/usr/bin/env bash
# init-env.sh — generate a working .env from .env.example with fresh secrets.
#
# WHY THIS EXISTS
# ---------------
# Two changes on this branch made `cp .env.example .env && docker compose up`
# fail:
#
#   * the API refuses to boot on a placeholder secret (WS1-3), and
#   * docker-compose.yml requires ML_SIDECAR_INTERNAL_TOKEN with no default
#     (WS1-5), so even `docker compose config` exits 1 without it.
#
# Both are deliberate. The tempting shortcut — committing real generated
# values into .env.example — is the bug they were written to prevent: a secret
# published in a template is shared by every deployment that copies it, and a
# random-looking hex string is WORSE than the literal CHANGEME it replaces,
# because nothing announces that it needs changing and the boot gate cannot
# recognise it as a placeholder.
#
# So .env.example keeps values the boot gate REJECTS, and this script mints
# real ones locally. Secrets are generated on the machine that will use them
# and never enter git.
#
# USAGE
#   ./scripts/init-env.sh          # create .env, refusing to clobber an existing one
#   ./scripts/init-env.sh --force  # overwrite an existing .env
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=".env"
FORCE="${1:-}"

if [[ -f "$TARGET" && "$FORCE" != "--force" ]]; then
    echo "error: $TARGET already exists. Re-run with --force to overwrite it." >&2
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl is required to generate secrets." >&2
    exit 1
fi

gen() { openssl rand -hex 32; }

# Every secret is generated independently. JWT and provider key in particular
# MUST differ — JwtConfig::from_env rejects them being equal.
JWT_SECRET="$(gen)"
PROVIDER_KEY="$(gen)"
ML_TOKEN="$(gen)"
NEXTAUTH="$(gen)"

cp .env.example "$TARGET"

# Replace only the assignment, never a commented line: the anchored `^KEY=`
# leaves the explanatory comments above each value intact.
replace() {
    local key="$1" value="$2"
    if ! grep -qE "^${key}=" "$TARGET"; then
        echo "error: ${key} not found in .env.example — update this script." >&2
        exit 1
    fi
    # `|` delimiter: hex values never contain it, unlike `/`.
    sed -i.bak -E "s|^${key}=.*|${key}=${value}|" "$TARGET"
    rm -f "${TARGET}.bak"
}

replace SECUREPROMPT_JWT_SECRET   "$JWT_SECRET"
replace SECUREPROMPT_PROVIDER_KEY "$PROVIDER_KEY"
replace ML_SIDECAR_INTERNAL_TOKEN "$ML_TOKEN"
replace NEXTAUTH_SECRET           "$NEXTAUTH"

echo "Wrote $TARGET with freshly generated secrets."
echo
echo "Still CHANGEME and only needed for the LibreChat stack:"
grep -nE "^[A-Z_]+=CHANGEME" "$TARGET" || echo "  (none)"
echo
echo "Next: docker compose up"
