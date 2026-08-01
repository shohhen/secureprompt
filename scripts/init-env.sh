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
#   ./scripts/init-env.sh                 # create .env, refusing to clobber an existing one
#   ./scripts/init-env.sh --fill-missing  # add only the keys an existing .env lacks
#   ./scripts/init-env.sh --force         # DESTRUCTIVE: regenerate every secret
#
#   ENV_FILE=<path>                       # target file, default .env (used by CI)
#
# --force IS NOT AN UPGRADE COMMAND
# --------------------------------
# It regenerates every secret independently, and two of them are not rotatable:
#
#   SECUREPROMPT_PROVIDER_KEY  AES-256-GCM key for
#                              provider_credentials.encrypted_credential
#                              (secureprompt-common/src/crypto.rs). There is no
#                              re-wrap step in this repository: rotate it and
#                              every stored provider credential becomes
#                              PERMANENTLY undecryptable.
#   SECUREPROMPT_JWT_SECRET    invalidates every session and refresh token.
#
# It also starts from .env.example, which carries no license token, no CORS
# origins and no provider config — so anything hand-edited into .env is gone.
#
# On an existing deployment use --fill-missing, which never touches a key that
# already has a value.
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${ENV_FILE:-.env}"
MODE="${1:-}"

case "$MODE" in
    ""|--force|--fill-missing) ;;
    *)
        echo "error: unknown option '$MODE'." >&2
        echo "       usage: init-env.sh [--fill-missing | --force]" >&2
        exit 2
        ;;
esac

if [[ -f "$TARGET" && "$MODE" == "" ]]; then
    echo "error: $TARGET already exists." >&2
    echo "       --fill-missing  add only the keys it lacks (safe on a live deployment)" >&2
    echo "       --force         regenerate EVERY secret (destroys stored provider" >&2
    echo "                       credentials — see the header of this script)" >&2
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
# WS1-P0 role split: docker-compose.yml builds BOTH the runtime DATABASE_URL and
# the password `db-migrate` sets on `secureprompt_app` from this one variable, so
# generating it here cannot leave the role and the URL disagreeing.
APP_DB_PASSWORD="$(gen)"

# --fill-missing: append the keys this .env does not have, and stop. Every
# existing assignment is left byte-for-byte alone — that is the entire point,
# and scripts/ci/check-upgrade-path-is-nondestructive.sh asserts it.
if [[ "$MODE" == "--fill-missing" ]]; then
    if [[ ! -f "$TARGET" ]]; then
        echo "error: $TARGET does not exist — run without --fill-missing to create it." >&2
        exit 1
    fi

    added=()
    fill() {
        local key="$1" value="$2"
        if grep -qE "^${key}=" "$TARGET"; then
            return
        fi
        # A file that does not end in a newline would otherwise get the new key
        # welded onto its last line.
        [[ -s "$TARGET" && -n "$(tail -c 1 "$TARGET")" ]] && echo >>"$TARGET"
        echo "${key}=${value}" >>"$TARGET"
        added+=("$key")
    }

    fill SECUREPROMPT_JWT_SECRET      "$JWT_SECRET"
    fill SECUREPROMPT_PROVIDER_KEY    "$PROVIDER_KEY"
    fill ML_SIDECAR_INTERNAL_TOKEN    "$ML_TOKEN"
    fill NEXTAUTH_SECRET              "$NEXTAUTH"
    fill SECUREPROMPT_APP_DB_PASSWORD "$APP_DB_PASSWORD"

    if [[ "${#added[@]}" -eq 0 ]]; then
        echo "$TARGET already has every key this script manages. Nothing changed."
    else
        echo "Added to $TARGET (existing values untouched): ${added[*]}"
    fi
    exit 0
fi

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
replace SECUREPROMPT_APP_DB_PASSWORD "$APP_DB_PASSWORD"

echo "Wrote $TARGET with freshly generated secrets."
echo
echo "Still CHANGEME and only needed for the LibreChat stack:"
grep -nE "^[A-Z_]+=CHANGEME" "$TARGET" || echo "  (none)"
echo
echo "Next: docker compose up"
