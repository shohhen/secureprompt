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
# MR1 review I1: docker-compose.yml used to default KMS_FILE_KEY to the literal
# base64 of "secureprompt-dev-kms-key-32bytes", published in this repository, so
# every unconfigured stack encrypted its file vault under a key anyone can read.
# It is now REQUIRED there, so it must be generated here. Format is fixed by
# secureprompt-common/src/kms.rs: base64-standard of EXACTLY 32 decoded bytes.
KMS_FILE_KEY="$(openssl rand 32 | base64)"
# WS6-5. Redis and ClickHouse were both unauthenticated in compose. Generated
# here for the same reason as everything above: docker-compose.yml requires
# them with no fallback, and .env.example must keep a value the hygiene gate
# rejects rather than a working one.
REDIS_PASSWORD="$(gen)"
CLICKHOUSE_PASSWORD="$(gen)"
# The LibreChat stack. These were left as CHANGEME for as long as chat was
# optional, and the script printed them under "only needed for the LibreChat
# stack". librechat and librechat-mongo are in docker-compose.yml now, so that
# heading stopped being true and MONGO_PASSWORD=CHANGEME became a database
# reachable from every container on the compose network under a credential
# published in this repository.
MONGO_PASSWORD="$(gen)"
LIBRECHAT_JWT="$(gen)"
LIBRECHAT_JWT_REFRESH="$(gen)"
# WIDTHS ARE LOAD-BEARING. LibreChat reads CREDS_KEY as 32 bytes of hex and
# CREDS_IV as 16; the wrong width boots fine and then fails to encrypt, which
# is a worse failure than not booting.
LIBRECHAT_KEY="$(openssl rand -hex 32)"
LIBRECHAT_IV="$(openssl rand -hex 16)"
# Not a secret, so it is not generated — but it must EXIST, or an upgraded
# deployment keeps the compiled-in default that covers only localhost:3000.
CORS_ORIGINS="http://localhost:3003,http://localhost:3000"
# Also not a secret: the vendor PUBLIC key that licence tokens verify against.
# Absent, licence activation 500s before it reads the token.
LICENSE_PUBKEY="6/lucPVN8u5Wa7U2kt2/GuyRojFxXdNYiz9DI1dJ3AY="

# --fill-missing: append the keys this .env does not have, and stop. Every
# existing assignment is left byte-for-byte alone — that is the entire point,
# and scripts/ci/check-upgrade-path-is-nondestructive.sh asserts it.
if [[ "$MODE" == "--fill-missing" ]]; then
    if [[ ! -f "$TARGET" ]]; then
        echo "error: $TARGET does not exist — run without --fill-missing to create it." >&2
        exit 1
    fi

    added=()
    repaired=()
    fill() {
        local key="$1" value="$2"
        # A key that is PRESENT but still holds the placeholder is the upgrade
        # case: an operator ran an older version of this script, which left
        # CHANGEME behind, and --fill-missing then skipped it forever because
        # the key existed. Repairing it is not "clobbering an existing value" —
        # CHANGEME is the absence of one, and the boot gate rejects it.
        if grep -qE "^${key}=CHANGEME$" "$TARGET"; then
            sed -i.bak -E "s|^${key}=CHANGEME$|${key}=${value}|" "$TARGET"
            rm -f "${TARGET}.bak"
            repaired+=("$key")
            return
        fi
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
    fill KMS_FILE_KEY                 "$KMS_FILE_KEY"
    fill REDIS_PASSWORD               "$REDIS_PASSWORD"
    fill CLICKHOUSE_PASSWORD          "$CLICKHOUSE_PASSWORD"
    fill MONGO_PASSWORD               "$MONGO_PASSWORD"
    fill LIBRECHAT_JWT_SECRET         "$LIBRECHAT_JWT"
    fill LIBRECHAT_JWT_REFRESH_SECRET "$LIBRECHAT_JWT_REFRESH"
    fill LIBRECHAT_CREDS_KEY          "$LIBRECHAT_KEY"
    fill LIBRECHAT_CREDS_IV           "$LIBRECHAT_IV"
    fill SECUREPROMPT_CORS_ORIGINS    "$CORS_ORIGINS"
    fill SECUREPROMPT_LICENSE_PUBKEY  "$LICENSE_PUBKEY"

    if [[ "${#added[@]}" -eq 0 && "${#repaired[@]}" -eq 0 ]]; then
        echo "$TARGET already has every key this script manages. Nothing changed."
    else
        [[ "${#added[@]}" -gt 0 ]] && echo "Added to $TARGET (existing values untouched): ${added[*]}"
        # Named separately from "added" so an operator can see that something
        # already on disk was rewritten, and which.
        [[ "${#repaired[@]}" -gt 0 ]] && echo "Replaced leftover CHANGEME placeholders: ${repaired[*]}"
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
replace KMS_FILE_KEY                 "$KMS_FILE_KEY"
replace REDIS_PASSWORD               "$REDIS_PASSWORD"
replace CLICKHOUSE_PASSWORD          "$CLICKHOUSE_PASSWORD"
replace MONGO_PASSWORD               "$MONGO_PASSWORD"
replace LIBRECHAT_JWT_SECRET         "$LIBRECHAT_JWT"
replace LIBRECHAT_JWT_REFRESH_SECRET "$LIBRECHAT_JWT_REFRESH"
replace LIBRECHAT_CREDS_KEY          "$LIBRECHAT_KEY"
replace LIBRECHAT_CREDS_IV           "$LIBRECHAT_IV"

echo "Wrote $TARGET with freshly generated secrets."

# This used to read "Still CHANGEME and only needed for the LibreChat stack"
# and list five keys. They are generated now, so anything printed here is a
# placeholder nobody owns — a bug in this script, not a note for the operator.
leftover="$(grep -nE "^[A-Z_]+=CHANGEME" "$TARGET" || true)"
if [ -n "$leftover" ]; then
    echo
    echo "BUG: these keys were left as placeholders and nothing will replace them:" >&2
    echo "$leftover" >&2
    echo "scripts/ci/check-init-env-leaves-no-placeholder.sh covers this." >&2
    exit 1
fi

echo
echo "Two settings are NOT secrets and this script cannot guess them. A"
echo "deployment reachable at anything other than localhost must set both:"
echo
echo "  SECUREPROMPT_CORS_ORIGINS=https://<your console host>"
echo "      Currently: $(grep -E '^SECUREPROMPT_CORS_ORIGINS=' "$TARGET" | cut -d= -f2-)"
echo "      The browser sends credentials, so the API must echo the exact"
echo "      origin. Miss it and the console reports \"Invalid credentials\"."
echo
echo "  NEXT_PUBLIC_API_URL=https://<your api host>"
echo "      A BUILD ARGUMENT, not a runtime variable. Next.js inlines it into"
echo "      the browser bundle, so setting it in $TARGET does nothing to an"
echo "      already-built image — the bundle keeps whatever it was compiled"
echo "      with: http://localhost:8080 — the browser's own machine, not yours."
echo "      Rebuild the web image to change it:"
echo "        docker build --build-arg NEXT_PUBLIC_API_URL=https://<api host> \\"
echo "          -f secureprompt-web/Dockerfile -t secureprompt/web:0.1.0 ."
echo
echo "Next: docker compose up"
