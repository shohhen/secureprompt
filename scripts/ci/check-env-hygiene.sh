#!/usr/bin/env bash
# check-env-hygiene.sh — VALIDATION 5-08-03
# Asserts:
#   1. .env.example contains CHANGEME for every required secret key.
#   2. .gitignore covers the .env.local pattern.
#   3. No .env.local file is tracked in git.
#   4. No .env.example line carries a real secret (32+ char hex/base64 value).
set -euo pipefail

REQUIRED=(
    "SECUREPROMPT_JWT_SECRET"
    "SECUREPROMPT_PROVIDER_KEY"
    "NEXTAUTH_SECRET"
)

FAIL=0

# 1. Each required key must be present and set exactly to CHANGEME.
for key in "${REQUIRED[@]}"; do
    if ! grep -qE "^${key}=CHANGEME$" .env.example 2>/dev/null; then
        echo "ERROR: .env.example missing or non-CHANGEME value for ${key}" >&2
        FAIL=1
    fi
done

# 2. Catch accidentally committed real secrets (32+ hex/base64 chars after =).
for key in "${REQUIRED[@]}"; do
    if grep -qE "^${key}=[A-Za-z0-9+/=]{32,}$" .env.example 2>/dev/null; then
        echo "ERROR: .env.example appears to contain a real secret for ${key}" >&2
        FAIL=1
    fi
done

# 3. .gitignore must include a .env.local pattern.
if ! grep -qE '(^|/)\.env\.local$' .gitignore 2>/dev/null; then
    echo "ERROR: .gitignore does not contain a .env.local pattern" >&2
    FAIL=1
fi

# 4. .env.local must NOT be tracked by git.
if git ls-files --error-unmatch -- '*/.env.local' '.env.local' 2>/dev/null; then
    echo "ERROR: a .env.local file is tracked by git — remove it and add to .gitignore" >&2
    FAIL=1
fi

if [[ "$FAIL" -ne 0 ]]; then
    exit 1
fi

echo "env-hygiene OK"
