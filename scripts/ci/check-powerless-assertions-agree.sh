#!/usr/bin/env bash
#
# check-powerless-assertions-agree.sh — MR7 C4 / M5.
#
# THE DEFECT THIS EXISTS FOR
# --------------------------
# Four places assert that the runtime role is powerless, and three of them
# described themselves as being "in the same shape as" one of the others. They
# were not. Only the Rust one asked about ROLE MEMBERSHIP, and the review proved
# the consequence by execution: with `secureprompt_app` granted membership of a
# BYPASSRLS role, migration 034 printed `ASSERTION PASSED` and
# `setup-app-role.sh` printed `OK: ... powerless`.
#
# Membership is the hole neither attribute reports. `secureprompt_app` is
# NOINHERIT, so `rolsuper`, `rolbypassrls` and `has_schema_privilege` all answer
# harmless — but NOINHERIT only means the privileges are not AUTOMATIC. `SET
# ROLE` reaches them from an ordinary connection with no password.
#
# A comment claiming four implementations agree is not checkable. This is.
#
# It is a coarse check on purpose: it asserts each file ASKS the question
# (`pg_auth_members`), not that it asks it identically. The behaviour is pinned
# by tests — `migration_034_refuses_a_runtime_role_that_can_reach_bypassrls` and
# `the_migration_step_refuses_a_runtime_role_that_can_reach_bypassrls` in
# secureprompt-api/tests/db_role_split.rs. This catches the one thing those
# cannot: a NEW copy of the assertion, or an old one quietly losing the query.
set -uo pipefail

cd "$(dirname "$0")/../.."

# Every file that claims to assert a Postgres role is powerless.
ASSERTIONS=(
    "secureprompt-api/src/db/migrations.rs"
    "secureprompt-api/migrations/034_app_role_runtime_grants.sql"
    "scripts/db/setup-app-role.sh"
    "scripts/ci/create-nonsuperuser-role.sh"
)

FAIL=0

for file in "${ASSERTIONS[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: ${file} is listed as a powerless-assertion site but does not exist." >&2
        echo "       If it moved, update this list; do not delete the entry." >&2
        FAIL=1
        continue
    fi

    # The attribute half. Whatever else it does, it must ask this.
    if ! grep -q 'rolsuper' "$file"; then
        echo "ERROR: ${file} no longer checks rolsuper/rolbypassrls." >&2
        FAIL=1
    fi

    # The half that was missing from three of the four.
    if ! grep -q 'pg_auth_members' "$file"; then
        echo "ERROR: ${file} does not check pg_auth_members." >&2
        echo "       A NOINHERIT role that is a MEMBER of a BYPASSRLS role reads" >&2
        echo "       NOSUPERUSER/NOBYPASSRLS in pg_roles and still reaches" >&2
        echo "       BYPASSRLS with one SET ROLE. Every attribute check passes" >&2
        echo "       and the deployment enforces no tenancy at all." >&2
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo "powerless assertions OK: all ${#ASSERTIONS[@]} ask about attributes AND role membership."
