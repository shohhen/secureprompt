#!/usr/bin/env bash
#
# Create the `secureprompt_runner` Postgres role used by the RLS gate job.
#
# WHY A NON-SUPERUSER ROLE MATTERS — this is the point of the whole job, so it
# is written down rather than assumed:
#
#   The postgres:16 image creates POSTGRES_USER as a SUPERUSER, and superusers
#   BYPASS row-level security unconditionally. Every developer's local database
#   and the compose stack therefore run with RLS effectively switched off. A
#   test suite that connects as that role cannot observe an RLS regression at
#   all — it will report green on code that leaks across tenants.
#
#   Concrete instance already in this repo: migration 017
#   (017_uzbek_identifier_policy_classes.sql:40) backfills policy classes with
#
#       UPDATE policy_rules SET conditions = ... WHERE name = 'Redact common PII'
#
#   with no workspace scoping and no `SET LOCAL app.workspace_id`. policy_rules
#   has RLS enabled (001_init.sql:78). Run as a NOBYPASSRLS role, that
#   statement matches ZERO rows — and `UPDATE` matching zero rows is not an
#   error, so the migration reports success while having done nothing. It only
#   appears to work locally because the dev role is a superuser.
#
#   NOSUPERUSER + NOBYPASSRLS is what catches that class of defect. CREATEDB is
#   required because `#[sqlx::test]` provisions a database per test.
#
# Env: ADMIN_DATABASE_URL — superuser connection used to create the role.
#      Defaults to the compose-default credentials on host `postgres`.
set -euo pipefail

ADMIN_DATABASE_URL="${ADMIN_DATABASE_URL:-postgres://secureprompt:secureprompt@postgres:5432/postgres}"
RUNNER_ROLE="${RUNNER_ROLE:-secureprompt_runner}"
RUNNER_PASSWORD="${RUNNER_PASSWORD:-secureprompt}"

psql "$ADMIN_DATABASE_URL" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${RUNNER_ROLE}') THEN
    CREATE ROLE ${RUNNER_ROLE}
      LOGIN PASSWORD '${RUNNER_PASSWORD}'
      NOSUPERUSER CREATEDB CREATEROLE NOBYPASSRLS;
  END IF;
END \$\$;
GRANT ALL PRIVILEGES ON DATABASE postgres TO ${RUNNER_ROLE};
SQL

# Assert the role really is powerless. Without this, a future base image or a
# stray GRANT could hand it superuser and the job would keep passing while
# testing nothing at all — the worst possible outcome for a security gate.
privileged="$(psql "$ADMIN_DATABASE_URL" -tAc \
  "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname='${RUNNER_ROLE}'")"
if [ "$privileged" != "f" ]; then
  echo "FAIL: ${RUNNER_ROLE} has superuser or BYPASSRLS (got '${privileged}')." >&2
  echo "      This job would exercise no RLS at all. Refusing to continue." >&2
  exit 1
fi

# ROLE MEMBERSHIP. Three other files describe themselves as "the same shape as
# scripts/ci/create-nonsuperuser-role.sh", and until MR7 none of them — this
# one included — asked this question. MEASURED: a NOINHERIT role that is a
# MEMBER of a BYPASSRLS role reads NOSUPERUSER/NOBYPASSRLS in pg_roles and
# still reaches BYPASSRLS with one SET ROLE. For a gate whose entire purpose is
# to run the suite as a role RLS applies to, that is the failure that matters.
memberships="$(psql "$ADMIN_DATABASE_URL" -tAc \
  "SELECT COALESCE(string_agg(g.rolname, ', ' ORDER BY g.rolname), '')
     FROM pg_auth_members m
     JOIN pg_roles mem ON mem.oid = m.member
     JOIN pg_roles g   ON g.oid   = m.roleid
    WHERE mem.rolname='${RUNNER_ROLE}'")"
if [ -n "$memberships" ]; then
  echo "FAIL: ${RUNNER_ROLE} is a member of: ${memberships}." >&2
  echo "      SET ROLE reaches whatever those hold, NOINHERIT or not, so this" >&2
  echo "      job could be exercising no RLS at all. Refusing to continue." >&2
  exit 1
fi

echo "OK: ${RUNNER_ROLE} exists, NOSUPERUSER + NOBYPASSRLS + CREATEDB, no role memberships."
