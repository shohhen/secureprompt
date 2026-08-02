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
# WHY THIS ROLE KEEPS CREATEROLE, AND WHY THAT IS NOT AN ESCAPE HATCH
# --------------------------------------------------------------------
# MR7 review M5 flagged CREATEROLE here, citing `tests/db_role_split.rs`:
# "with it the role can grant itself membership of a privileged role and escape
# the split entirely". That was true of PostgreSQL 15 and earlier. It is FALSE
# of PostgreSQL 16, which is what `helm/secureprompt/values.yaml` and every
# `docker-compose*.yml` pin, and PG16 is the floor this script now asserts.
#
# MEASURED on postgres:16.14, as a NOSUPERUSER / CREATEDB / CREATEROLE /
# NOBYPASSRLS role, every route the finding names:
#
#   GRANT <existing BYPASSRLS role> TO self
#     -> ERROR: permission denied to grant role
#        DETAIL: Only roles with the ADMIN option on role "..." may grant this
#   CREATE ROLE x BYPASSRLS
#     -> ERROR: Only roles with the BYPASSRLS attribute may create roles with
#        the BYPASSRLS attribute
#   CREATE ROLE x; ALTER ROLE x BYPASSRLS
#     -> same denial on the ALTER
#   CREATE ROLE x SUPERUSER
#     -> ERROR: Only roles with the SUPERUSER attribute may ...
#   ALTER ROLE self BYPASSRLS
#     -> ERROR: permission denied to alter role
#
#   Final state: rolsuper = f, rolbypassrls = f.
#
# PG16 narrowed CREATEROLE to "may administer the roles it created", and an
# attribute can only be conferred by a role that already holds it. So CREATEROLE
# grants the power to make POWERLESS roles and nothing more.
#
# It is also REQUIRED, not incidental: `tests/rls_repo_scope.rs`,
# `tests/audit_export.rs`, `tests/admin_audit.rs`, `tests/auth_redis_outage.rs`,
# `tests/migration_006_rls.rs` and `tests/db_role_split.rs` all `CREATE ROLE`
# probe roles as the connected role. Dropping CREATEROLE would not harden this
# job; it would stop it running.
#
# The premise is asserted below rather than trusted, because it is a
# version-dependent property and this script is cited as the canonical shape by
# three other files.
#
# ON "NOT CREATE": M5 also notes this script does not check CREATE on schema
# public. That is deliberate and is the difference between this role and
# `secureprompt_app`. This role RUNS THE MIGRATIONS in each per-test database,
# so it must be able to create tables; the runtime role must not. Checking
# CREATE here would fail the job it exists to enable.
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

# POSTGRES 16 FLOOR. Everything above about CREATEROLE being harmless is a
# property of PG16's narrowed CREATEROLE. On PG15 and earlier a CREATEROLE role
# really could grant itself membership of any non-superuser role, which is the
# escape MR7 M5 describes. Refuse rather than silently run the security gate on
# a server where its own reasoning does not hold.
server_version="$(psql "$ADMIN_DATABASE_URL" -tAc "SHOW server_version_num")"
if [ "$server_version" -lt 160000 ]; then
  echo "FAIL: server_version_num=${server_version} (< 16). On PostgreSQL 15 and" >&2
  echo "      earlier, CREATEROLE lets ${RUNNER_ROLE} grant itself membership of" >&2
  echo "      a privileged role, so this job would not be running under RLS at" >&2
  echo "      all. The chart and every compose file pin postgres:16." >&2
  exit 1
fi

# THE PREMISE, EXECUTED. `SET ROLE` makes permission checks use ${RUNNER_ROLE},
# so this is the real attempt, not a reading of pg_roles. Both statements MUST
# fail; if either succeeds the role can manufacture a BYPASSRLS identity and
# every RLS assertion in the gate is worthless.
escape="$(psql "$ADMIN_DATABASE_URL" -tAc "
  SET ROLE ${RUNNER_ROLE};
  DO \$\$
  BEGIN
    BEGIN
      EXECUTE 'CREATE ROLE sp_m5_escape_probe NOLOGIN BYPASSRLS';
      RAISE EXCEPTION 'CREATED_BYPASSRLS_ROLE';
    EXCEPTION
      WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
      EXECUTE 'ALTER ROLE ${RUNNER_ROLE} BYPASSRLS';
      RAISE EXCEPTION 'SELF_GRANTED_BYPASSRLS';
    EXCEPTION
      WHEN insufficient_privilege THEN NULL;
    END;
  END \$\$;
" 2>&1)" || true
if printf '%s' "$escape" | grep -qE "CREATED_BYPASSRLS_ROLE|SELF_GRANTED_BYPASSRLS"; then
  echo "FAIL: ${RUNNER_ROLE} was able to manufacture a BYPASSRLS identity:" >&2
  printf '      %s\n' "$escape" >&2
  echo "      Every RLS assertion in this job would be exercising nothing." >&2
  exit 1
fi
psql "$ADMIN_DATABASE_URL" -qtAc "DROP ROLE IF EXISTS sp_m5_escape_probe" >/dev/null 2>&1 || true

echo "OK: ${RUNNER_ROLE} exists, NOSUPERUSER + NOBYPASSRLS + CREATEDB, no role memberships, and cannot manufacture BYPASSRLS on PG${server_version}."
