#!/usr/bin/env bash
#
# Provision the RUNTIME Postgres role, `secureprompt_app`.
#
# WHEN YOU NEED THIS
# ------------------
# Usually you do not. `secureprompt-api --migrate-only` creates the role (via
# 001_init.sql), grants it (034_app_role_runtime_grants.sql) and sets its
# password, all in one step, and that is what docker-compose.yml and the Helm
# chart run. Reach for this script when you cannot run that step against the
# database yet:
#
#   * managed Postgres (RDS, Cloud SQL) where the role must be created by an
#     administrator before the application is allowed to connect at all;
#   * rotating the runtime password without redeploying;
#   * repairing a role that has drifted — someone granted it BYPASSRLS, or the
#     `ALTER ROLE` in the migration step failed because the migration role has
#     no CREATEROLE.
#
# WHY THE ROLE HAS TO BE POWERLESS
# --------------------------------
# The `postgres:16` image creates POSTGRES_USER as a SUPERUSER, and superusers
# bypass row-level security unconditionally. Running the product as that role
# means the sixteen armed RLS policies on this schema protect nothing. This
# role is the answer: NOSUPERUSER and NOBYPASSRLS, so the policies apply; and
# NOCREATEDB/NOCREATEROLE with no CREATE on schema public, so it can neither
# create nor own a table — an owner is FILTERED by `FORCE ROW LEVEL SECURITY`
# rather than exempt from it, which is a different access path, not a wider one.
#
# The assertion at the end is the whole point, and is not optional: without it
# a future base image or a stray GRANT could hand this role superuser and every
# deployment would keep working perfectly while enforcing no tenancy at all.
# Nothing else would report it.
#
# ENV
#   ADMIN_DATABASE_URL   superuser/owner connection. REQUIRED.
#   APP_ROLE             defaults to secureprompt_app
#   APP_PASSWORD         required unless --no-password is given
#
# USAGE
#   ADMIN_DATABASE_URL=postgres://secureprompt:...@host:5432/secureprompt \
#   APP_PASSWORD="$(openssl rand -hex 32)" \
#     ./scripts/db/setup-app-role.sh
#
#   # verify/repair only, leave the password alone
#   ADMIN_DATABASE_URL=... ./scripts/db/setup-app-role.sh --no-password
set -euo pipefail

ADMIN_DATABASE_URL="${ADMIN_DATABASE_URL:-}"
APP_ROLE="${APP_ROLE:-secureprompt_app}"
APP_PASSWORD="${APP_PASSWORD:-}"
SET_PASSWORD=1

if [ "${1:-}" = "--no-password" ]; then
  SET_PASSWORD=0
fi

if [ -z "$ADMIN_DATABASE_URL" ]; then
  echo "error: ADMIN_DATABASE_URL is required (owner/superuser connection)." >&2
  exit 2
fi
if [ "$SET_PASSWORD" = "1" ] && [ -z "$APP_PASSWORD" ]; then
  echo "error: APP_PASSWORD is required, or pass --no-password to leave it." >&2
  echo "       generate one with: openssl rand -hex 32" >&2
  exit 2
fi

# The role name goes through `format('%I')` and the password through
# `format('%L')`, both server-side. Neither is interpolated into SQL text here:
# a password containing a quote would otherwise end the literal.
#
# The values reach the server as parameters of `set_config`, outside any
# dollar-quoted block — psql does NOT substitute `:vars` inside `$$ ... $$`, so
# the DO body reads them back with `current_setting`.
psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -q \
     -v role="$APP_ROLE" <<'SQL'
SELECT set_config('sp.role', :'role', false);
DO $$
DECLARE
    target TEXT := current_setting('sp.role');
BEGIN
    BEGIN
        EXECUTE format(
            'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOINHERIT NOREPLICATION NOBYPASSRLS', target);
    EXCEPTION
        WHEN duplicate_object THEN NULL;
        WHEN unique_violation THEN NULL;   -- created concurrently; roles are cluster-global
    END;

    EXECUTE format('ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE '
                   'NOBYPASSRLS LOGIN', target);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), target);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', target);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES '
                   'IN SCHEMA public TO %I', target);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', target);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                   'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', target);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                   'GRANT USAGE, SELECT ON SEQUENCES TO %I', target);
    EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I', target);
END $$;
SQL

if [ "$SET_PASSWORD" = "1" ]; then
  # `\getenv` keeps the password out of argv (and therefore out of `ps`), and
  # `format('%L')` keeps its quoting Postgres's problem. Never echoed.
  APP_PASSWORD="$APP_PASSWORD" psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -q \
       -v role="$APP_ROLE" <<'SQL' >/dev/null
\getenv app_password APP_PASSWORD
SELECT set_config('sp.role', :'role', false);
SELECT set_config('sp.pw', :'app_password', false);
DO $$
BEGIN
    EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L',
                   current_setting('sp.role'), current_setting('sp.pw'));
END $$;
SQL
fi

# ---------------------------------------------------------------------------
# The assertion. Same shape as scripts/ci/create-nonsuperuser-role.sh.
# ---------------------------------------------------------------------------
privileged="$(psql "$ADMIN_DATABASE_URL" -tAc \
  "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname='${APP_ROLE}'")"
if [ "$privileged" != "f" ]; then
  echo "FAIL: ${APP_ROLE} has SUPERUSER or BYPASSRLS (got '${privileged}')." >&2
  echo "      Row-level security would be inert at runtime and nothing would" >&2
  echo "      report it. Refusing to continue." >&2
  exit 1
fi

can_create="$(psql "$ADMIN_DATABASE_URL" -tAc \
  "SELECT has_schema_privilege('${APP_ROLE}','public','CREATE')")"
if [ "$can_create" != "f" ]; then
  echo "FAIL: ${APP_ROLE} has CREATE on schema public (got '${can_create}')." >&2
  echo "      It could create — and therefore own — a table, and an owner is" >&2
  echo "      filtered by FORCE ROW LEVEL SECURITY rather than exempt from it." >&2
  exit 1
fi

owns="$(psql "$ADMIN_DATABASE_URL" -tAc \
  "SELECT count(*) FROM pg_class
    WHERE relnamespace = 'public'::regnamespace
      AND relowner = (SELECT oid FROM pg_roles WHERE rolname='${APP_ROLE}')")"
if [ "$owns" != "0" ]; then
  echo "FAIL: ${APP_ROLE} owns ${owns} object(s) in schema public." >&2
  exit 1
fi

echo "OK: ${APP_ROLE} exists, NOSUPERUSER + NOBYPASSRLS, no CREATE on public, owns nothing."
