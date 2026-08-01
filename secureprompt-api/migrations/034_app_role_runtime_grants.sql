-- 034 — make `secureprompt_app` usable as the RUNTIME role, and keep it powerless.
--
-- WHAT CHANGED AROUND THIS MIGRATION
-- ----------------------------------
-- `secureprompt_app` has been declared in `001_init.sql` since the first
-- migration and has never been connected with. Everything — `sqlx migrate run`
-- on boot, and every request the API then served — ran as the single role the
-- `postgres:16` image creates from POSTGRES_USER, which that image makes a
-- SUPERUSER. Superusers bypass row-level security unconditionally, so the
-- sixteen armed policies on this schema protected nothing while the product ran.
--
-- The deployment now uses two roles:
--
--   owner/migrator  owns every table, holds CREATE ON SCHEMA public, runs this
--                   file and every other migration. Unchanged: it is the same
--                   role that already owns the tables in every existing
--                   deployment, so no `ALTER TABLE ... OWNER TO` is needed.
--   runtime         `secureprompt_app`. Connects, reads and writes rows. Owns
--                   nothing, creates nothing, and is NOBYPASSRLS, so the
--                   policies apply to it.
--
-- WHY THIS FILE IS NOT JUST ANOTHER `GRANT ON ALL TABLES` LINE
-- -----------------------------------------------------------
-- Nine migrations already end with
--
--     GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
--         TO secureprompt_app;
--
-- and each grants only what exists at the moment it runs. `pg_default_acl` was
-- EMPTY before this file — measured, not assumed — so a table created by a
-- LATER migration is reachable only if that migration remembers to repeat the
-- line. Forgetting is silent: the schema is correct, the tests pass (they
-- connect as the owner), and the first request that touches the new table gets
-- a 42501 in production.
--
-- `ALTER DEFAULT PRIVILEGES` closes that. It attaches to the role that issues
-- it (`current_user` — there is no `FOR ROLE` clause below on purpose), which
-- means the guarantee holds precisely as long as migrations keep running as the
-- same role that ran this one. That is the invariant: ONE migration role per
-- deployment. Changing it later requires re-running this file as the new role.
--
-- Two related traps, both measured on this branch and both designed around here:
--
--   * `GRANT ... ON ALL TABLES` issued by a NON-OWNER emits a WARNING per table
--     and REPORTS SUCCESS while granting nothing — the GRANT analogue of
--     `UPDATE 0`. That is why the grants below must be run by the owner, i.e.
--     by the migration role, and not from any runtime path.
--   * `FORCE ROW LEVEL SECURITY` applies to the table OWNER as well. Making the
--     runtime role an owner would therefore not widen its reach, it would
--     subject it to policies written for tenants. Hence `REVOKE CREATE` below:
--     the runtime role must not be able to create — and thereby own — anything.
--
-- IDEMPOTENT. Safe on a fresh database and on one that has been running since
-- 001. It transfers no ownership and moves no data.

-- ---------------------------------------------------------------------------
-- 1. The role must exist, and must be powerless.
--
-- The ALTER is attempted only when something is actually wrong, because
-- `ALTER ROLE ... NOSUPERUSER` needs superuser, and the migration role is not
-- guaranteed to be one (CI's `test:rls-nonsuperuser` job runs this whole set as
-- a NOSUPERUSER/CREATEROLE role). On a correct database the branch is never
-- taken and no privilege is required. On an incorrect one it is repaired if
-- possible and the migration FAILS if not — never silently tolerated.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r RECORD;
BEGIN
    SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolcanlogin
      INTO r
      FROM pg_roles
     WHERE rolname = 'secureprompt_app';

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'role secureprompt_app does not exist. 001_init.sql creates it; if '
            'that migration was applied to this database by hand, create the '
            'role with scripts/db/setup-app-role.sh before re-running.';
    END IF;

    IF r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole
       OR NOT r.rolcanlogin THEN
        BEGIN
            ALTER ROLE secureprompt_app
                NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE LOGIN;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE EXCEPTION
                'secureprompt_app carries attributes that defeat the role '
                'split (super=%, bypassrls=%, createdb=%, createrole=%, '
                'login=%) and this migration role cannot correct them. Fix it '
                'as a superuser: ALTER ROLE secureprompt_app NOSUPERUSER '
                'NOBYPASSRLS NOCREATEDB NOCREATEROLE LOGIN;',
                r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole,
                r.rolcanlogin;
        END;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Reach for everything that exists now.
--
-- Repeated from 001 deliberately: this file must be correct standing alone, so
-- that re-running it is the documented repair for a database whose grants have
-- drifted.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO secureprompt_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO secureprompt_app;

DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO secureprompt_app', current_database());
END $$;

-- ---------------------------------------------------------------------------
-- 3. Reach for everything a LATER migration creates.
--
-- This is the part that did not exist before. Without it the grants above are a
-- snapshot, and the schema drifts away from the runtime role one migration at a
-- time.
-- ---------------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secureprompt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO secureprompt_app;

-- ---------------------------------------------------------------------------
-- 4. Deny the runtime role the schema.
--
-- Not decoration: CREATE on a schema is also the ability to OWN, and an owner
-- is filtered by FORCE ROW LEVEL SECURITY rather than exempted from it. A
-- runtime role that can create tables can also create one the policies were
-- never written for.
-- ---------------------------------------------------------------------------
REVOKE CREATE ON SCHEMA public FROM secureprompt_app;

-- ---------------------------------------------------------------------------
-- 4b. And the same privilege held by PUBLIC, which the REVOKE above cannot
--     reach.
--
-- MEASURED on postgres:16.14: with `GRANT CREATE ON SCHEMA public TO PUBLIC`
-- in place, `REVOKE CREATE ... FROM secureprompt_app` is a NO-OP — it removes
-- a grant the role does not individually hold — and the assertion below then
-- raised, taking the whole deployment down: `--migrate-only` exits non-zero,
-- compose's `db-migrate` never reaches `service_completed_successfully`, and
-- neither `api` nor `worker` starts.
--
-- This is not an exotic state. `PUBLIC` holding `CREATE` on `public` is the
-- DEFAULT for every database created before PostgreSQL 15; `pg_upgrade`
-- preserves schema ACLs, so only a newly `initdb`'d PG15+ cluster drops it.
-- It is also what an operator gets from `GRANT ALL ON SCHEMA public TO PUBLIC`.
-- The chart and compose pin postgres:16, but a database restored from an older
-- cluster carries the old ACL.
--
-- Conditional rather than unconditional because REVOKE requires ownership of
-- the schema (or grant option), which the migration role is not guaranteed to
-- have on managed Postgres. On a database that does not need the repair, the
-- statement is never attempted and no privilege is required.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    public_holds_create BOOLEAN;
BEGIN
    -- grantee 0 is the pseudo-role PUBLIC. COALESCE onto acldefault() because
    -- a NULL nspacl means "the built-in default", which for a schema created
    -- before PG15 still includes the PUBLIC grant.
    SELECT EXISTS (
        SELECT 1
          FROM pg_namespace n,
               aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
         WHERE n.nspname = 'public'
           AND a.grantee = 0
           AND a.privilege_type = 'CREATE')
      INTO public_holds_create;

    IF public_holds_create THEN
        BEGIN
            REVOKE CREATE ON SCHEMA public FROM PUBLIC;
            RAISE NOTICE
                '034: revoked CREATE ON SCHEMA public from PUBLIC (the '
                'pre-PostgreSQL-15 default). Any role that was relying on that '
                'grant to create objects in schema public must now be granted '
                'CREATE explicitly.';
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE EXCEPTION
                'CREATE ON SCHEMA public is granted to PUBLIC, which gives it '
                'to secureprompt_app, and this migration role cannot revoke it '
                '(it does not own schema public). Fix it as the schema owner '
                'or a superuser: REVOKE CREATE ON SCHEMA public FROM PUBLIC;';
        END;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 5. The powerless-assertion, in the same shape as
--    scripts/ci/create-nonsuperuser-role.sh.
--
-- Placed AFTER the grants so it also catches a grant in this file having
-- somehow elevated the role. Without it, a future base image or a stray
-- `ALTER ROLE` could hand the runtime role superuser and every deployment would
-- keep working perfectly while enforcing no tenancy at all — the worst
-- available outcome, because nothing would report it.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    privileged BOOLEAN;
    can_create BOOLEAN;
    grantees   TEXT;
BEGIN
    SELECT rolsuper OR rolbypassrls
      INTO privileged
      FROM pg_roles
     WHERE rolname = 'secureprompt_app';

    IF privileged IS DISTINCT FROM FALSE THEN
        RAISE EXCEPTION
            'secureprompt_app has SUPERUSER or BYPASSRLS. Every row-level '
            'security policy in this schema would be inert at runtime. '
            'Refusing to complete the migration.';
    END IF;

    SELECT has_schema_privilege('secureprompt_app', 'public', 'CREATE')
      INTO can_create;

    IF can_create THEN
        -- Name the grantee instead of guessing at it. The previous text here
        -- said "it is probably a member of a role that holds it", which is the
        -- ONE cause it provably cannot be: secureprompt_app is NOINHERIT, and
        -- a NOINHERIT membership makes has_schema_privilege answer FALSE
        -- (measured). That sent the operator to pg_auth_members, which is
        -- empty, while the real grantee sat in pg_namespace.nspacl.
        SELECT string_agg(DISTINCT
                   CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_get_userbyid(a.grantee) END, ', ')
          INTO grantees
          FROM pg_namespace n,
               aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
         WHERE n.nspname = 'public'
           AND a.privilege_type = 'CREATE';

        RAISE EXCEPTION
            'secureprompt_app still has CREATE on schema public after the '
            'REVOKEs above. CREATE on schema public is currently held by: %. '
            'Revoke it from whichever of those reaches secureprompt_app '
            '(PUBLIC reaches every role). Refusing to complete the migration.',
            COALESCE(grantees, '(nothing in pg_namespace.nspacl — the grant is '
                               'reaching it some other way)');
    END IF;
END $$;
