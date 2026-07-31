-- WS1-P1E — make the two CROSS-TENANT-BY-NECESSITY refresh-token lookups
-- possible for a role that does not bypass row-level security.
--
-- ===========================================================================
-- THE PROBLEM THIS FILE EXISTS FOR
-- ===========================================================================
--
-- `tests/rls_call_site_guard.rs` lists two statements in
-- `src/db/refresh_token_repo.rs` that run on a BARE POOL against
-- `refresh_tokens`, which migration 002 put under FORCE ROW LEVEL SECURITY:
-- `rotate`'s pre-lookup and `find_active_by_hash`. Neither can arm a scope
-- first. A refresh token is thirty-two bytes of entropy; it does not name its
-- workspace, and the lookup is what DISCOVERS the workspace. That is the same
-- shape as the login-by-email lookup migration 031 Part 2 describes on `users`.
--
-- Today the deployment connects as a SUPERUSER and superusers bypass RLS
-- unconditionally, so both read correctly. MEASURED under a
-- NOSUPERUSER/NOBYPASSRLS role before this migration, in
-- `tests/rls_refresh_token_scope.rs` (commit "test(p1e): RED"):
--
--   * `rotate` presented with a LIVE refresh token answered `NotFound`, so
--     `POST /v1/auth/refresh` 401s and every signed-in session in the
--     deployment dies at its first rotation;
--   * `find_active_by_hash` answered `None` for a row that is on disk,
--     unrevoked and unexpired.
--
-- WHY NOT A `SECURITY DEFINER` FUNCTION, which is the textbook answer and the
-- one migration 031 Part 2 reaches for on `users`. FORCE ROW LEVEL SECURITY
-- applies to the table OWNER too, so a SECURITY DEFINER function is filtered
-- by the policy unless its owner holds BYPASSRLS. Which role owns it, and
-- whether it carries BYPASSRLS, is a role-split decision that this workstream
-- does not own — 031 says so in as many words. The policy below needs no
-- privileged owner and no new role, so it can land now and does not pre-empt
-- that decision.
--
-- ===========================================================================
-- PART 1 — `workspace_isolation` must not RAISE on a recycled connection
-- ===========================================================================
--
-- 002's policy is
--   `workspace_id = current_setting('app.current_workspace_id', true)::uuid`.
-- `current_setting(..., true)` returns NULL only while the setting has never
-- been assigned in this session. Once ANY transaction on the connection has
-- run `set_config('app.current_workspace_id', …, true)` — which is what every
-- scoped repository call does — the setting reverts at COMMIT to the EMPTY
-- STRING, not to NULL, and stays that way for the life of the connection.
-- `''::uuid` is not a cast that returns NULL. It raises.
--
-- MEASURED, PostgreSQL 16, NOSUPERUSER/NOBYPASSRLS role, one session:
--
--   BEGIN; SELECT set_config('app.current_workspace_id', '<uuid>', true);
--   COMMIT;
--   SELECT current_setting('app.current_workspace_id', true) IS NULL;  -- f
--   SELECT count(*) FROM refresh_tokens;
--     ERROR:  invalid input syntax for type uuid: ""
--
-- So the "silent zero" this workstream is built around is only half the story
-- on a POOLED connection: the same statement returns the empty set on a fresh
-- connection and RAISES on one that has served a scoped transaction before.
-- Which of the two a given request gets is decided by pool checkout. That is
-- worse than either alone, and it is why this part comes first: the possession
-- probe in Part 2 arms no workspace scope, so on a recycled connection it
-- would hit this error every time and never reach its own policy.
--
-- WHAT THE REWRITE ADMITS: nothing. For every value `v` of the setting the
-- visible row set is unchanged —
--
--   v = a valid uuid  → identical predicate, identical rows;
--   v = NULL (never assigned) → `NULL::uuid` before, `NULL::uuid` after;
--   v = '' (assigned and released) → ERROR before, NULL after, and a NULL
--       predicate shows NO rows.
--
-- The only behaviour that changes is that the error becomes the invisibility
-- 002 already intended for an unarmed connection. The INSERT direction stays
-- LOUD: `USING` supplies `WITH CHECK` for a policy created without a command,
-- and an INSERT with the setting at '' is still rejected with
-- `new row violates row-level security policy for table "refresh_tokens"` —
-- measured, and pinned by
-- `an_unarmed_insert_is_still_rejected_not_silently_dropped`.
--
-- This is applied to `refresh_tokens` ONLY. The same landmine is in every
-- other `workspace_isolation` policy in this schema and is recorded in the
-- P1E report; sweeping all sixteen armed tables in a migration that ships a
-- new policy would put an unreviewed schema-wide change under a narrow title.
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS workspace_isolation ON refresh_tokens;

CREATE POLICY workspace_isolation ON refresh_tokens
    USING (
        workspace_id
        = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
    );

-- ===========================================================================
-- PART 2 — the possession probe
-- ===========================================================================
--
-- A refresh token is a BEARER credential. The security property the product
-- actually wants on a by-hash lookup is not "the caller is in this workspace"
-- — the caller has not proved which workspace it is in yet — it is "the caller
-- possesses the token". This policy says exactly that: a transaction may read
-- the row whose `token_hash` it NAMES, and nothing else.
--
-- EXACTLY WHAT IS NOW ADMITTED, each line measured on PostgreSQL 16 under a
-- NOSUPERUSER/NOBYPASSRLS role and pinned in
-- `tests/rls_refresh_token_scope.rs`:
--
--   * SELECT of the row whose `token_hash` equals the string this transaction
--     has placed in `app.refresh_token_probe`. `token_hash` is UNIQUE
--     (migration 002), so that is AT MOST ONE ROW.
--   * Nothing else. With the probe set to another workspace's token hash and
--     no workspace scope armed: SELECT saw 1 row, and on the same transaction
--     `UPDATE … WHERE token_hash = …` affected 0 rows, `DELETE` affected 0
--     rows, and a blind `UPDATE refresh_tokens SET revoked_at = NOW()`
--     affected 0 rows. The transaction COMMITTED and both rows were still
--     present and unrevoked on disk. `FOR SELECT` is load-bearing: an UPDATE
--     must also satisfy the UPDATE-applicable policies, and the only one is
--     `workspace_isolation`.
--   * No enumeration. The predicate is an EQUALITY on a value the caller
--     supplies; a `WHERE token_hash LIKE '%'` in the QUERY still returned 1
--     row, because the policy — not the query — decides visibility.
--   * Nothing when the probe is unset or names a hash that was never issued:
--     0 rows, measured both ways.
--
-- WHAT AN ATTACKER GAINS. To read a row they must first name its SHA-256. A
-- hash is derivable only from the raw token, which is 32 bytes of entropy, so
-- naming one means already holding that token. The marginal capability is
-- therefore: someone who ALREADY HOLDS a refresh token belonging to another
-- workspace can learn that token's `user_id`, `workspace_id` and `session_id`
-- — which they can already learn by presenting the token to
-- `POST /v1/auth/refresh`, because that is what the endpoint is for. It grants
-- no ability to revoke, rotate, delete or mint anything, and no ability to
-- discover a token they do not have. It does give an existence oracle for a
-- hash the caller can name, to a caller who can already execute arbitrary SQL
-- on the connection.
--
-- WHY THE VALUE IS A HASH AND NOT THE RAW TOKEN. The raw token would then
-- appear in `pg_stat_activity`, in `log_min_duration_statement` output and in
-- any query the DBA runs while the transaction is open. The hash is what the
-- table already stores.
--
-- WHY THIS GUC IS SAFE TO SET. `db::scope::begin_refresh_token_probe` sets it
-- with `set_config(…, true)` — TRANSACTION-LOCAL — and READS IT BACK before
-- returning the transaction, the same read-back FU1 added to
-- `begin_scoped`. A session-local `false` would leave one caller's token hash
-- armed on a pooled connection for whatever statement is handed it next.
-- Measured: after the probe transaction commits the setting reads back as ''
-- and a subsequent bare read sees 0 rows.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'refresh_tokens'
          AND policyname = 'refresh_token_possession'
    ) THEN
        CREATE POLICY refresh_token_possession ON refresh_tokens
            FOR SELECT
            USING (
                token_hash = current_setting('app.refresh_token_probe', true)
            );
    END IF;
END $$;

-- GRANT ON ALL TABLES applies only to tables that exist when it runs — same
-- reason migrations 002, 003, 018, 021, 023, 025, 026, 028, 030 and 031 repeat
-- it. RLS is a filter ON TOP of privileges, not a replacement for them.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
