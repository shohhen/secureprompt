-- FU4 — the three facts a refresh row was missing before it could be listed.
--
-- WHY THERE IS NO `user_sessions` TABLE HERE
--
-- WS4-3 reported that revocation was all-or-nothing "since no session record
-- exists". The obvious remedy is a session table written at login and pruned at
-- expiry. It is the wrong one, and the reason is that the record already
-- exists: `refresh_tokens` (migration 002) gets exactly ONE row per sign-in,
-- from `build_token_pair_body`, and one row per rotation, linked to its
-- predecessor by `replaced_by`. That row already carries the workspace, the
-- user, a creation time and an expiry; it is already closed by
-- `POST /v1/auth/logout`, by replay detection and by WS4-3's own revocation; it
-- is already under FORCE ROW LEVEL SECURITY; and it is already declared in
-- `GET /v1/data-inventory`.
--
-- A second table would therefore have bought a second source of truth that can
-- disagree with the first, a second lifetime to keep in step with `expires_at`,
-- a second write on the login request path, and a new class of personal data in
-- the compliance attestation. Three columns on the row that is already written
-- buy the same capability and add none of that. The login path gains no
-- statement — the same INSERT carries four more values.
--
-- WHAT WAS ACTUALLY MISSING
--
--   1. `session_id` — identity ACROSS rotation. Each `/v1/auth/refresh` writes
--      a new row, so a listing that counted rows would report a browser left
--      open for a day as ninety-six devices. The sign-in row seeds this with a
--      fresh UUID and every successor copies it, so the chain has one name.
--   2. `access_jti` — the id of the access token minted alongside the row. This
--      is what makes revocation NARROW: `jti_blacklist:{jti}` already exists
--      and WS4-3 correctly rejected it as an ADMIN seam, because "an admin
--      revoking a lost laptop has never seen that jti". That objection is about
--      discoverability, and it dies the moment sessions are listable — the
--      listing is where the jti comes from.
--   3. `client_ip` / `client_descriptor` — which device this is.
--
-- THE PERSONAL-DATA DECISION, MADE RATHER THAN DEFAULTED
--
-- WS4-3 deliberately kept IP and User-Agent OUT of `session_revocation_audit`,
-- on the stated ground that "nothing goes in here that we would not want kept
-- forever" — that table is NEVER purged. This is a different table with a
-- different lifetime and therefore a different answer, but the discipline is
-- the same and it is spelled out here rather than assumed:
--
--   * The raw `User-Agent` is NOT stored. It is a high-entropy fingerprint, and
--     on `POST /v1/auth/token` it is an unauthenticated, attacker-controlled
--     header of unbounded length — a raw column is a write primitive as well as
--     a privacy cost. What is stored is a derived descriptor from a CLOSED
--     vocabulary ("Chrome on macOS"): enough to tell one of your devices from
--     another, which is the entire purpose, and nothing more.
--   * `client_ip` IS stored, because "where is this account signed in from?" is
--     the question that prompts the revocation. It is written only when the
--     value parses as an IP address, so this column cannot become free text.
--   * BOTH are recorded ONCE, on the sign-in row, and are never re-recorded on
--     rotation. A column refreshed every fifteen minutes for the life of a
--     thirty-day refresh chain is a movement log, not a session list.
--   * BOTH are erased by `retention.purge` as soon as the session stops being
--     live (scope `refresh_tokens.device_context`). The ROW survives — deleting
--     it would break the replay detection that migration 002's header describes
--     — but the personal data on it does not. `GET /v1/data-inventory` declares
--     this as its own class with that mechanism.
--
-- The CHECK constraints below are the last line of that argument: they are what
-- makes "bounded, not free text" true of the database and not only of the
-- Rust that writes to it.

-- `DEFAULT gen_random_uuid()`, the same default migration 002 gives `id`, and
-- for the same reason: a refresh row that names no chain IS a chain of one, and
-- that is a truthful answer rather than a placeholder. It also means an INSERT
-- written before FU4 — of which this repository's own test seeders have
-- several — keeps working and produces a listable session rather than a
-- constraint violation.
--
-- The default does NOT let a rotation quietly fork a session: `rotate` supplies
-- `session_id` explicitly, copied from the row it replaces, and
-- `rotating_a_session_does_not_turn_it_into_two` fails if that copy is ever
-- dropped.
ALTER TABLE refresh_tokens ADD COLUMN session_id UUID DEFAULT gen_random_uuid();

-- Backfill. Every pre-existing row becomes its own session.
--
-- This looks like it fragments existing rotation chains, and it does — but not
-- visibly, and the reason is worth stating because it is what makes the simple
-- backfill correct. Single-use rotation means a chain has exactly ONE row with
-- `revoked_at IS NULL`: every predecessor was revoked by the rotation that
-- replaced it. The listing shows live sessions only, so a chain that existed
-- before this migration lists as exactly one entry — its current tip — and its
-- successors inherit that tip's id from here on. The only artefacts are that
-- such a session reports the last rotation as its start time and carries no
-- device context, both of which age out within one refresh lifetime.
UPDATE refresh_tokens SET session_id = id WHERE session_id IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN session_id SET NOT NULL;

ALTER TABLE refresh_tokens ADD COLUMN access_jti         TEXT;
ALTER TABLE refresh_tokens ADD COLUMN client_ip          TEXT;
ALTER TABLE refresh_tokens ADD COLUMN client_descriptor  TEXT;

-- 45 characters is the longest possible IPv6 text form
-- (`0000:...:0000:255.255.255.255`). 64 bounds a `{browser} on {os}` descriptor
-- drawn from a closed vocabulary with room to spare, and a UUID-shaped jti.
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_client_ip_bounded
    CHECK (client_ip IS NULL OR length(client_ip) <= 45);
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_client_descriptor_bounded
    CHECK (client_descriptor IS NULL OR length(client_descriptor) <= 64);
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_access_jti_bounded
    CHECK (access_jti IS NULL OR length(access_jti) <= 64);

-- The listing groups by session within one user, and the narrow revocation
-- resolves one session within one user. Both are covered by this index; the
-- existing partial index on `(user_id) WHERE revoked_at IS NULL` is not,
-- because the listing must read revoked rows too in order to decide that a
-- session is over.
CREATE INDEX idx_refresh_tokens_user_session
    ON refresh_tokens(user_id, session_id);

-- The device-context scrub in `retention.purge` looks for rows that still carry
-- context. Partial, so it indexes only the small live set rather than every
-- refresh row the deployment has ever issued.
CREATE INDEX idx_refresh_tokens_device_context
    ON refresh_tokens(session_id)
    WHERE client_ip IS NOT NULL OR client_descriptor IS NOT NULL;

-- ---------------------------------------------------------------------------
-- The revocation trail learns to say WHICH session.
--
-- NULL means "every session this user held" — WS4-3's user-wide lever, whose
-- rows all predate this column and are correctly NULL. A value means one
-- session was ended and the rest were left alone. Without this the trail cannot
-- distinguish an administrator who signed out one lost laptop from one who cut
-- off a person's access entirely, which is a difference an auditor cares about.
--
-- Nullable rather than defaulted for the reason migration 026 gives about
-- foreign keys: history must not be rewritten. Existing rows were user-wide
-- revocations and NULL is the truthful answer for them.
-- ---------------------------------------------------------------------------
ALTER TABLE session_revocation_audit ADD COLUMN session_id UUID;

-- No GRANT re-run: this migration creates no table, and column privileges are
-- inherited from the table grant that migrations 002 and 026 already issued.
