-- WS2-3 — per-workspace policy for "the ML sidecar produced no coverage".
--
-- `MlSidecarClient::detect_if_available` used to return an empty detection
-- set on three fail-open paths (client unconfigured, client disabled, circuit
-- breaker OPEN) plus a fourth (every chunk call failed). An empty set is
-- indistinguishable from "there was no PII", so a sidecar outage silently
-- degraded the gateway to whatever the deterministic Rust floor caught and
-- still answered 200. This table makes that a deliberate choice per
-- workspace:
--
--   * 'block'              — fail closed. The request is rejected with a
--                            503 BEFORE it is forwarded to the provider.
--   * 'degrade_with_alert' — proceed on the deterministic floor alone, but
--                            emit an alert, set a response header, and mark
--                            the analytics row floor_only = true.
--
-- Shape deliberately mirrors migration 007's `workspace_secure_mode`: one row
-- per workspace, PK = workspace_id, ON DELETE CASCADE, upserted on write.
--
-- EXISTING WORKSPACES ARE NOT BACKFILLED, BY DESIGN. There is no
-- INSERT ... SELECT here; `SidecarPolicyRepository::get` returns 'block' when
-- no row exists. Rationale:
--   1. Fail-closed by ABSENCE. A backfill only covers workspaces that exist
--      at migration time; rows created afterwards (signup, seeding, tests,
--      any future code path) would have no row and would need the same
--      default-on-read anyway. Having exactly one rule — "no row means
--      block" — means there is no window in which a workspace is unprotected.
--   2. A backfilled row is indistinguishable from an operator's explicit
--      choice. Keeping the table empty until someone writes to it means
--      every row in it represents a real decision, which is what an auditor
--      reading this table needs.
--
-- NO ROW-LEVEL SECURITY, matching `workspace_secure_mode` (007) and unlike
-- `workspace_budgets` (003). The RLS policy used elsewhere keys off
-- `current_setting('app.current_workspace_id')`, which the pooled gateway
-- connection does not set on the request path; adding FORCE RLS here would
-- make every read return zero rows, i.e. every workspace would silently
-- revert to 'block' regardless of what it chose. Both the repository read
-- and write are parameterised by the authenticated workspace_id.

CREATE TABLE workspace_sidecar_policy (
    workspace_id UUID PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
    sidecar_unavailable TEXT NOT NULL DEFAULT 'block'
        CHECK (sidecar_unavailable IN ('block', 'degrade_with_alert')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workspace_sidecar_policy ON workspace_sidecar_policy(workspace_id);

-- Re-execute role grants for the new table (same as migration 003).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureprompt_app;
