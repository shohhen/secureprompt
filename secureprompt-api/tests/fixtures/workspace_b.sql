-- Workspace B fixture for cross-tenant isolation tests.
--
-- SCOPING. `api_keys` and `policy_rules` are ENABLE + FORCE ROW LEVEL
-- SECURITY, so the inserts below are refused with `42501` unless
-- `app.current_workspace_id` names this workspace. The scope is set
-- TRANSACTION-LOCAL (`set_config(..., true)`) inside an explicit
-- BEGIN/COMMIT. The BEGIN/COMMIT is what makes `true` usable at all: with no
-- surrounding transaction each statement is its own implicit one, so the
-- setting would die with the `SELECT set_config` and the next INSERT would be
-- unarmed.
--
-- Transaction-local rather than session-local so this file cannot arm a
-- connection for whatever runs after it. sqlx 0.8.6 applies fixtures on a
-- dedicated connection that it closes before the test's pool is built
-- (`sqlx-core-0.8.6/src/testing/mod.rs::setup_test_db`), so a session-local
-- setting does not in fact reach the pool today — but that is an internal
-- detail of the harness and this file should not rest on it.

BEGIN;

INSERT INTO workspaces (id, name, created_at, updated_at)
VALUES (
    'bbbbbbbb-0000-0000-0000-000000000000',
    'Workspace B',
    NOW(),
    NOW()
);

SELECT set_config(
    'app.current_workspace_id',
    'bbbbbbbb-0000-0000-0000-000000000000',
    true
);

INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
VALUES (
    'bb000001-0000-0000-0000-000000000000',
    'bbbbbbbb-0000-0000-0000-000000000000',
    'default',
    'hash_workspace_b_key',
    NOW()
);

INSERT INTO policy_rules (
    id,
    workspace_id,
    name,
    priority,
    conditions,
    action,
    action_params,
    enabled,
    dry_run,
    created_at,
    updated_at
)
VALUES (
    'bb100001-0000-0000-0000-000000000000',
    'bbbbbbbb-0000-0000-0000-000000000000',
    'default deny',
    100,
    '[{"field":"detection_class","op":"eq","value":"email"}]',
    'redact',
    '{"placeholder_template":"[REDACTED:{class}:{hash8}]"}',
    true,
    false,
    NOW(),
    NOW()
);

COMMIT;
