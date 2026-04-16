-- Workspace B fixture for cross-tenant isolation tests.

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
    false
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
