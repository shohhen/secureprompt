-- Workspace A fixture for cross-tenant isolation tests.

INSERT INTO workspaces (id, name, created_at, updated_at)
VALUES (
    'aaaaaaaa-0000-0000-0000-000000000000',
    'Workspace A',
    NOW(),
    NOW()
);

SELECT set_config(
    'app.current_workspace_id',
    'aaaaaaaa-0000-0000-0000-000000000000',
    false
);

INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
VALUES (
    'aa000001-0000-0000-0000-000000000000',
    'aaaaaaaa-0000-0000-0000-000000000000',
    'default',
    'hash_workspace_a_key',
    NOW()
);

INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
VALUES (
    'aa000002-0000-0000-0000-000000000000',
    'aaaaaaaa-0000-0000-0000-000000000000',
    'secondary',
    'hash_workspace_a_key_2',
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
    'aa100001-0000-0000-0000-000000000000',
    'aaaaaaaa-0000-0000-0000-000000000000',
    'default deny',
    100,
    '[{"field":"detection_class","op":"eq","value":"aws_access_key"}]',
    'deny',
    '{}',
    true,
    false,
    NOW(),
    NOW()
);
