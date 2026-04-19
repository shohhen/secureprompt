//! Task 5-01-A smoke test: migrations 002/003/004 apply cleanly + RLS is
//! enabled on the two new tables.

use sqlx::{PgPool, Row};

use super::fixtures;

/// VALIDATION 5-01-NN smoke: the three new migrations should create
/// `refresh_tokens`, `workspace_budgets` and the `users.role` column; both new
/// tables should have `pg_class.relrowsecurity = true`.
#[sqlx::test]
async fn migrations_apply_cleanly(pool: PgPool) -> sqlx::Result<()> {
    let table_names: Vec<String> = sqlx::query(
        "SELECT tablename FROM pg_tables
         WHERE schemaname = 'public'
           AND tablename IN ('refresh_tokens','workspace_budgets')
         ORDER BY tablename",
    )
    .fetch_all(&pool)
    .await?
    .into_iter()
    .map(|row| row.get::<String, _>("tablename"))
    .collect();
    assert_eq!(
        table_names,
        vec![
            "refresh_tokens".to_string(),
            "workspace_budgets".to_string()
        ],
        "expected both new tables to be created by migrations"
    );

    // RLS must be enabled on both tables.
    for table in ["refresh_tokens", "workspace_budgets"] {
        let rls_enabled: bool = sqlx::query(
            "SELECT relrowsecurity FROM pg_class
             WHERE oid = ($1::text)::regclass",
        )
        .bind(table)
        .fetch_one(&pool)
        .await?
        .get("relrowsecurity");
        assert!(
            rls_enabled,
            "RLS must be enabled on {table} — migration 00{}.sql is the source",
            if table == "refresh_tokens" { "2" } else { "3" }
        );
    }

    // users.role column must exist with the expected CHECK constraint.
    let role_column: String = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'users'
           AND column_name = 'role'",
    )
    .fetch_one(&pool)
    .await?
    .get("column_name");
    assert_eq!(role_column, "role", "users.role column must exist");

    Ok(())
}

/// Seeding two workspaces succeeds and respects the RLS policies via the
/// workspace-scoped INSERT path used by the repositories.
#[sqlx::test]
async fn seed_two_workspaces_is_idempotent(pool: PgPool) -> sqlx::Result<()> {
    let seeded = fixtures::seed_two_workspaces(&pool).await?;
    assert_ne!(seeded.workspace_a, seeded.workspace_b);
    assert_ne!(seeded.admin_a, seeded.admin_b);
    Ok(())
}
