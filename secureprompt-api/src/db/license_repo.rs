use chrono::{DateTime, Utc};
use secureprompt_common::errors::ApiError;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::admin_audit_repo::{self, AdminActor, AdminAuditEntry};
use crate::db::scope::begin_scoped;

#[derive(Debug, Clone)]
pub struct ActivatedLicense {
    pub token: String,
    pub updated_at: DateTime<Utc>,
}

pub async fn get(pool: &PgPool) -> sqlx::Result<Option<ActivatedLicense>> {
    let row = sqlx::query(
        "SELECT token, updated_at FROM license_activation WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(ActivatedLicense {
            token: r.try_get("token")?,
            updated_at: r.try_get("updated_at")?,
        })),
        None => Ok(None),
    }
}

/// Store the activated token AND the record that somebody activated it, in one
/// transaction (P1A).
///
/// # Why the audit row is workspace-scoped when the license is not
///
/// `license_activation` is a singleton — one row, `id = 1`, for the whole
/// deployment. `admin_audit` is per-tenant under FORCE RLS, so the record lands
/// in the workspace of the ADMINISTRATOR who pasted the token, which is the
/// honest attribution available: the action was taken by a person, and that
/// person belongs to exactly one workspace. On the single-tenant on-prem
/// deployments this console targets the two are the same thing. On a
/// multi-tenant install another tenant's export will not carry this row, which
/// is stated in `CONTROL_COVERAGE` rather than left to be discovered.
///
/// # Errors
/// Returns `ApiError::Database` on SQL failure and `ApiError::Internal` when
/// the tenancy scope does not arm (see [`crate::db::scope`]).
pub async fn upsert_audited(
    pool: &PgPool,
    token: &str,
    activated_by: Option<Uuid>,
    actor: &AdminActor,
    entry: &AdminAuditEntry,
) -> Result<(), ApiError> {
    let mut tx = begin_scoped(pool, actor.workspace_id).await?;

    sqlx::query(
        "INSERT INTO license_activation (id, token, activated_by)
         VALUES (1, $1, $2)
         ON CONFLICT (id) DO UPDATE
             SET token        = EXCLUDED.token,
                 activated_by = EXCLUDED.activated_by,
                 updated_at   = now()",
    )
    .bind(token)
    .bind(activated_by)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::Database(e.to_string()))?;

    admin_audit_repo::write(&mut tx, actor, entry).await?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
    Ok(())
}

/// Remove the stored token AND record that somebody removed it, in one
/// transaction (P1A).
///
/// The removal is the more consequential half: it can take a running
/// deployment back to whatever the environment carries, or to Unlicensed.
///
/// # Errors
/// As [`upsert_audited`].
pub async fn clear_audited(
    pool: &PgPool,
    actor: &AdminActor,
    entry: &AdminAuditEntry,
) -> Result<(), ApiError> {
    let mut tx = begin_scoped(pool, actor.workspace_id).await?;

    sqlx::query("DELETE FROM license_activation WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

    admin_audit_repo::write(&mut tx, actor, entry).await?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;
    Ok(())
}

/// Unaudited write, for the `#[sqlx::test]` below and for nothing else.
///
/// Kept `#[cfg(test)]` on purpose: an unaudited path into `license_activation`
/// reachable from production code is exactly how the gap P1A closes reopens.
#[cfg(test)]
pub async fn upsert(pool: &PgPool, token: &str, activated_by: Option<Uuid>) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO license_activation (id, token, activated_by)
         VALUES (1, $1, $2)
         ON CONFLICT (id) DO UPDATE
             SET token        = EXCLUDED.token,
                 activated_by = EXCLUDED.activated_by,
                 updated_at   = now()",
    )
    .bind(token)
    .bind(activated_by)
    .execute(pool)
    .await?;

    Ok(())
}

/// As [`upsert`] — test-only, same reason.
#[cfg(test)]
pub async fn clear(pool: &PgPool) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM license_activation WHERE id = 1")
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn upsert_get_clear_roundtrip(pool: sqlx::PgPool) -> sqlx::Result<()> {
        assert!(get(&pool).await?.is_none());
        upsert(&pool, "tok-A", None).await?;
        assert_eq!(get(&pool).await?.unwrap().token, "tok-A");
        upsert(&pool, "tok-B", None).await?; // singleton: overwrites
        assert_eq!(get(&pool).await?.unwrap().token, "tok-B");
        clear(&pool).await?;
        assert!(get(&pool).await?.is_none());
        Ok(())
    }
}
