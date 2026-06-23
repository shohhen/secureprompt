//! Postgres persistence for the offline-revalidation overlay (spec §4.3).
//! Chosen over a local file so the high-water mark is consistent across GKE
//! replicas. All updates are monotone max-merges.

use sqlx::{PgPool, Row};

/// A row from `license_freshness`. Both fields are epoch-second integers.
pub struct FreshnessRow {
    pub last_assertion_at: i64,
    pub highwater_at: i64,
}

/// Load the freshness row for `lic_id`. Returns `None` when no row exists yet.
///
/// `lic_id` must be a valid UUID string; an invalid UUID returns `Ok(None)`
/// rather than an error so a misconfigured token doesn't surface a DB error.
pub async fn load(pool: &PgPool, lic_id: &str) -> sqlx::Result<Option<FreshnessRow>> {
    let id: uuid::Uuid = match lic_id.parse() {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let row = sqlx::query(
        r#"SELECT extract(epoch FROM last_assertion_at)::bigint AS last_assertion_at,
                  extract(epoch FROM highwater_at)::bigint      AS highwater_at
           FROM license_freshness
           WHERE lic_id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| FreshnessRow {
        last_assertion_at: r.get("last_assertion_at"),
        highwater_at: r.get("highwater_at"),
    }))
}

/// Upsert with monotone max-merge.
///
/// * `observed_assertion_at` — epoch-second of the verified assertion issued_at;
///   `None` on a no-credit tick (system clock bump only).
/// * `system_now` — current wall clock epoch-second; always advances `highwater_at`.
///
/// Invariants guaranteed by the GREATEST merge:
/// - `last_assertion_at` only ever increases (only moves on a verified assertion).
/// - `highwater_at` only ever increases (never decreases even on a clock rollback).
pub async fn record(
    pool: &PgPool,
    lic_id: &str,
    observed_assertion_at: Option<i64>,
    system_now: i64,
) -> sqlx::Result<()> {
    let id: uuid::Uuid = match lic_id.parse() {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    // assertion = 0 when None so that GREATEST(existing, to_timestamp(0)) leaves
    // last_assertion_at unchanged when there is no new assertion.
    let assertion = observed_assertion_at.unwrap_or(0);
    // The high-water seed is the max of the assertion time and the system clock.
    let hw_seed = assertion.max(system_now);

    sqlx::query(
        r#"
        INSERT INTO license_freshness (lic_id, last_assertion_at, highwater_at)
        VALUES ($1, to_timestamp($2), to_timestamp($3))
        ON CONFLICT (lic_id) DO UPDATE SET
            last_assertion_at = GREATEST(license_freshness.last_assertion_at, to_timestamp($2)),
            highwater_at      = GREATEST(license_freshness.highwater_at, to_timestamp($3)),
            updated_at        = now()
        "#,
    )
    .bind(id)
    .bind(assertion as f64)
    .bind(hw_seed as f64)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn record_is_max_merge(pool: sqlx::PgPool) -> sqlx::Result<()> {
        let lic = "7480afdb-cbc1-441c-83b2-4d315115829e";

        // Initially no row.
        assert!(load(&pool, lic).await?.is_none());

        // First record: assertion at epoch 1000, system_now = 1000.
        record(&pool, lic, Some(1000), 1000).await?;
        let r = load(&pool, lic).await?.unwrap();
        assert_eq!(r.last_assertion_at, 1000);
        assert_eq!(r.highwater_at, 1000);

        // A no-credit tick with a higher system clock bumps only the high-water.
        record(&pool, lic, None, 1500).await?;
        let r = load(&pool, lic).await?.unwrap();
        assert_eq!(r.last_assertion_at, 1000); // unchanged
        assert_eq!(r.highwater_at, 1500);      // raised

        // An OLDER system clock (rollback) must NOT lower the high-water.
        record(&pool, lic, None, 1200).await?;
        let r = load(&pool, lic).await?.unwrap();
        assert_eq!(r.highwater_at, 1500); // stays at the max

        Ok(())
    }

    #[sqlx::test]
    async fn invalid_uuid_returns_none(pool: sqlx::PgPool) -> sqlx::Result<()> {
        // An invalid UUID must return Ok(None) rather than propagating an error.
        assert!(load(&pool, "not-a-uuid").await?.is_none());
        // record() with an invalid UUID must also be a silent no-op.
        record(&pool, "not-a-uuid", Some(100), 100).await?;
        Ok(())
    }
}
