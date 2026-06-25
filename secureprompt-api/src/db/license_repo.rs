use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

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

    Ok(row.map(|r| ActivatedLicense {
        token: r.try_get("token").expect("token column"),
        updated_at: r.try_get("updated_at").expect("updated_at column"),
    }))
}

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
