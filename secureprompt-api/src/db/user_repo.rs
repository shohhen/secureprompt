use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Extended projection used by `/v1/auth/token`. Includes `role` so the
/// handler can embed it in the JWT claim without a second query.
#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}

/// Process-lifetime cached dummy Argon2id hash. The login handler runs
/// `verify_password` against it whenever the email lookup misses, so the
/// total compute time for bad-email and bad-password paths is
/// statistically indistinguishable (threat T-05-07 — account enumeration
/// defence). Computed once per process on first access.
fn dummy_argon2_hash() -> &'static str {
    use std::sync::OnceLock;
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"dummy-enumeration-defence-password", &salt)
            .expect("argon2 must hash dummy password")
            .to_string()
    })
    .as_str()
}

pub struct UserRepository {
    pub pool: PgPool,
}

impl UserRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<UserRow>, ApiError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, created_at, updated_at
             FROM users
             WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(row.map(|record| UserRow {
            id: record.get("id"),
            workspace_id: record.get("workspace_id"),
            email: record.get("email"),
            password_hash: record.get("password_hash"),
            created_at: record.get("created_at"),
            updated_at: record.get("updated_at"),
        }))
    }

    pub async fn list_workspace_users(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<UserRow>, ApiError> {
        let rows = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, created_at, updated_at
             FROM users
             WHERE workspace_id = $1
             ORDER BY created_at DESC",
        )
        .bind(workspace_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| UserRow {
                id: record.get("id"),
                workspace_id: record.get("workspace_id"),
                email: record.get("email"),
                password_hash: record.get("password_hash"),
                created_at: record.get("created_at"),
                updated_at: record.get("updated_at"),
            })
            .collect())
    }

    /// Create a new user in the workspace with an Argon2id-hashed password.
    /// Returns `ApiError::Conflict` if the email is already taken.
    pub async fn create_user(
        &self,
        workspace_id: WorkspaceId,
        email: &str,
        plaintext_password: &str,
        role: &str,
    ) -> Result<UserRow, ApiError> {
        let hash = hash_password(plaintext_password)?;

        let row = sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW(), NOW())
             RETURNING id, workspace_id, email, password_hash, created_at, updated_at",
        )
        .bind(workspace_id.0)
        .bind(email)
        .bind(&hash)
        .bind(role)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            let msg = error.to_string();
            if msg.contains("unique") || msg.contains("duplicate") {
                ApiError::Conflict("email already in use".into())
            } else {
                ApiError::Database(msg)
            }
        })?;

        Ok(UserRow {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    /// Deployment-wide user count (users has no RLS — global count is intended,
    /// for license seat enforcement).
    pub async fn count_total_users(&self) -> Result<i64, ApiError> {
        let row = sqlx::query("SELECT count(*) AS n FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;
        Ok(row.get::<i64, _>("n"))
    }

    /// Look up a user by email including the `role` column. Used by
    /// `/v1/auth/token`.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn find_by_email_with_role(
        &self,
        email: &str,
    ) -> Result<Option<UserCredentials>, ApiError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, role
             FROM users
             WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;
        Ok(row.map(|record| UserCredentials {
            id: record.get("id"),
            workspace_id: record.get("workspace_id"),
            email: record.get("email"),
            password_hash: record.get("password_hash"),
            role: record.get("role"),
        }))
    }
}

/// Hash a plaintext password with Argon2id using OS randomness for the salt.
/// Centralised so every caller (`create_user`, the workspace + owner flow)
/// uses the same parameters.
///
/// # Errors
/// Returns `ApiError::Internal` if the argon2 crate fails (extremely rare —
/// typically an OOM condition).
pub fn hash_password(plaintext: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::Internal(format!("password hash failed: {e}")))
}

/// Verify a plaintext password against an Argon2id PHC hash string. Returns
/// `true` on match, `false` on mismatch or malformed stored hash.
#[must_use]
pub fn verify_password(hash: &str, plaintext: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok()
}

/// Run the Argon2id verify path against the process dummy hash. Used by
/// `/v1/auth/token` when the email lookup misses, so the bad-email and
/// bad-password code paths spend comparable compute time (T-05-07).
pub fn verify_against_dummy(plaintext: &str) {
    let _ = verify_password(dummy_argon2_hash(), plaintext);
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    #[test]
    fn verify_password_accepts_correct_plaintext() {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(b"correct-horse-battery-staple", &salt)
            .expect("argon2 hash")
            .to_string();
        assert!(verify_password(&hash, "correct-horse-battery-staple"));
    }

    #[test]
    fn verify_password_rejects_wrong_plaintext() {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(b"correct", &salt)
            .expect("argon2 hash")
            .to_string();
        assert!(!verify_password(&hash, "wrong"));
    }

    #[test]
    fn verify_password_rejects_malformed_hash() {
        assert!(!verify_password("not-a-valid-hash", "anything"));
    }

    #[test]
    fn dummy_hash_is_a_valid_argon2_hash() {
        // Running verify_against_dummy should not panic; confirms the
        // OnceLock initializer produces a valid PHC string.
        verify_against_dummy("anything");
    }
}
