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
    /// AES-GCM-encrypted TOTP secret bytes (via `state.kms`). `None` until
    /// enrollment starts. The repo never encrypts/decrypts this — callers
    /// own that via the KMS abstraction (migration 016).
    pub totp_secret_encrypted: Option<Vec<u8>>,
    /// Set once the user confirms their first valid TOTP code. `None` means
    /// "enrollment not completed" even if a secret has been set.
    pub totp_confirmed_at: Option<DateTime<Utc>>,
    /// Last accepted RFC 6238 timestep (30s units), for replay prevention.
    pub totp_last_timestep: Option<i64>,
    /// Consecutive failed verification attempts since the last success.
    pub totp_failed_attempts: i32,
    /// If set and in the future, TOTP/backup-code verification is locked out.
    pub totp_locked_until: Option<DateTime<Utc>>,
}

/// Extended projection used by `/v1/auth/token`.
///
/// Includes `role` so the handler can embed it in the JWT claim without a
/// second query, and `totp_confirmed_at` (2FA, Task 5) so the login
/// handler can decide access-vs-challenge-vs-enroll without a second query.
#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub totp_confirmed_at: Option<DateTime<Utc>>,
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
            "SELECT id, workspace_id, email, password_hash, created_at, updated_at,
                    totp_secret_encrypted, totp_confirmed_at, totp_last_timestep,
                    totp_failed_attempts, totp_locked_until
             FROM users
             WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(row.map(row_to_user))
    }

    /// Look up a user by primary key, including the TOTP enrollment/lockout
    /// state (`totp_*` columns from migration 016). Used by the 2FA
    /// enroll/verify/challenge/disable handlers, which authenticate via a
    /// purpose-scoped token carrying only a `user_id`.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn find_by_id(&self, user_id: Uuid) -> Result<Option<UserRow>, ApiError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, created_at, updated_at,
                    totp_secret_encrypted, totp_confirmed_at, totp_last_timestep,
                    totp_failed_attempts, totp_locked_until
             FROM users
             WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.map(row_to_user))
    }

    pub async fn list_workspace_users(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<UserRow>, ApiError> {
        let rows = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, created_at, updated_at,
                    totp_secret_encrypted, totp_confirmed_at, totp_last_timestep,
                    totp_failed_attempts, totp_locked_until
             FROM users
             WHERE workspace_id = $1
             ORDER BY created_at DESC",
        )
        .bind(workspace_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows.into_iter().map(row_to_user).collect())
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
             RETURNING id, workspace_id, email, password_hash, created_at, updated_at,
                       totp_secret_encrypted, totp_confirmed_at, totp_last_timestep,
                       totp_failed_attempts, totp_locked_until",
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

        Ok(row_to_user(row))
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

    /// Look up a user by email including the `role` column and TOTP
    /// enrollment state. Used by `/v1/auth/token` (2FA, Task 5 — the
    /// `totp_confirmed_at` column feeds `decide_2fa` so the handler can
    /// branch access/challenge/enroll without a second query).
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn find_by_email_with_role(
        &self,
        email: &str,
    ) -> Result<Option<UserCredentials>, ApiError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, email, password_hash, role, totp_confirmed_at
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
            totp_confirmed_at: record.get("totp_confirmed_at"),
        }))
    }

    // ---- TOTP 2FA (migration 016) -----------------------------------

    /// Begin (or restart) TOTP enrollment: store the encrypted secret and
    /// clear any prior confirmation. `encrypted` is already ciphertext —
    /// the caller encrypts it via `state.kms` before calling this; the
    /// repo never sees the plaintext secret.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` if `user_id` doesn't exist,
    /// `ApiError::Database` for pool/query failures.
    pub async fn set_totp_secret(&self, user_id: Uuid, encrypted: &[u8]) -> Result<(), ApiError> {
        let result = sqlx::query(
            "UPDATE users
             SET totp_secret_encrypted = $2,
                 totp_confirmed_at = NULL
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(encrypted)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        require_row(result, user_id)
    }

    /// Mark enrollment complete after the first valid code is verified.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` if `user_id` doesn't exist,
    /// `ApiError::Database` for pool/query failures.
    pub async fn confirm_totp(&self, user_id: Uuid) -> Result<(), ApiError> {
        let result = sqlx::query("UPDATE users SET totp_confirmed_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        require_row(result, user_id)
    }

    /// Turn TOTP off: clears the secret, confirmation, replay state, and
    /// lockout counters, and deletes all backup codes. Runs in a single
    /// transaction so a mid-way failure can't leave orphaned backup codes
    /// for a user with no secret.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` if `user_id` doesn't exist,
    /// `ApiError::Database` for pool/query/transaction failures.
    pub async fn disable_totp(&self, user_id: Uuid) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        let result = sqlx::query(
            "UPDATE users
             SET totp_secret_encrypted = NULL,
                 totp_confirmed_at = NULL,
                 totp_last_timestep = NULL,
                 totp_failed_attempts = 0,
                 totp_locked_until = NULL
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if result.rows_affected() == 0 {
            // Transaction drops here without commit → auto-rollback.
            return Err(ApiError::NotFound(format!("user {user_id} not found")));
        }

        sqlx::query("DELETE FROM user_backup_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    /// Record a successful TOTP verification: persist the accepted
    /// timestep (replay prevention — `verify_code` rejects anything ≤
    /// this on the next attempt) and clear the failure/lockout counters.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` if `user_id` doesn't exist,
    /// `ApiError::Database` for pool/query failures.
    pub async fn record_totp_success(&self, user_id: Uuid, timestep: i64) -> Result<(), ApiError> {
        let result = sqlx::query(
            "UPDATE users
             SET totp_last_timestep = $2,
                 totp_failed_attempts = 0,
                 totp_locked_until = NULL
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(timestep)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        require_row(result, user_id)
    }

    /// Record a failed TOTP/backup-code verification: increments the
    /// failure counter and, once it reaches `lock_threshold`, sets
    /// `totp_locked_until = now() + lock_secs`. The threshold check and
    /// increment happen in one statement (both read the pre-update
    /// `totp_failed_attempts`, so they agree on the same count).
    ///
    /// Returns the new attempt count so the caller can report it / decide
    /// whether the account just crossed into lockout.
    ///
    /// # Errors
    /// Returns `ApiError::NotFound` if `user_id` doesn't exist,
    /// `ApiError::Database` for pool/query failures.
    pub async fn record_totp_failure(
        &self,
        user_id: Uuid,
        lock_threshold: i32,
        lock_secs: i64,
    ) -> Result<i32, ApiError> {
        let row = sqlx::query(
            "UPDATE users
             SET totp_failed_attempts = totp_failed_attempts + 1,
                 totp_locked_until = CASE
                     WHEN totp_failed_attempts + 1 >= $2
                         THEN NOW() + make_interval(secs => $3::double precision)
                     ELSE totp_locked_until
                 END
             WHERE id = $1
             RETURNING totp_failed_attempts",
        )
        .bind(user_id)
        .bind(lock_threshold)
        .bind(lock_secs)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let record = row.ok_or_else(|| ApiError::NotFound(format!("user {user_id} not found")))?;
        Ok(record.get::<i32, _>("totp_failed_attempts"))
    }

    /// Insert pre-hashed backup codes (10 per enrollment). `hashes` are
    /// Argon2 PHC strings produced by the caller via `hash_password` —
    /// the repo stores hashes only, never plaintext codes.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn insert_backup_codes(
        &self,
        user_id: Uuid,
        hashes: &[String],
    ) -> Result<(), ApiError> {
        if hashes.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO user_backup_codes (id, user_id, code_hash, created_at)
             SELECT gen_random_uuid(), $1, code_hash, NOW()
             FROM UNNEST($2::text[]) AS code_hash",
        )
        .bind(user_id)
        .bind(hashes)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// Consume a single-use backup code: Argon2-verifies `code_plain`
    /// against every unused hash for the user, and atomically marks the
    /// first match as used (the `used_at IS NULL` guard in the UPDATE
    /// makes this race-safe under concurrent challenge attempts — if
    /// another request wins the race on the same row, this falls through
    /// to try the remaining candidates rather than reporting success).
    ///
    /// Returns `true` iff a code was matched and consumed.
    ///
    /// # Errors
    /// Returns `ApiError::Database` for pool/query failures.
    pub async fn consume_backup_code(
        &self,
        user_id: Uuid,
        code_plain: &str,
    ) -> Result<bool, ApiError> {
        let candidates = sqlx::query(
            "SELECT id, code_hash FROM user_backup_codes
             WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        for record in candidates {
            let id: Uuid = record.get("id");
            let hash: String = record.get("code_hash");
            if !verify_password(&hash, code_plain) {
                continue;
            }
            let result = sqlx::query(
                "UPDATE user_backup_codes SET used_at = NOW()
                 WHERE id = $1 AND used_at IS NULL",
            )
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
            if result.rows_affected() == 1 {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Map an sqlx query result row into `UserRow`. Shared by every method that
/// selects/returns the full `users` projection so the 11-field mapping
/// lives in exactly one place.
///
/// Takes `PgRow` by value (not `&PgRow`) so it drops in directly as
/// `.map(row_to_user)` / `row_to_user(row)` at every call site below,
/// mirroring the `db_err`-style helpers this file and `refresh_token_repo.rs`
/// already use the same way with `sqlx::Error`.
#[allow(clippy::needless_pass_by_value)]
fn row_to_user(record: sqlx::postgres::PgRow) -> UserRow {
    UserRow {
        id: record.get("id"),
        workspace_id: record.get("workspace_id"),
        email: record.get("email"),
        password_hash: record.get("password_hash"),
        created_at: record.get("created_at"),
        updated_at: record.get("updated_at"),
        totp_secret_encrypted: record.get("totp_secret_encrypted"),
        totp_confirmed_at: record.get("totp_confirmed_at"),
        totp_last_timestep: record.get("totp_last_timestep"),
        totp_failed_attempts: record.get("totp_failed_attempts"),
        totp_locked_until: record.get("totp_locked_until"),
    }
}

/// Shared `sqlx::Error -> ApiError` mapping for the TOTP methods below.
/// By-value so it drops in directly as `.map_err(db_err)` (same idiom as
/// `refresh_token_repo.rs`'s `db_err` / `db/mod.rs`'s `api_error_from_sqlx`).
#[allow(clippy::needless_pass_by_value)]
fn db_err(error: sqlx::Error) -> ApiError {
    ApiError::Database(error.to_string())
}

/// Turn a zero-rows-affected `UPDATE ... WHERE id = $1` into
/// `ApiError::NotFound`; used by the single-row TOTP state updates.
#[allow(clippy::needless_pass_by_value)]
fn require_row(result: sqlx::postgres::PgQueryResult, user_id: Uuid) -> Result<(), ApiError> {
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound(format!("user {user_id} not found")));
    }
    Ok(())
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

    /// DB-free roundtrip for the backup-code hashing path: enrollment
    /// hashes each plaintext backup code with `hash_password` before
    /// `insert_backup_codes` stores it, and `consume_backup_code`
    /// Argon2-verifies a plaintext attempt with `verify_password` against
    /// the stored hash. No new hashing helper was factored out — this
    /// exercises the exact `hash_password`/`verify_password` pair those
    /// two repo methods rely on.
    #[test]
    fn backup_code_hash_then_verify_roundtrip() {
        let hash = hash_password("QZXR-7KPD-2M4N").expect("hash_password succeeds");
        assert!(verify_password(&hash, "QZXR-7KPD-2M4N"));
        assert!(!verify_password(&hash, "WRONG-CODE-0000"));
    }
}
