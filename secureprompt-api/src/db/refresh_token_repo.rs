//! Phase 5 / Plan 05-01 — refresh-token repository.
//!
//! Skeleton in Task 5-01-B (just enough for `AppState` to compile). Methods
//! `insert`, `rotate`, `revoke_all_for_user`, `find_active_by_hash` land in
//! Task 5-01-C, which will also add `hash_refresh_token` and
//! `RotationOutcome`.

use sqlx::PgPool;

pub struct RefreshTokenRepository {
    pub pool: PgPool,
}

impl RefreshTokenRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
