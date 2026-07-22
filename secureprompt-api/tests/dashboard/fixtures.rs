//! Dashboard test fixtures — seeds two workspaces with distinct users and API
//! keys. Reused by Plans 03/04/05/06 cross-tenant matrix tests (per D-13 +
//! threat T-05-05).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use secureprompt_api::db::api_key_repo::hash_api_key;
use sqlx::PgPool;
use uuid::Uuid;

#[allow(dead_code)]
pub const WS_A_UUID: &str = "cafe0a00-0000-0000-0000-000000000000";
#[allow(dead_code)]
pub const WS_B_UUID: &str = "cafe0b00-0000-0000-0000-000000000000";

#[allow(dead_code)]
pub const ADMIN_A_EMAIL: &str = "admin-a@example.com";
#[allow(dead_code)]
pub const VIEWER_A_EMAIL: &str = "viewer-a@example.com";
#[allow(dead_code)]
pub const ADMIN_B_EMAIL: &str = "admin-b@example.com";
#[allow(dead_code)]
pub const VIEWER_B_EMAIL: &str = "viewer-b@example.com";

#[allow(dead_code)]
pub const SHARED_PASSWORD: &str = "test-password-1234";

#[allow(dead_code)]
pub const API_KEY_A: &str = "sp_wsAplaintext0000000000000000000000";
#[allow(dead_code)]
pub const API_KEY_B: &str = "sp_wsBplaintext0000000000000000000000";

/// Seed identifiers returned to the caller for assertions.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SeededWorkspaces {
    pub workspace_a: Uuid,
    pub workspace_b: Uuid,
    pub admin_a: Uuid,
    pub viewer_a: Uuid,
    pub admin_b: Uuid,
    pub viewer_b: Uuid,
}

/// Unique workspace fixture used by Plan 05-05 budget tests. Every test
/// gets a fresh `(workspace_id, admin_user_id, viewer_user_id)` triple plus
/// login credentials so concurrent runs never collide on Redis budget
/// counter keys (which are keyed by workspace UUID).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UniqueWorkspace {
    pub workspace_id: Uuid,
    pub admin_id: Uuid,
    pub viewer_id: Uuid,
    pub admin_email: String,
    pub viewer_email: String,
    pub password: String,
}

/// Seed a workspace with a fresh UUID + unique admin/viewer emails. Each
/// test should call this so its Redis budget keys are uniquely namespaced.
#[allow(dead_code)]
pub async fn seed_unique_workspace(pool: &PgPool) -> sqlx::Result<UniqueWorkspace> {
    let workspace_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let viewer_id = Uuid::new_v4();
    let suffix = format!("{}", Uuid::new_v4().simple()); // 32 hex chars
    let admin_email = format!("admin-{suffix}@example.com");
    let viewer_email = format!("viewer-{suffix}@example.com");
    let password = SHARED_PASSWORD.to_owned();
    let password_hash = hash_password(&password);

    sqlx::query(
        "INSERT INTO workspaces (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(workspace_id)
    .bind(format!("Workspace {suffix}"))
    .execute(pool)
    .await?;

    for (user_id, email, role) in [
        (admin_id, &admin_email, "admin"),
        (viewer_id, &viewer_email, "viewer"),
    ] {
        sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(workspace_id)
        .bind(email)
        .bind(&password_hash)
        .bind(role)
        .execute(pool)
        .await?;
    }

    Ok(UniqueWorkspace {
        workspace_id,
        admin_id,
        viewer_id,
        admin_email,
        viewer_email,
        password,
    })
}

/// Mint a JWT access token directly for the given workspace/user/role,
/// bypassing the `/v1/auth/token` HTTP endpoint entirely.
///
/// 2FA collateral fix: `POST /v1/auth/token` now forces Owner/Admin roles
/// into the enrollment branch (202 `enroll_required`) instead of returning
/// an access token (see `dashboard::routes::auth::decide_2fa`). Tests that
/// only need an authenticated admin *session* to exercise some other
/// surface (budgets, RLS, ...) — and are not themselves testing the login
/// flow — should mint the token directly with this helper instead of
/// logging in as an Owner/Admin fixture. This is the same pattern
/// `dashboard::settings_tests::mint_jwt` used before 2FA existed, extracted
/// here so every fixture-consuming test file can share it. Tests that
/// genuinely exercise the login/refresh/logout flow itself must keep going
/// through the real HTTP endpoint (see `dashboard::auth_tests`).
#[allow(dead_code)]
pub fn mint_jwt(secret: &str, workspace_id: Uuid, user_id: Uuid, role: &str) -> String {
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::Serialize;

    // Deliberately omits the `purpose` claim (`purpose: Option<String>` on
    // the real `jwt_auth::Claims`) so this always mints a normal, purposeless
    // access token — the real struct marks it
    // `#[serde(default, skip_serializing_if = "Option::is_none")]`, so a
    // missing field decodes as `None` exactly like a real access token.
    #[derive(Serialize)]
    struct Claims {
        sub: Uuid,
        ws: Uuid,
        role: String,
        iat: i64,
        exp: i64,
        jti: String,
    }

    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        ws: workspace_id,
        role: role.to_owned(),
        iat: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(),
        jti: Uuid::new_v4().to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("mint test JWT")
}

/// Hash a plaintext password with Argon2id using a fresh random salt.
/// Used both by the fixture seeder and by the refresh-token tests.
#[allow(dead_code)]
pub fn hash_password(plaintext: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .expect("argon2 hash must succeed with a valid salt")
        .to_string()
}

/// Seed two workspaces, an admin + viewer per workspace, and one API key per
/// workspace. Returns the UUIDs so tests can assert equality.
#[allow(dead_code)]
pub async fn seed_two_workspaces(pool: &PgPool) -> sqlx::Result<SeededWorkspaces> {
    let workspace_a = Uuid::parse_str(WS_A_UUID).expect("valid WS_A_UUID");
    let workspace_b = Uuid::parse_str(WS_B_UUID).expect("valid WS_B_UUID");

    for (workspace_id, name) in [
        (workspace_a, "Workspace A"),
        (workspace_b, "Workspace B"),
    ] {
        sqlx::query(
            "INSERT INTO workspaces (id, name, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(workspace_id)
        .bind(name)
        .execute(pool)
        .await?;
    }

    let password_hash = hash_password(SHARED_PASSWORD);

    let admin_a = Uuid::new_v4();
    let viewer_a = Uuid::new_v4();
    let admin_b = Uuid::new_v4();
    let viewer_b = Uuid::new_v4();

    for (user_id, workspace_id, email, role) in [
        (admin_a, workspace_a, ADMIN_A_EMAIL, "admin"),
        (viewer_a, workspace_a, VIEWER_A_EMAIL, "viewer"),
        (admin_b, workspace_b, ADMIN_B_EMAIL, "admin"),
        (viewer_b, workspace_b, VIEWER_B_EMAIL, "viewer"),
    ] {
        sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
        )
        .bind(user_id)
        .bind(workspace_id)
        .bind(email)
        .bind(&password_hash)
        .bind(role)
        .execute(pool)
        .await?;
    }

    for (workspace_id, raw_key) in [
        (workspace_a, API_KEY_A),
        (workspace_b, API_KEY_B),
    ] {
        sqlx::query(
            "INSERT INTO api_keys (id, workspace_id, name, key_hash, created_at)
             VALUES ($1, $2, $3, $4, NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(workspace_id)
        .bind("default")
        .bind(hash_api_key(raw_key))
        .execute(pool)
        .await?;
    }

    Ok(SeededWorkspaces {
        workspace_a,
        workspace_b,
        admin_a,
        viewer_a,
        admin_b,
        viewer_b,
    })
}
