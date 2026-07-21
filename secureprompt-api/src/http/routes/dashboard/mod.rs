//! Phase 5 — governance dashboard route umbrella.
//!
//! Each submodule returns a `Router<AppState>` so `http/mod.rs` can compose
//! them. Plan 05-01 ships `auth`; Plan 05-03 ships `analytics`; later plans
//! populate the remaining submodules.

pub mod analytics;
pub mod auth;
pub mod budgets;
// Plan 05-04 namespaces.
pub mod keys;
// Phase 7 / Task 30 — `/v1/me/*` for trusted server-to-server callers
// (LibreChat backend fetches the JWT-authed user's plaintext API key).
pub mod me;
// Plan 06-02: OIDC PKCE flow (AUTH-03).
pub mod oidc;
pub mod policy_rules;
pub mod providers;
pub mod requests;
pub mod role;
pub mod secure_mode;
// 2FA (Task 6): `/v1/auth/2fa/{enroll,verify}` — TOTP enrollment + first
// confirmation. Mounted under `/v1/auth` in `http/mod.rs` (Task 9).
pub mod twofactor;
pub mod users;

// Task 5-01-C wires `auth` into `Router::nest("/v1/auth", ...)`.
// Task 5-03-A wires `analytics` into `Router::nest("/v1/analytics", ...)`.
// Task 5-05-A wires `budgets` into `Router::nest("/v1/workspaces", ...)`.
// Task 5-04-B/C wires `keys`, `providers`, `policy_rules`, `requests`.
