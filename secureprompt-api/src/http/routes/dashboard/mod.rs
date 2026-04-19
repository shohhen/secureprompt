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
// Plan 06-02: OIDC PKCE flow (AUTH-03).
pub mod oidc;
pub mod policy_rules;
pub mod providers;
pub mod requests;
pub mod role;

// Task 5-01-C wires `auth` into `Router::nest("/v1/auth", ...)`.
// Task 5-03-A wires `analytics` into `Router::nest("/v1/analytics", ...)`.
// Task 5-05-A wires `budgets` into `Router::nest("/v1/workspaces", ...)`.
// Task 5-04-B/C wires `keys`, `providers`, `policy_rules`, `requests`.
