//! Phase 5 / Plan 05-01 — `/v1/auth/{token,refresh,logout}` handlers.
//!
//! Task 5-01-B registers an empty router so `http/mod.rs` can nest
//! `/v1/auth` today; Task 5-01-C populates the three handlers and wires
//! `route_layer(jwt_mw)` onto `/logout` only.

use axum::Router;

use crate::app_state::AppState;

/// Returns an empty `Router<AppState>`. Replaced in Task 5-01-C with the
/// three handler routes plus the per-route JWT middleware for `/logout`.
#[must_use]
pub fn routes() -> Router<AppState> {
    Router::new()
}
