//! Phase 5 — governance dashboard route umbrella.
//!
//! Each submodule returns a `Router<AppState>` so `http/mod.rs` can compose
//! them. Plan 05-01 ships `auth`; later plans populate the remaining
//! submodules (they start as empty-router stubs so the router wiring is
//! stable across plans and Plan 02's codegen picks them up as they land).

pub mod auth;

// Task 5-01-C wires the `auth` submodule into `Router::nest("/v1/auth", ...)`
// in `http/mod.rs`. The remaining dashboard namespaces (analytics, requests,
// keys, providers, policy_rules, budgets) land in Plans 05-03 through 05-05.
