//! Dashboard integration test registry.
//!
//! Submodules are grouped by the plan task that introduces them.

#[path = "fixtures.rs"]
pub mod fixtures;

#[path = "smoke.rs"]
pub mod smoke;

#[path = "jwt.rs"]
pub mod jwt;

#[path = "auth_tests.rs"]
pub mod auth;

#[path = "budgets_tests.rs"]
pub mod budgets;
