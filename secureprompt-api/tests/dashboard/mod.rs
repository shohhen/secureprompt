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

#[path = "analytics_tests.rs"]
pub mod analytics;

#[path = "requests_tests.rs"]
pub mod requests;

#[path = "settings_tests.rs"]
pub mod settings;

#[path = "rls_matrix.rs"]
pub mod rls;

#[path = "users_tests.rs"]
pub mod users;

#[path = "secure_mode_tests.rs"]
pub mod secure_mode;
