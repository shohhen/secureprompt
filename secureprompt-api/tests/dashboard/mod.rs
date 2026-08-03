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

#[path = "auth_register_tests.rs"]
pub mod auth_register;

#[path = "budgets_tests.rs"]
pub mod budgets;

#[path = "analytics_tests.rs"]
pub mod analytics;

#[path = "requests_tests.rs"]
pub mod requests;

#[path = "settings_tests.rs"]
pub mod settings;

// MR1 review I5: the file proves application tenancy (handler IDOR guards +
// query predicates), not Postgres RLS — `#[sqlx::test]` connects as a
// BYPASSRLS superuser. The module carries the accurate name so the test IDs
// cargo prints do too; the file keeps its path because dated plan/audit docs
// cite it. See that file's header for the whole argument.
#[path = "rls_matrix.rs"]
pub mod cross_tenant_idor;

#[path = "users_tests.rs"]
pub mod users;

#[path = "secure_mode_tests.rs"]
pub mod secure_mode;

// WS4-3 — admin-initiated session revocation.
#[path = "session_revocation_tests.rs"]
pub mod session_revocation;

// FU4 — listing the sessions a user holds, and ending ONE of them.
#[path = "session_listing_tests.rs"]
pub mod session_listing;
