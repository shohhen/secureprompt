//! Phase 5 / Plan 05-01 — Dashboard integration tests.
//!
//! This file aggregates the three test modules:
//!   - `smoke`    — migrations apply cleanly + RLS is enabled (Task 5-01-A).
//!   - `fixtures` — seed two workspaces + users, shared by Plans 03/04/05/06.
//!   - `jwt`      — JWT middleware tamper-detection (Task 5-01-B).
//!   - `auth`     — token / refresh / logout handlers (Task 5-01-C).
//!
//! Each module lives under `tests/dashboard/` and is wired in via `mod.rs`.

#[path = "dashboard/mod.rs"]
mod dashboard;
