/// WS4-1 / Task 19 — the `audit.export` control: page bytes, digest chain,
/// manifest, Ed25519 signature. Lives here because the worker produces it and
/// the API serves it, and there must be exactly one definition of "signed".
pub mod audit_export;
pub mod config;
pub mod crypto;
pub mod errors;
pub mod kms;      // Phase 7 / Plan 07-01
pub mod pipeline;
pub mod tasks;    // Phase 6 / Plan 06-04
pub mod telemetry;
pub mod types;

pub use errors::{ApiError, AppError};
pub use types::{ProviderId, RequestId, UserId, WorkspaceId};
