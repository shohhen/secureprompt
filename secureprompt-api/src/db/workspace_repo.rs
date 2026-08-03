//! Workspace + owner-user creation in a single Postgres transaction.
//!
//! Used by `POST /v1/auth/register` to guarantee that a duplicate-email
//! failure on the users insert rolls back the workspace insert — no
//! orphaned workspace rows.

use chrono::{DateTime, Utc};
use secureprompt_common::{errors::ApiError, types::WorkspaceId};
use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::user_repo::UserRow;

/// Canonical PII classes seeded into every new workspace's "Redact common
/// PII" rule. Curated for high-precision / unambiguous categories — leaving
/// out `LOCATION` / `ORGANIZATION` / `GPE` since those fire on harmless
/// prompts like "tell me about Apple."
///
/// The detector pipeline normalizes classes via
/// `crate::detection::merge::normalize_class` before they reach policy
/// evaluation, so these MUST match the post-normalization spelling
/// (e.g. `EMAIL_ADDRESS`, not `EMAIL`).
///
/// WS2-1: the Uzbek / CIS identifier classes emitted by the deterministic
/// detection floor are listed here too. Detecting an identifier is not the
/// same as redacting it — this seeded rule makes `rules_evaluated == 1`,
/// which suppresses the `redact_when_no_rules` safety net in
/// `pipeline/service.rs`, and `policy/engine.rs::matching_detections` then
/// redacts only the classes named here whenever ANY listed class is present.
/// Omitting them meant a prompt containing both an email and a PINFL
/// redacted the email and forwarded the PINFL. Migration
/// `017_uzbek_identifier_policy_classes.sql` back-fills workspaces that were
/// already seeded with the narrower list.
///
/// FIX-WAVE: the same omission applied to EVERY CREDENTIAL CLASS. The list
/// carried 15 entries while `detection/registry.rs` emits 37, and not one of
/// the 15 was a credential — so a prompt containing an email AND a bearer
/// token redacted the email and shipped the token, because populating
/// `redaction_map` also suppressed the secure-mode catch-all. Five review
/// rounds of credential-detection work therefore delivered nothing on the
/// real chat path. Every credential class the registry emits is now listed,
/// back-filled by `019_credential_policy_classes.sql`.
///
/// Two entries were also DEAD NAMES matching nothing the registry ever
/// emits: `GCP_KEY` (registry emits `google_api_key` and
/// `gcp_service_account_email`) and `AZURE_KEY` (registry emits
/// `azure_storage_connection_string`). Both are replaced by the real
/// spellings below. Migration 019 leaves the dead strings in place in
/// existing rows — they match nothing, so removing them is churn, and the
/// superset guard the back-fill relies on is keyed on them.
///
/// `IBAN` sits alongside `IBAN_CODE` on purpose. Both spellings are live:
/// the Rust regex floor emits `iban`, which `normalize_class` only
/// upper-cases, while the Python sidecar's `_map_label` emits Presidio's
/// `IBAN_CODE`. Listing only the Presidio spelling left the floor's own IBAN
/// detections unprotected whenever the sidecar was down or the class came
/// from regex alone. The same reasoning applied to `SSN` / `US_SSN` until
/// both were demoted to `OPT_IN_ONLY_CLASSES` below — which is why BOTH had
/// to go: leaving either one in would have made the demotion cosmetic.
///
/// KEEP THIS IN SYNC WITH THE REGISTRY. It is checked by
/// `default_policy_classes_cover_every_registry_class` below, which fails
/// the build when a new detector class is added without a decision here.
/// A rot in this list is no longer a silent leak either — `fail_closed` in
/// `policy/engine.rs` makes a firing `redact` rule cover every detection in
/// the request — but the explicit list is what protects deployments that
/// have turned `SECUREPROMPT_REDACT_WHEN_NO_RULES` off.
///
/// A class may be ABSENT from this list only if `OPT_IN_ONLY_CLASSES` names
/// it. That is enforced, not merely intended: see
/// `the_exclusion_list_does_not_excuse_an_accidental_omission`.
pub const DEFAULT_POLICY_CLASSES: &[&str] = &[
    // ── People / contact PII (ML sidecar + floor) ──────────────────────
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    // ── Financial identifiers ──────────────────────────────────────────
    "CREDIT_CARD",
    // `US_SSN` / `SSN` are deliberately NOT here — see OPT_IN_ONLY_CLASSES.
    "IBAN_CODE",
    "IBAN",
    // ── Uzbek / CIS identifiers (WS2-1) ────────────────────────────────
    "PINFL",
    "STIR",
    "MFO",
    "PASSPORT_NUMBER",
    "UZCARD",
    "HUMO",
    // ── Cloud provider keys ────────────────────────────────────────────
    "AWS_ACCESS_KEY",
    "GOOGLE_API_KEY",
    "GCP_SERVICE_ACCOUNT_EMAIL",
    "AZURE_STORAGE_CONNECTION_STRING",
    // ── Vendor API keys ────────────────────────────────────────────────
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_SECRET_KEY",
    "STRIPE_PUBLISHABLE_KEY",
    // ── Source-control tokens ──────────────────────────────────────────
    "GITHUB_PAT",
    "GITHUB_FINE_GRAINED_PAT",
    "GITHUB_OAUTH_TOKEN",
    "GITHUB_REFRESH_TOKEN",
    // ── Slack tokens ───────────────────────────────────────────────────
    "SLACK_BOT_TOKEN",
    "SLACK_USER_TOKEN",
    "SLACK_APP_TOKEN",
    // ── Private keys ───────────────────────────────────────────────────
    "PRIVATE_KEY_PEM",
    "RSA_PRIVATE_KEY",
    "OPENSSH_PRIVATE_KEY",
    // ── Connection strings / URIs ──────────────────────────────────────
    "POSTGRESQL_URI",
    "MONGODB_URI",
    "WEBHOOK_URL",
    // ── Generic credentials ────────────────────────────────────────────
    "BEARER_TOKEN",
    "BASIC_AUTH_HEADER",
    "PASSWORD_ASSIGNMENT",
    "OAUTH_CLIENT_SECRET",
    "API_TOKEN_GENERIC",
    "JWT",
];

/// Detector classes that are deliberately NOT seeded into a new workspace's
/// "Redact common PII" rule — available, but OFF until an admin turns them
/// on. This is the one and only sanctioned way for a class to be missing
/// from `DEFAULT_POLICY_CLASSES`.
///
/// It exists because the drift guards must keep failing for an ACCIDENTAL
/// omission (that is the defect they were written for: the list carried 15
/// entries while the registry emitted 37, and not one of the 15 was a
/// credential) while still permitting a DELIBERATE one. Absence alone cannot
/// distinguish the two; a name on this list is the difference.
///
/// The guards that consult it live in `policy/failclosed_tests.rs`:
/// `default_policy_classes_cover_every_registry_class` (registry drift),
/// `opt_in_only_classes_contains_no_dead_names` (this list's own rot), and
/// `migration_020_backfills_default_policy_classes_plus_the_opt_ins`
/// (Rust ↔ SQL drift).
///
/// ── Why `SSN` / `US_SSN` (owner decision, 2026-07-30) ──────────────────
/// SecurePrompt is an Uzbekistan-market product; the US Social Security
/// Number is not a supported default class.
///
///   * `SOCIAL_SECURITY_NUMBER` appears ZERO times across every active
///     dataset under `data/**` — v5, v7, `v7_corpus_v2`/v3, `v7_hardened`,
///     `v8_corpus`, `spy_ruz`, `aug_*`. Its only occurrences are in the abandoned
///     v4 corpus under `docs/backup_v4/`, where the generator hallucinated a
///     Cyrillic "ССН" into Uzbek HR documents. The deployed v8 model has no
///     training support for it, and the label survives only as a dead entry
///     in `_V2_RAW_LABELS` (`secureprompt-ml/app/detection/xlmr_ner.py:129`).
///   * `compliance.py:9` maps `US_SSN → [GDPR, HIPAA]`; HIPAA is US
///     healthcare law and does not apply to this market.
///
/// DEMOTED, NOT DELETED. `Matcher::Ssn` and its `DetectorSpec` stay, so the
/// class is still DETECTED — it is only no longer redacted by the seeded
/// default. An admin re-enables it by adding the class to that rule in the
/// policy UI; `demoting_ssn_is_reversible_from_the_policy_ui` executes that
/// path rather than asserting it.
///
/// BOTH SPELLINGS ARE LISTED because both are live: the Rust floor emits
/// `ssn` (upper-cased to `SSN` by `merge::normalize_class`) and the Python
/// sidecar emits Presidio's `US_SSN`. Demoting one and not the other would
/// have been cosmetic.
///
/// THE PREREQUISITE, since the ordering is load-bearing: until `fa880be`
/// moved the bare-nine-digit backstop from `Matcher::Ssn` onto `stir`, `ssn`
/// was the ONLY detector that redacted an UNLABELLED Uzbek tax number —
/// `Matcher::Stir` is keyword-gated and needs a nearby `ИНН`/`STIR` label.
/// Demoting the class before that commit would have turned a mislabel into
/// a real leak. `a_bare_nine_digit_stir_survives_the_demotion` asserts the
/// no-leak property on redacted output.
///
/// Existing workspaces are reconciled by
/// `024_demote_ssn_to_opt_in.sql`, which strips both spellings from rules
/// that still exactly match the seeded default and leaves customised rules
/// alone.
pub const OPT_IN_ONLY_CLASSES: &[&str] = &["SSN", "US_SSN"];

#[derive(Debug, Clone)]
pub struct WorkspaceRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct WorkspaceRepository {
    pub pool: PgPool,
}

impl WorkspaceRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_id(&self, id: WorkspaceId) -> Result<Option<WorkspaceRow>, ApiError> {
        let row =
            sqlx::query("SELECT id, name, created_at, updated_at FROM workspaces WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(row.map(|record| WorkspaceRow {
            id: record.get("id"),
            name: record.get("name"),
            created_at: record.get("created_at"),
            updated_at: record.get("updated_at"),
        }))
    }

    pub async fn list_workspace_ids(&self) -> Result<Vec<WorkspaceId>, ApiError> {
        let rows = sqlx::query("SELECT id FROM workspaces ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| ApiError::Database(error.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|record| WorkspaceId(record.get("id")))
            .collect())
    }

    /// Insert a workspace and an owner user in a single transaction.
    ///
    /// * `password_hash` must already be Argon2id-encoded
    ///   (see `crate::db::user_repo::hash_password`).
    /// * `workspace_name` must be pre-trimmed (no leading/trailing whitespace).
    /// * On unique-email collision, returns `ApiError::Conflict` and the
    ///   transaction rolls back — no workspace row is left behind.
    ///
    /// # Errors
    /// `ApiError::Conflict` on duplicate email; `ApiError::Database` on any
    /// other sqlx failure.
    pub async fn create_with_owner(
        &self,
        workspace_name: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(WorkspaceRow, UserRow), ApiError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let ws_row = sqlx::query(
            "INSERT INTO workspaces (id, name, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, NOW(), NOW())
             RETURNING id, name, created_at, updated_at",
        )
        .bind(workspace_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        let ws = WorkspaceRow {
            id: ws_row.get("id"),
            name: ws_row.get("name"),
            created_at: ws_row.get("created_at"),
            updated_at: ws_row.get("updated_at"),
        };

        // Role is hardcoded to 'owner' here and is NOT included in the RETURNING
        // clause — the caller already knows the role. `UserRow` has no `role`
        // field; if a caller ever needs it, they must re-fetch (see
        // `UserRepository::find_by_email_with_role`).
        let user_row = sqlx::query(
            "INSERT INTO users (id, workspace_id, email, password_hash, role, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, $2, $3, 'owner', NOW(), NOW())
             RETURNING id, workspace_id, email, password_hash, created_at, updated_at",
        )
        .bind(ws.id)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unique") || msg.contains("duplicate") {
                ApiError::Conflict("email already in use".into())
            } else {
                ApiError::Database(msg)
            }
        })?;

        // Seed the workspace with a "Redact common PII" rule so chat
        // traffic is safe by default. Without this, brand-new workspaces
        // run with zero rules → policy engine returns `allow` → the
        // gateway forwards raw PII to the upstream model, which is
        // exactly what SecurePrompt exists to prevent. The fallback
        // gate in `pipeline/service.rs` (`redact_when_no_rules`) is the
        // safety net for workspaces created before this seed shipped;
        // this row is the explicit, dashboard-editable expression of
        // the same intent.
        //
        // Matched on the standard `detection_class IN [...]` engine
        // condition; admins can edit/disable it from the policy UI like
        // any other rule.
        let conditions = json!([
            { "field": "detection_class", "op": "in", "value": DEFAULT_POLICY_CLASSES }
        ]);
        sqlx::query(
            "INSERT INTO policy_rules
                (id, workspace_id, name, priority, conditions, action, action_params,
                 enabled, dry_run, created_at, updated_at)
             VALUES ($1, $2, 'Redact common PII', 100, $3, 'redact', '{}'::jsonb,
                     true, false, NOW(), NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(ws.id)
        .bind(&conditions)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Database(e.to_string()))?;

        // If we got this far, all three INSERTs succeeded — commit.
        tx.commit()
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        let user = UserRow {
            id: user_row.get("id"),
            workspace_id: user_row.get("workspace_id"),
            email: user_row.get("email"),
            password_hash: user_row.get("password_hash"),
            created_at: user_row.get("created_at"),
            updated_at: user_row.get("updated_at"),
            // Migration 016 (`totp_*` columns) — a freshly created owner has
            // never enrolled in 2FA, matching the columns' NULL/0 defaults.
            totp_secret_encrypted: None,
            totp_confirmed_at: None,
            totp_last_timestep: None,
            totp_failed_attempts: 0,
            totp_locked_until: None,
        };

        Ok((ws, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::user_repo::hash_password;

    #[sqlx::test]
    async fn creates_workspace_and_owner_user(pool: PgPool) {
        let repo = WorkspaceRepository::new(pool.clone());
        let hash = hash_password("pw-for-test-only").unwrap();

        let (ws, user) = repo
            .create_with_owner("Acme Inc", "owner@example.com", &hash)
            .await
            .expect("transaction must succeed");

        assert_eq!(ws.name, "Acme Inc");
        assert_eq!(user.email, "owner@example.com");
        assert_eq!(user.workspace_id, ws.id);

        let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(role, "owner");
    }

    #[sqlx::test]
    async fn seeds_default_redact_rule_for_new_workspace(pool: PgPool) {
        let repo = WorkspaceRepository::new(pool.clone());
        let hash = hash_password("pw-for-test-only").unwrap();

        let (ws, _) = repo
            .create_with_owner("Seeded Co", "seed@example.com", &hash)
            .await
            .expect("workspace + seed must succeed");

        let row = sqlx::query(
            "SELECT name, action, enabled, dry_run, conditions
             FROM policy_rules
             WHERE workspace_id = $1",
        )
        .bind(ws.id)
        .fetch_one(&pool)
        .await
        .expect("seed rule must exist");

        let name: String = row.get("name");
        let action: String = row.get("action");
        let enabled: bool = row.get("enabled");
        let dry_run: bool = row.get("dry_run");
        let conditions: serde_json::Value = row.get("conditions");

        assert_eq!(name, "Redact common PII");
        assert_eq!(action, "redact");
        assert!(enabled);
        assert!(!dry_run);
        // PERSON must be in the seeded class list — that's the entity that
        // motivated this seed (regression test for "name leaked because no
        // rule was configured").
        let class_list: Vec<&str> = conditions[0]["value"]
            .as_array()
            .expect("value array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            class_list.contains(&"PERSON"),
            "PERSON must be in the seeded redact list, got {class_list:?}"
        );
    }

    #[sqlx::test]
    async fn rolls_back_workspace_when_email_already_exists(pool: PgPool) {
        let repo = WorkspaceRepository::new(pool.clone());
        let hash = hash_password("pw").unwrap();

        // First insert — succeeds.
        repo.create_with_owner("First Workspace", "dup@example.com", &hash)
            .await
            .expect("first insert");

        let ws_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
            .fetch_one(&pool)
            .await
            .unwrap();

        // Second insert with same email — must conflict.
        let err = repo
            .create_with_owner("Second Workspace", "dup@example.com", &hash)
            .await
            .expect_err("second insert must fail");

        match err {
            ApiError::Conflict(_) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }

        let user_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            user_count_after, 1,
            "failed register must not orphan a partial user row"
        );

        // Workspace count must be unchanged — no orphan from the failed tx.
        let ws_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(ws_count_after, ws_count_before);
    }
}
