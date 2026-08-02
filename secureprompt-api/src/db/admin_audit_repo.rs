//! FU5 — the single writer of `admin_audit`, the administrative audit trail.
//!
//! # One table, and what that buys
//!
//! Migration 028's header carries the storage argument in full. The short form:
//! `audit_export::ControlRow` is already a normalised `event_type` + JSONB
//! `detail` shape, this table is that shape at rest, and the exporter reads it
//! with one unfiltered query that passes [`AdminAuditAction::as_str`] straight
//! through as `event_type`. There is no per-action code in the export path, so
//! a newly audited action cannot be missing from the export — there is nothing
//! to add.
//!
//! # Every write is in a transaction, and almost every one is the caller's
//!
//! [`write`] takes a `&mut Transaction` rather than a pool, so the audit row
//! commits with the action it describes or neither commits. That is WS4-3's
//! rule (`session_revocation_repo::write_audit`) and
//! `RawCaptureRepository::upsert_audited`'s before it: a control whose audit
//! trail can fail independently of the control is a control with a silent mode.
//!
//! P1A added two actions that CANNOT share a transaction with what they
//! record, and they are named here rather than left as exceptions somebody
//! discovers: `auth.login_succeeded` and `auth.second_factor_verified`. The
//! "action" for a login is the issuance of a session, which belongs to FU4's
//! refresh-token chain, and for the two 2FA-gated outcomes there is no database
//! write at all — the handler mints a five-minute purpose token and returns
//! 202. Both are therefore written FIRST, in a scoped transaction of their own,
//! and a failure returns before anything is issued. The guarantee that survives
//! is the one that matters — no session is issued without a record of the login
//! that opened it — and the residual, over-reporting a login whose session
//! issuance then failed, is written down in
//! `dashboard::auth::record_login` along with the availability consequence.
//!
//! WHAT HAPPENS WHEN THE AUDIT WRITE ITSELF FAILS, stated rather than left to
//! be discovered: the `?` propagates, the caller's transaction is dropped
//! without a commit, Postgres rolls it back, and the HTTP handler returns an
//! error. The administrative action does NOT take effect. That is the correct
//! direction — an action that happened with no record of it is a trail that
//! lies, and this product is sold on the trail. The cost is that a defect in
//! this module takes the write path down with it, which is why the `detail`
//! builders here are total functions over values the caller already holds and
//! perform no I/O, no parsing and no allocation that can fail.
//!
//! # The RLS silent-zero trap
//!
//! `admin_audit` is under FORCE ROW LEVEL SECURITY keyed on
//! `app.current_workspace_id` (migration 028). Every caller reaches [`write`]
//! from inside a transaction that has already armed that GUC, and the INSERT
//! would be REJECTED rather than silently dropped if one had not — the loud
//! half of the trap described in [`crate::db::scope`]. The silent half bites
//! READS, which is why the export's reader arms and reads back.

use secureprompt_common::errors::ApiError;
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// The longest `target_label` this table accepts.
///
/// Enforced HERE by truncation and AGAIN by
/// `admin_audit_target_label_bounded` in migration 028, so a writer that
/// forgets to truncate fails loudly rather than accumulating unbounded
/// administrator-supplied text in a table that is never purged.
pub const TARGET_LABEL_MAX: usize = 200;

/// Declare the audited vocabulary ONCE.
///
/// MR4 F8: the enum, [`AdminAuditAction::ALL`] and [`AdminAuditAction::as_str`]
/// used to be three hand-written lists, and the type's own docs called that "a
/// chain of failures". Three of the four links held. The fourth — *the variant
/// must appear in `ALL` at all* — was enforced by nothing: `ALL` was a
/// hand-written `&'static [Self]` with no exhaustiveness derive, so a variant
/// added to the enum and to both `match`es but to neither `ALL` nor the
/// migration left both compared sets at 22, the pinning test green, and the
/// first production INSERT of that action failing on the CHECK constraint in
/// front of a customer.
///
/// Generating all three from one list removes the link rather than testing it:
/// there is no longer a second place for a variant to be missing from.
/// `target_type` stays a hand-written exhaustive `match` below, because it maps
/// GROUPS of actions to one object kind and the grouping is the documentation —
/// and an exhaustive match is already a compile error for a new variant.
macro_rules! admin_audit_vocabulary {
    ($( $(#[$meta:meta])* $variant:ident => $action:literal ),+ $(,)?) => {
        /// Every administrative action FU5 audits.
        ///
        /// # This enum is the vocabulary, and it is pinned in three places
        ///
        /// Adding an audited action means adding ONE line to
        /// `admin_audit_vocabulary!`. That is not a convention, it is a chain
        /// of failures:
        ///
        ///   1. The variant, [`Self::ALL`] and [`Self::as_str`] are generated
        ///      from that one line, so they cannot disagree; and
        ///      [`Self::target_type`] is an exhaustive `match`, so a new
        ///      variant that is not spelled out there **does not compile**.
        ///   2. [`Self::ALL`] is reconciled against migration 028's
        ///      `admin_audit_action_known` CHECK constraint by
        ///      `tests/admin_audit.rs::the_action_vocabulary_is_pinned_in_three_places`,
        ///      so a variant with no migration entry **fails a test** — and, if
        ///      it ever escaped the test, would fail its production INSERT
        ///      rather than write an undocumented action.
        ///   3. The same test reconciles [`Self::ALL`] against
        ///      `audit_export::CONTROL_COVERAGE`, the prose copied into every
        ///      signed manifest, so the auditor's document cannot fall behind
        ///      the code.
        ///
        /// The export itself needs no entry at all: it selects every row of
        /// `admin_audit` without an `action` predicate and passes the value
        /// through.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub enum AdminAuditAction {
            $( $(#[$meta])* $variant ),+
        }

        impl AdminAuditAction {
            /// Every variant, generated from the same list as the variants
            /// themselves — omission is not possible rather than not permitted.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The stored `action`, which is also the exported `event_type`
            /// verbatim.
            ///
            /// Dotted `object.verb`, matching the shape FU1 chose for the three
            /// existing control-plane events (`raw_capture.changed`,
            /// `retention.purge`, `session.revoked`).
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $action ),+
                }
            }
        }
    };
}

admin_audit_vocabulary! {
    ApiKeyCreated => "api_key.created",
    ApiKeyRevoked => "api_key.revoked",
    ApiKeyRotated => "api_key.rotated",
    ProviderCredentialCreated => "provider_credential.created",
    ProviderCredentialUpdated => "provider_credential.updated",
    ProviderCredentialDeleted => "provider_credential.deleted",
    PolicyRuleCreated => "policy_rule.created",
    PolicyRuleUpdated => "policy_rule.updated",
    PolicyRuleDeleted => "policy_rule.deleted",
    PolicyRuleEnabledChanged => "policy_rule.enabled_changed",
    PolicyRuleDryRunChanged => "policy_rule.dry_run_changed",
    UserCreated => "user.created",
    /// P1A — migration 029. The four surfaces FU5 named as unreached.
    TwoFactorEnrollmentStarted => "two_factor.enrollment_started",
    TwoFactorEnabled => "two_factor.enabled",
    TwoFactorDisabled => "two_factor.disabled",
    LicenseActivated => "license.activated",
    LicenseCleared => "license.cleared",
    BudgetUpdated => "budget.updated",
    SecureModeUpdated => "secure_mode.updated",
    SidecarPolicyUpdated => "sidecar_policy.updated",
    LoginSucceeded => "auth.login_succeeded",
    SecondFactorVerified => "auth.second_factor_verified",
}

impl AdminAuditAction {
    /// The kind of object `target_id` points at.
    ///
    /// Derived from the action rather than supplied by the call site, so a
    /// handler cannot label an API key event as a policy rule.
    #[must_use]
    pub const fn target_type(self) -> &'static str {
        match self {
            Self::ApiKeyCreated | Self::ApiKeyRevoked | Self::ApiKeyRotated => "api_key",
            Self::ProviderCredentialCreated
            | Self::ProviderCredentialUpdated
            | Self::ProviderCredentialDeleted => "provider",
            Self::PolicyRuleCreated
            | Self::PolicyRuleUpdated
            | Self::PolicyRuleDeleted
            | Self::PolicyRuleEnabledChanged
            | Self::PolicyRuleDryRunChanged => "policy_rule",
            // The acted-on object is a person's account — their own, for the
            // self-service 2FA and login actions. `target_user_id` is filled
            // as well, so these land in the export's existing user columns.
            Self::UserCreated
            | Self::TwoFactorEnrollmentStarted
            | Self::TwoFactorEnabled
            | Self::TwoFactorDisabled
            | Self::LoginSucceeded
            | Self::SecondFactorVerified => "user",
            // The license is deployment-wide and has no UUID of its own;
            // `target_label` carries the vendor's `lic_id`, which is what a
            // revocation is a verdict about.
            Self::LicenseActivated | Self::LicenseCleared => "license",
            // These settings have no id of their own — the workspace IS the
            // object, so `target_id` is the workspace id.
            Self::BudgetUpdated | Self::SecureModeUpdated | Self::SidecarPolicyUpdated => {
                "workspace"
            }
        }
    }
}

/// Who performed the action, as they read at the moment they performed it.
///
/// Assembled from the authenticated context, NEVER from a request body. The
/// email is denormalised into the row rather than referenced, for the reason
/// migration 026 gives: a foreign key would let deleting a user rewrite the
/// evidence.
#[derive(Debug, Clone)]
pub struct AdminActor {
    pub workspace_id: Uuid,
    pub user_id: Option<Uuid>,
    pub email: Option<String>,
    pub role: Option<String>,
}

impl AdminActor {
    /// Look up the acting user's email so the row reads alone.
    ///
    /// A failed lookup yields `None` rather than an error, exactly as
    /// `SessionRevocationRepository::actor_email` does: a missing display name
    /// must not stop a security action from being recorded, and the id is still
    /// present.
    pub async fn resolve(pool: &PgPool, workspace_id: Uuid, user_id: Uuid, role: &str) -> Self {
        let email: Option<String> =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND workspace_id = $2")
                .bind(user_id)
                .bind(workspace_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
        Self {
            workspace_id,
            user_id: Some(user_id),
            email,
            role: Some(role.to_owned()),
        }
    }
}

/// One administrative action, ready to be written.
///
/// `target_type` is absent on purpose — it comes from
/// [`AdminAuditAction::target_type`].
#[derive(Debug, Clone)]
pub struct AdminAuditEntry {
    pub action: AdminAuditAction,
    /// The object acted on.
    pub target_id: Option<Uuid>,
    /// The object's own name, so the row still names something after the
    /// object is deleted. Truncated to [`TARGET_LABEL_MAX`] by [`write`].
    pub target_label: Option<String>,
    /// Set only when the target IS a workspace member, so the row lands in the
    /// export's existing target columns rather than inside `detail`.
    pub target_user_id: Option<Uuid>,
    pub target_email: Option<String>,
    pub target_role: Option<String>,
    /// Action-specific facts. Bounded values only — never a secret, and never
    /// an unbounded copy of request input. See migration 028's header.
    pub detail: Value,
}

impl AdminAuditEntry {
    /// An entry naming an object by id and name, with no user target.
    #[must_use]
    pub fn on_object(action: AdminAuditAction, target_id: Uuid, label: Option<String>) -> Self {
        Self {
            action,
            target_id: Some(target_id),
            target_label: label,
            target_user_id: None,
            target_email: None,
            target_role: None,
            detail: json!({}),
        }
    }

    /// An entry for an object that has a NAME but no UUID of its own.
    ///
    /// P1A needs exactly one: the deployment's license, whose identity is the
    /// vendor-issued `lic_id` string — the value a revocation is a verdict
    /// about. Putting it in `target_label` rather than inventing a UUID keeps
    /// `target_id` meaning "the primary key of a row in this database", which
    /// is what every other action's `target_id` means.
    #[must_use]
    pub fn on_named_object(action: AdminAuditAction, label: Option<String>) -> Self {
        Self {
            action,
            target_id: None,
            target_label: label,
            target_user_id: None,
            target_email: None,
            target_role: None,
            detail: json!({}),
        }
    }

    /// An entry whose target is the acting principal's own account.
    ///
    /// The self-service actions — 2FA enrolment, confirmation and reset, and
    /// login — have actor and target equal. Spelling that out here rather than
    /// at four call sites keeps `target_user_id` populated, which is what puts
    /// these rows in the export's existing user columns instead of burying the
    /// principal in `detail`.
    #[must_use]
    pub fn on_own_account(
        action: AdminAuditAction,
        user_id: Uuid,
        email: &str,
        role: &str,
    ) -> Self {
        Self::on_object(action, user_id, None).targeting_user(user_id, email, role)
    }

    /// Attach the action-specific facts.
    #[must_use]
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    /// Mark the target as a workspace member, filling the export's user
    /// columns as well as the generic ones.
    #[must_use]
    pub fn targeting_user(mut self, user_id: Uuid, email: &str, role: &str) -> Self {
        self.target_user_id = Some(user_id);
        self.target_email = Some(email.to_owned());
        self.target_role = Some(role.to_owned());
        self
    }
}

/// Cut a label to [`TARGET_LABEL_MAX`] CHARACTERS.
///
/// Characters and not bytes: slicing a UTF-8 string at a byte offset panics
/// mid-codepoint, and administrators name things in Russian and Uzbek here.
///
/// `single_option_map` says to inline this into the caller. Kept as a named
/// function on purpose: it is the ONE place the bound on
/// administrator-supplied text is applied, and migration 028's
/// `admin_audit_target_label_bounded` CHECK is written to match it. Inlining it
/// makes that pairing invisible.
#[allow(clippy::single_option_map)]
fn bounded_label(label: Option<&str>) -> Option<String> {
    label.map(|value| value.chars().take(TARGET_LABEL_MAX).collect())
}

/// Write one administrative action into the caller's OPEN transaction.
///
/// The caller must already have armed `app.current_workspace_id` — every call
/// site reaches this from inside a transaction that did, and the INSERT is
/// rejected rather than silently dropped if not.
///
/// # Errors
/// Returns `ApiError::Database` when the INSERT fails. The caller must
/// propagate it and MUST NOT commit: the action and its record commit together
/// or not at all.
pub async fn write(
    tx: &mut Transaction<'_, Postgres>,
    actor: &AdminActor,
    entry: &AdminAuditEntry,
) -> Result<Uuid, ApiError> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO admin_audit
             (id, workspace_id, action, actor_user_id, actor_email, actor_role,
              target_type, target_id, target_label,
              target_user_id, target_email, target_role, detail, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())",
    )
    .bind(id)
    .bind(actor.workspace_id)
    .bind(entry.action.as_str())
    .bind(actor.user_id)
    .bind(actor.email.as_deref())
    .bind(actor.role.as_deref())
    .bind(entry.action.target_type())
    .bind(entry.target_id)
    .bind(bounded_label(entry.target_label.as_deref()))
    .bind(entry.target_user_id)
    .bind(entry.target_email.as_deref())
    .bind(entry.target_role.as_deref())
    .bind(&entry.detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| ApiError::Database(e.to_string()))?;
    Ok(id)
}

/// One field's movement, for a `detail.changed` object.
///
/// Only fields that actually MOVED belong in a diff. A record that lists every
/// field on every edit reads as though the administrator changed everything,
/// which is worse than useless when the question is what they changed.
pub fn changed_field(
    map: &mut serde_json::Map<String, Value>,
    name: &str,
    before: &Value,
    after: &Value,
) {
    if before != after {
        map.insert(name.to_owned(), json!({"before": before, "after": after}));
    }
}
