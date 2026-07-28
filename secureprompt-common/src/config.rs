use serde::{Deserialize, Serialize};

/// Plan 3 — license verification configuration.
///
/// **All key material is environment-sourced.** There is no file fallback.
/// The three env vars are:
///   - `SECUREPROMPT_LICENSE_PUBKEY` — base64 Ed25519 vendor public key (32 bytes).
///   - `SECUREPROMPT_ATTEST_KEK`     — base64 32-byte key-encryption key for the
///                                     attestation key (ATTEST-KEK only; the gateway
///                                     never holds nor needs the MODEL-KEK).
///   - `SECUREPROMPT_LICENSE_TOKEN`  — the compact `base64url(payload).base64url(sig)`
///                                     license token (sp-license 0.2.0).
///
/// Any of them being unset / empty is non-fatal: the gateway runs Unlicensed
/// (fail-open, mirroring the previous behavior on a missing license file).
#[derive(Clone)]
pub struct LicenseConfig {
    /// The full license token (compact single-line form). Empty => unlicensed.
    pub license_token: String,
    /// base64 Ed25519 vendor public key; empty => unlicensed/grace.
    /// TODO(plan6): pin this as a compile-time const (include_bytes) — env-loading
    /// permits substitution and is a development convenience only.
    pub pubkey_b64: String,
    pub recheck_secs: u64,
    /// base64 32-byte key-encryption key for the attestation key (ATTEST-KEK).
    /// The gateway holds ONLY this KEK; the MODEL-KEK lives exclusively in the
    /// ML sidecar. The wrapped model blob is relayed as-is to the sidecar.
    /// TODO(plan6): pin the KEK as a compile-time const alongside the vendor public key.
    pub attest_kek_b64: String,
    /// Shared secret used when relaying the wrapped model blob to the ML sidecar's
    /// `POST /internal/model-key` endpoint. Empty string disables the relay.
    /// Loaded from `ML_SIDECAR_INTERNAL_TOKEN`; empty default.
    pub internal_token: String,
    /// sp-admin base URL for online revocation checks (OCSP-style). `None` =>
    /// fully offline: the gateway only trusts the local token and never blocks
    /// on revocation. Loaded from `SECUREPROMPT_LICENSE_SERVER_URL`.
    pub license_server_url: Option<String>,
    /// How often (seconds) to poll sp-admin for revocation. Default 300 (5 min).
    /// Loaded from `SECUREPROMPT_REVOCATION_CHECK_SECS`.
    pub revocation_check_secs: u64,
    /// How often (seconds) to upload a signed attestation heartbeat to sp-admin
    /// (`POST {license_server_url}/v1/attestations`). Default 3600 (1h). Only runs
    /// when `license_server_url` is set. From `SECUREPROMPT_ATTESTATION_INTERVAL_SECS`.
    pub attestation_interval_secs: u64,
}

impl std::fmt::Debug for LicenseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenseConfig")
            .field("license_token", &"<redacted>")
            .field("pubkey_b64", &self.pubkey_b64)
            .field("attest_kek_b64", &"<redacted>")
            .field("recheck_secs", &self.recheck_secs)
            .field("internal_token", &"<redacted>")
            .field("license_server_url", &self.license_server_url)
            .field("revocation_check_secs", &self.revocation_check_secs)
            .field("attestation_interval_secs", &self.attestation_interval_secs)
            .finish()
    }
}

impl LicenseConfig {
    pub fn from_env() -> Self {
        // Empty env var (set but blank) is treated as unset — keeps docker-compose
        // `${VAR:-}` defaults working as "no value" rather than "value of empty".
        let from_env = |name: &str| -> String {
            std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_default()
        };

        Self {
            license_token: from_env("SECUREPROMPT_LICENSE_TOKEN"),
            pubkey_b64: from_env("SECUREPROMPT_LICENSE_PUBKEY"),
            attest_kek_b64: from_env("SECUREPROMPT_ATTEST_KEK"),
            recheck_secs: std::env::var("SECUREPROMPT_LICENSE_RECHECK_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            internal_token: std::env::var("ML_SIDECAR_INTERNAL_TOKEN").unwrap_or_default(),
            license_server_url: std::env::var("SECUREPROMPT_LICENSE_SERVER_URL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            revocation_check_secs: std::env::var("SECUREPROMPT_REVOCATION_CHECK_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            attestation_interval_secs: std::env::var("SECUREPROMPT_ATTESTATION_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
        }
    }
}

/// `Default` delegates to `from_env()` so that `#[serde(skip)]` on
/// `AppConfig::license` works (serde needs `Default` for skipped fields).
impl Default for LicenseConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub telemetry: TelemetryConfig,
    pub server: ServerConfig,
    pub clickhouse: ClickhouseConfig,
    /// Phase 5 / Plan 05-01 — dashboard JWT signing + rotation parameters.
    pub jwt: JwtConfig,
    /// Public `POST /v1/auth/register` endpoint. `false` in on-prem
    /// deployments (default); enabled explicitly for cloud/demo.
    /// Populated from `SECUREPROMPT_PUBLIC_SIGNUP_ENABLED`.
    #[serde(default)]
    pub public_signup_enabled: bool,
    /// Phase 1 chat-completions debug mode. When `true`, `/v1/chat/completions`
    /// runs the full redaction pipeline but **does not call the cloud provider**.
    /// Instead it returns the tokenized prompt + raw provider invocation body
    /// as the assistant message. Used to verify the LibreChat → SecurePrompt
    /// round-trip end-to-end before cloud adapters are wired.
    /// Populated from `SECUREPROMPT_CHAT_DEBUG_MODE`. Defaults to `false`.
    #[serde(default)]
    pub chat_debug_mode: bool,
    /// Safety net for first-run / mis-configured workspaces: when enabled
    /// AND a chat hits a workspace that has zero policy rules, the gateway
    /// auto-redacts every detected PII span before egress. Without this
    /// the policy engine would short-circuit to `allow` and forward the
    /// raw prompt to the upstream — exactly the leak the product exists
    /// to prevent.
    ///
    /// Once an admin defines at least one rule the workspace's explicit
    /// policy takes over and this fallback no longer fires (so the
    /// "I want PERSON to pass through" choice still works).
    ///
    /// Populated from `SECUREPROMPT_REDACT_WHEN_NO_RULES`. Defaults to
    /// `true` — the safe behavior.
    #[serde(default = "default_redact_when_no_rules")]
    pub redact_when_no_rules: bool,
    /// WS2-3 — deployment-level default for a workspace's
    /// `sidecar_unavailable` policy: what to do when the ML sidecar produces
    /// no detection coverage for a request. One of `block` (fail closed,
    /// 503) or `degrade_with_alert` (answer on the deterministic detection
    /// floor, loudly). A workspace row in `workspace_sidecar_policy`
    /// overrides this; this is what applies when the workspace has never
    /// chosen.
    ///
    /// Populated from `SECUREPROMPT_SIDECAR_UNAVAILABLE_DEFAULT`. Defaults to
    /// `block` — the fail-closed posture. It exists because `block` is only a
    /// safe default if there is a reachable off-switch: a deployment with no
    /// ML sidecar at all (the `docker-compose.simple.yml` profile) would
    /// otherwise 503 every gateway request with no recourse except an
    /// admin-JWT `PUT /v1/secure-mode` per workspace.
    #[serde(default = "default_sidecar_unavailable")]
    pub sidecar_unavailable_default: String,
    /// Plan 3 — gateway license verification (fail-open). Loaded from env;
    /// not serde-deserialized because the public key must not come from a
    /// config file.
    #[serde(skip)]
    pub license: LicenseConfig,
}

fn default_redact_when_no_rules() -> bool {
    true
}

fn default_sidecar_unavailable() -> String {
    "block".to_owned()
}

impl AppConfig {
    /// Parse `SECUREPROMPT_PUBLIC_SIGNUP_ENABLED` from the environment.
    /// Truthy values: `1`, `true`, `yes` (case-insensitive). Everything else
    /// (including unset) → `false`.
    #[must_use]
    pub fn public_signup_enabled_from_env() -> bool {
        std::env::var("SECUREPROMPT_PUBLIC_SIGNUP_ENABLED")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"))
    }

    /// Parse `SECUREPROMPT_CHAT_DEBUG_MODE` from the environment.
    /// Truthy values: `1`, `true`, `yes` (case-insensitive). Everything else
    /// (including unset) → `false`.
    #[must_use]
    pub fn chat_debug_mode_from_env() -> bool {
        std::env::var("SECUREPROMPT_CHAT_DEBUG_MODE")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"))
    }

    /// Parse `SECUREPROMPT_REDACT_WHEN_NO_RULES`. Truthy: `1`, `true`,
    /// `yes`. Falsy: `0`, `false`, `no`. **Unset → `true`** — the safe
    /// default (we'd rather over-redact a brand-new workspace than leak
    /// PII because the admin hasn't built rules yet).
    #[must_use]
    /// Parse `SECUREPROMPT_SIDECAR_UNAVAILABLE_DEFAULT` from the environment.
    ///
    /// Only the exact value `degrade_with_alert` opts a deployment out of
    /// fail-closed. Anything else — unset, misspelled, empty — yields
    /// `block`, because a PII gateway must not fail open because someone
    /// fat-fingered an env var.
    #[must_use]
    pub fn sidecar_unavailable_default_from_env() -> String {
        match std::env::var("SECUREPROMPT_SIDECAR_UNAVAILABLE_DEFAULT")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("degrade_with_alert") => "degrade_with_alert".to_owned(),
            Some(other) if !other.is_empty() && other != "block" => {
                tracing::warn!(
                    value = %other,
                    "SECUREPROMPT_SIDECAR_UNAVAILABLE_DEFAULT is not a recognised value;                      falling back to 'block'"
                );
                "block".to_owned()
            }
            _ => "block".to_owned(),
        }
    }

    pub fn redact_when_no_rules_from_env() -> bool {
        match std::env::var("SECUREPROMPT_REDACT_WHEN_NO_RULES")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
        {
            Some(v) if matches!(v.as_str(), "0" | "false" | "no") => false,
            _ => true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    pub otel_enabled: bool,
    pub prometheus_enabled: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MlSidecarConfig {
    pub url: String,
    /// Per-call timeout in milliseconds (D-04: 200ms).
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClickhouseConfig {
    pub url: String,
    pub database: String,
}

/// Phase 5 / Plan 05-04 — AES-256-GCM key for provider credential encryption.
///
/// Loaded from `SECUREPROMPT_PROVIDER_KEY` (64 hex chars = 32 bytes).
/// Must be DISTINCT from `SECUREPROMPT_JWT_SECRET` (enforced by `JwtConfig::from_env`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderKeyConfig {
    /// 32-byte AES key as hex string (64 chars).
    pub hex_key: String,
}

impl ProviderKeyConfig {
    /// Load from `SECUREPROMPT_PROVIDER_KEY`.  Returns a zeroed-key config
    /// (for tests / missing env) rather than failing, because the API can
    /// start without provider encryption when no credentials have been stored.
    ///
    /// Production deployments MUST set this env var; the config validator
    /// should warn loudly when it is missing.
    #[must_use]
    pub fn from_env_or_zero() -> Self {
        let hex_key = std::env::var("SECUREPROMPT_PROVIDER_KEY")
            .unwrap_or_else(|_| "0".repeat(64));
        Self { hex_key }
    }

    /// Parse the stored hex string into raw key bytes.
    ///
    /// # Errors
    /// Returns `Err` when the value is not exactly 64 valid hex characters.
    pub fn to_key_bytes(&self) -> Result<[u8; 32], String> {
        crate::crypto::parse_provider_key(&self.hex_key)
            .map_err(|e| e.to_string())
    }
}

/// Phase 5 / Plan 05-01 — dashboard JWT configuration.
///
/// Loaded from three env vars (see `JwtConfig::from_env`):
///   - `SECUREPROMPT_JWT_SECRET` — required, must be distinct from
///     `SECUREPROMPT_PROVIDER_KEY` (AES-GCM key for provider credentials).
///   - `SECUREPROMPT_JWT_ACCESS_TTL_SECS` — default 900 (15 min).
///   - `SECUREPROMPT_JWT_REFRESH_TTL_SECS` — default 2_592_000 (30 days).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    pub secret: String,
    pub access_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
}

/// Sentinel values shipped in `.env.example` and comparable templates.
///
/// WS1-3: booting with one of these means the deployment is running on a
/// secret that is public knowledge — `.env.example` sets
/// `SECUREPROMPT_JWT_SECRET=CHANGEME`, and an operator who copies it to
/// `.env` and forgets to edit gets a gateway whose tokens anyone can forge.
/// Compared case-insensitively after trimming.
const PLACEHOLDER_SECRETS: &[&str] = &[
    "changeme",
    "change_me",
    "change-me",
    "changethis",
    "change_this",
    "change-this",
    "secret",
    "password",
    "placeholder",
    "todo",
    "xxx",
    "your-secret-here",
    "your_secret_here",
    "replaceme",
    "replace_me",
];

/// Reject a known-placeholder secret, naming the variable so the operator can
/// act on the message without reading source.
///
/// # Errors
/// Returns a human-readable error when `value` is a known placeholder.
fn reject_placeholder_secret(var: &str, value: &str) -> Result<(), String> {
    let normalized = value.trim().to_ascii_lowercase();
    if PLACEHOLDER_SECRETS.contains(&normalized.as_str()) {
        return Err(format!(
            "{var} is set to the placeholder value {value:?} — refusing to boot. \
             Generate a real secret (for example `openssl rand -hex 32`) and set {var}."
        ));
    }
    Ok(())
}

impl JwtConfig {
    pub const DEFAULT_ACCESS_TTL_SECS: u64 = 900;
    pub const DEFAULT_REFRESH_TTL_SECS: u64 = 2_592_000;

    /// Load from environment. Returns `Err` if `SECUREPROMPT_JWT_SECRET` is
    /// missing or equals `SECUREPROMPT_PROVIDER_KEY` (both-env-must-differ
    /// guardrail per 05-PATTERNS.md §providers.rs).
    ///
    /// # Errors
    /// Returns a human-readable error string when the secret is missing,
    /// empty, or aliased to the provider key.
    pub fn from_env() -> Result<Self, String> {
        let secret = std::env::var("SECUREPROMPT_JWT_SECRET")
            .map_err(|_| "SECUREPROMPT_JWT_SECRET is required".to_string())?;
        if secret.trim().is_empty() {
            return Err("SECUREPROMPT_JWT_SECRET must not be empty".into());
        }
        reject_placeholder_secret("SECUREPROMPT_JWT_SECRET", &secret)?;
        if let Ok(provider_key) = std::env::var("SECUREPROMPT_PROVIDER_KEY") {
            if !provider_key.is_empty() {
                reject_placeholder_secret("SECUREPROMPT_PROVIDER_KEY", &provider_key)?;
            }
            if !provider_key.is_empty() && provider_key == secret {
                return Err(
                    "SECUREPROMPT_JWT_SECRET must differ from SECUREPROMPT_PROVIDER_KEY".into(),
                );
            }
        }
        let access_ttl_secs = std::env::var("SECUREPROMPT_JWT_ACCESS_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(Self::DEFAULT_ACCESS_TTL_SECS);
        let refresh_ttl_secs = std::env::var("SECUREPROMPT_JWT_REFRESH_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(Self::DEFAULT_REFRESH_TTL_SECS);
        Ok(Self {
            secret,
            access_ttl_secs,
            refresh_ttl_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::JwtConfig;
    use std::sync::{Mutex, OnceLock};

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    /// Recover from poisoning rather than propagating it. These tests mutate
    /// process-global env vars, so the guard exists only for mutual exclusion
    /// — it protects no invariant that a panicking test could corrupt.
    /// Unwrapping here turned a single genuine failure into six, hiding which
    /// test actually broke.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn clear_jwt_env() {
        std::env::remove_var("SECUREPROMPT_JWT_SECRET");
        std::env::remove_var("SECUREPROMPT_JWT_ACCESS_TTL_SECS");
        std::env::remove_var("SECUREPROMPT_JWT_REFRESH_TTL_SECS");
        std::env::remove_var("SECUREPROMPT_PROVIDER_KEY");
    }

    #[test]
    fn rejects_missing_secret() {
        let _g = env_lock();
        clear_jwt_env();
        let result = JwtConfig::from_env();
        assert!(result.is_err(), "missing secret must error");
    }

    #[test]
    fn rejects_secret_equal_to_provider_key() {
        let _g = env_lock();
        clear_jwt_env();
        std::env::set_var("SECUREPROMPT_JWT_SECRET", "same-string");
        std::env::set_var("SECUREPROMPT_PROVIDER_KEY", "same-string");
        let result = JwtConfig::from_env();
        clear_jwt_env();
        assert!(result.is_err(), "aliased keys must error");
    }

    // ── WS1-3: refuse to boot on known-default secrets ───────────────────────

    #[test]
    fn rejects_placeholder_jwt_secret_naming_the_variable() {
        let _g = env_lock();
        for placeholder in [
            "CHANGEME",
            "changeme",
            "ChangeMe",
            "  CHANGEME  ",
            "change_me",
            "CHANGE_ME",
            "changethis",
            "secret",
            "password",
            "your-secret-here",
        ] {
            clear_jwt_env();
            std::env::set_var("SECUREPROMPT_JWT_SECRET", placeholder);
            let result = JwtConfig::from_env();
            clear_jwt_env();

            let err = result.expect_err(&format!(
                "placeholder secret {placeholder:?} must be rejected at boot"
            ));
            assert!(
                err.contains("SECUREPROMPT_JWT_SECRET"),
                "error must name the offending variable so the operator can fix \
                 it; got: {err}"
            );
        }
    }

    #[test]
    fn rejects_placeholder_provider_key_naming_the_variable() {
        let _g = env_lock();
        clear_jwt_env();
        std::env::set_var("SECUREPROMPT_JWT_SECRET", "a-genuinely-distinct-secret");
        std::env::set_var("SECUREPROMPT_PROVIDER_KEY", "CHANGEME");
        let result = JwtConfig::from_env();
        clear_jwt_env();

        let err = result.expect_err("placeholder provider key must be rejected");
        assert!(
            err.contains("SECUREPROMPT_PROVIDER_KEY"),
            "error must name the offending variable; got: {err}"
        );
    }

    #[test]
    fn accepts_a_real_secret() {
        let _g = env_lock();
        clear_jwt_env();
        // Guards against an over-broad placeholder rule rejecting real values.
        std::env::set_var(
            "SECUREPROMPT_JWT_SECRET",
            "7f3c1b9a4e2d8f06b5a1c7e93d4082fa61bc5d0e9a3f7148",
        );
        let result = JwtConfig::from_env();
        clear_jwt_env();
        assert!(result.is_ok(), "a real secret must boot: {result:?}");
    }

    #[test]
    fn loads_defaults_when_ttl_unset() {
        let _g = env_lock();
        clear_jwt_env();
        std::env::set_var("SECUREPROMPT_JWT_SECRET", "distinct-secret-value");
        let cfg = JwtConfig::from_env().expect("valid secret");
        clear_jwt_env();
        assert_eq!(cfg.access_ttl_secs, JwtConfig::DEFAULT_ACCESS_TTL_SECS);
        assert_eq!(cfg.refresh_ttl_secs, JwtConfig::DEFAULT_REFRESH_TTL_SECS);
    }

    #[test]
    fn public_signup_enabled_defaults_to_false_when_unset() {
        let _g = env_lock();
        std::env::remove_var("SECUREPROMPT_PUBLIC_SIGNUP_ENABLED");
        assert!(!super::AppConfig::public_signup_enabled_from_env());
    }

    #[test]
    fn public_signup_enabled_parses_truthy_values() {
        let _g = env_lock();
        for v in ["1", "true", "TRUE", "yes", "YES", "  true  "] {
            std::env::set_var("SECUREPROMPT_PUBLIC_SIGNUP_ENABLED", v);
            assert!(
                super::AppConfig::public_signup_enabled_from_env(),
                "{v} should parse as true"
            );
        }
        std::env::remove_var("SECUREPROMPT_PUBLIC_SIGNUP_ENABLED");
    }

    #[test]
    fn public_signup_enabled_rejects_non_truthy() {
        let _g = env_lock();
        for v in ["0", "false", "no", "", "maybe", "  "] {
            std::env::set_var("SECUREPROMPT_PUBLIC_SIGNUP_ENABLED", v);
            assert!(
                !super::AppConfig::public_signup_enabled_from_env(),
                "{v} should parse as false"
            );
        }
        std::env::remove_var("SECUREPROMPT_PUBLIC_SIGNUP_ENABLED");
    }

    fn clear_license_env() {
        std::env::remove_var("SECUREPROMPT_LICENSE_PUBKEY");
        std::env::remove_var("SECUREPROMPT_ATTEST_KEK");
        std::env::remove_var("SECUREPROMPT_LICENSE_TOKEN");
    }

    #[test]
    fn license_config_loads_three_env_vars() {
        let _g = env_lock();
        clear_license_env();

        // --- 1. All three set → all three populated. ---
        std::env::set_var("SECUREPROMPT_LICENSE_PUBKEY", "PUB");
        std::env::set_var("SECUREPROMPT_ATTEST_KEK", "KEK");
        std::env::set_var("SECUREPROMPT_LICENSE_TOKEN", "TOKEN");
        let cfg = super::LicenseConfig::from_env();
        assert_eq!(cfg.pubkey_b64, "PUB");
        assert_eq!(cfg.attest_kek_b64, "KEK");
        assert_eq!(cfg.license_token, "TOKEN");

        // --- 2. All unset → empty strings, no panic, no file-system reads. ---
        clear_license_env();
        let cfg = super::LicenseConfig::from_env();
        assert_eq!(cfg.pubkey_b64, "");
        assert_eq!(cfg.attest_kek_b64, "");
        assert_eq!(cfg.license_token, "");

        // --- 3. Empty string is treated as unset. ---
        std::env::set_var("SECUREPROMPT_LICENSE_PUBKEY", "");
        std::env::set_var("SECUREPROMPT_ATTEST_KEK", "");
        std::env::set_var("SECUREPROMPT_LICENSE_TOKEN", "");
        let cfg = super::LicenseConfig::from_env();
        assert_eq!(cfg.pubkey_b64, "");
        assert_eq!(cfg.attest_kek_b64, "");
        assert_eq!(cfg.license_token, "");

        clear_license_env();
    }
}

#[cfg(test)]
mod sidecar_unavailable_default_tests {
    use super::AppConfig;

    /// WS2-3 — the deployment-level escape hatch must open for exactly one
    /// spelling and stay shut for everything else. A PII gateway must not
    /// fail open because an operator mistyped an env var.
    ///
    /// Single test, sequential asserts on purpose: these mutate process-wide
    /// environment, so splitting them into separate `#[test]`s would let the
    /// harness run them concurrently and race.
    #[test]
    fn only_the_exact_opt_out_value_disables_fail_closed() {
        const VAR: &str = "SECUREPROMPT_SIDECAR_UNAVAILABLE_DEFAULT";

        std::env::remove_var(VAR);
        assert_eq!(
            AppConfig::sidecar_unavailable_default_from_env(),
            "block",
            "unset must fail closed"
        );

        for opt_out in ["degrade_with_alert", "  Degrade_With_Alert  "] {
            std::env::set_var(VAR, opt_out);
            assert_eq!(
                AppConfig::sidecar_unavailable_default_from_env(),
                "degrade_with_alert",
                "{opt_out:?} must opt out (trimmed, case-insensitive)"
            );
        }

        // Near-misses, a plausible typo, and an unrelated value.
        for bad in ["degrade", "DEGRADE_WITH_ALERTS", "true", "", "   ", "off"] {
            std::env::set_var(VAR, bad);
            assert_eq!(
                AppConfig::sidecar_unavailable_default_from_env(),
                "block",
                "{bad:?} must NOT open the gate"
            );
        }

        std::env::set_var(VAR, "block");
        assert_eq!(AppConfig::sidecar_unavailable_default_from_env(), "block");
        std::env::remove_var(VAR);
    }
}
