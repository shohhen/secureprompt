use serde::{Deserialize, Serialize};

/// Plan 3 — license verification configuration.
///
/// Fields are loaded from environment variables; see `LicenseConfig::from_env`.
/// `LicenseConfig` is intentionally NOT deserialized from a config file
/// (the public key must come from the environment at runtime only).
#[derive(Debug, Clone)]
pub struct LicenseConfig {
    pub license_path: String,
    /// base64 Ed25519 vendor public key; empty => unlicensed/grace.
    /// TODO(plan6): pin this as a compile-time const (include_bytes) — env-loading
    /// permits substitution and is a development convenience only.
    pub pubkey_b64: String,
    pub recheck_secs: u64,
    /// base64 32-byte key-encryption key for the model decryption key.
    /// TODO(plan6): pin the KEK as a compile-time const alongside the vendor public key.
    pub model_kek_b64: String,
}

impl LicenseConfig {
    pub fn from_env() -> Self {
        Self {
            license_path: std::env::var("SECUREPROMPT_LICENSE_PATH")
                .unwrap_or_else(|_| "/etc/secureprompt/license.json".into()),
            pubkey_b64: std::env::var("SECUREPROMPT_LICENSE_PUBKEY").unwrap_or_default(),
            recheck_secs: std::env::var("SECUREPROMPT_LICENSE_RECHECK_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            model_kek_b64: std::env::var("SECUREPROMPT_MODEL_KEK").unwrap_or_default(),
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
    /// Plan 3 — gateway license verification (fail-open). Loaded from env;
    /// not serde-deserialized because the public key must not come from a
    /// config file.
    #[serde(skip)]
    pub license: LicenseConfig,
}

fn default_redact_when_no_rules() -> bool {
    true
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
        if let Ok(provider_key) = std::env::var("SECUREPROMPT_PROVIDER_KEY") {
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

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_MUTEX.get_or_init(|| Mutex::new(())).lock().unwrap()
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
}
