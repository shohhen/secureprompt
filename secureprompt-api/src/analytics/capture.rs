//! WS3-1 / WS3-2 — the single gate through which raw request content may be
//! persisted, and the encryption applied to it on the way past.
//!
//! # The defect this exists to make impossible
//!
//! `pipeline/service.rs` had seven unconditional assignments of
//! `event.raw_prompt`, `event.raw_response` and `event.restored_response`.
//! Every one of them wrote plaintext — the un-redacted user message, the
//! upstream reply, and the reply with PII restored — into ClickHouse on every
//! request, under a fixed 90-day TTL, with no configuration gate anywhere in
//! the repository.
//!
//! The fix is deliberately structural rather than seven `if` statements.
//! [`crate::analytics::events::RequestEvent`] no longer HAS those fields; it
//! has one private `captured` field that only
//! [`crate::analytics::events::RequestEvent::capture_content`] can set, and
//! that method's only route to a `Some` is [`seal`] below. A future call site
//! that forgets the gate does not leak — it fails to compile.
//!
//! # Scope correction (WS3 review)
//!
//! The paragraph above was true of the three fields it names and FALSE of the
//! event as a whole, which is how it read. A FOURTH field, `redacted_prompt`,
//! stayed `pub` and stayed exempt — with a doc comment asserting the
//! exemption was safe because the field holds "the same bytes that were
//! forwarded upstream". On the fail-closed path nothing is forwarded and
//! nothing is redacted, so it held the raw prompt, in the clear, in
//! `request_events`, under the same 90-day TTL this module exists to escape.
//!
//! `redacted_prompt` is now private too, and settable only through
//! [`crate::analytics::events::RequestEvent::record_prompt`], which takes a
//! [`crate::analytics::events::RedactedPrompt`] — so a call site must NAME
//! whether its request was actually redacted. The compile-error property now
//! covers all four fields, which is what the paragraph above always claimed.
//!
//! # Fail-closed in three places
//!
//! 1. Capture not enabled for the workspace → `None`. This is the default,
//!    and it is the default by ABSENCE (no row in `workspace_raw_capture`),
//!    not by a backfill.
//! 2. Nothing to store → `None`, so an opted-in workspace does not accumulate
//!    empty rows.
//! 3. **Encryption failed → `None`.** A KMS outage must never downgrade to
//!    storing plaintext. Losing an audit record is recoverable; silently
//!    writing the customer's prompts in the clear because Vault was
//!    unreachable is the original defect wearing a different hat.

use secureprompt_common::kms::KmsBackend;

/// What the workspace's `workspace_raw_capture` row (migration 021) says to
/// do about this request.
///
/// Constructed from [`crate::db::raw_capture_repo::RawCaptureSettings`] at
/// the top of the request path and carried down, so one database read covers
/// every capture site on the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureDecision {
    pub enabled: bool,
    pub retention_days: i32,
}

impl Default for CaptureDecision {
    /// Capture OFF. Used verbatim whenever the settings read fails, so a
    /// Postgres outage cannot turn into permission to retain plaintext.
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: crate::db::raw_capture_repo::DEFAULT_RETENTION_DAYS,
        }
    }
}

impl From<crate::db::raw_capture_repo::RawCaptureSettings> for CaptureDecision {
    fn from(settings: crate::db::raw_capture_repo::RawCaptureSettings) -> Self {
        Self {
            enabled: settings.enabled,
            retention_days: settings.retention_days,
        }
    }
}

/// Ciphertext destined for the `request_content_captures` table.
///
/// The three payload fields are ALWAYS ciphertext when `encrypted` is true,
/// which [`seal`] is the only constructor and always sets. There is no
/// constructor that produces plaintext.
#[derive(Clone)]
pub struct CapturedContent {
    pub raw_prompt: Option<String>,
    pub raw_response: Option<String>,
    pub restored_response: Option<String>,
    /// Always true for anything [`seal`] produces. Persisted so a reader can
    /// distinguish these rows from the plaintext columns historical
    /// `request_events` rows still carry, without guessing from the bytes.
    pub encrypted: bool,
    /// Days of retention, applied by the analytics writer against the SAME
    /// timestamp it stamps `created_at` with. Carried as a duration rather
    /// than an absolute instant on purpose: computing `expires_at` here and
    /// `created_at` in the writer would leave a sub-second skew between them
    /// and make `dateDiff('day', created_at, expires_at)` land on
    /// `retention_days - 1` for requests that straddle midnight.
    pub retention_days: i32,
}

/// Never prints the payload, even though it is ciphertext. A `Debug` impl is
/// the classic accidental egress — into a log line, a panic message, a
/// `tracing` field — and the whole point of this module is that this content
/// has exactly one destination.
impl std::fmt::Debug for CapturedContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedContent")
            .field("raw_prompt_len", &self.raw_prompt.as_ref().map(String::len))
            .field(
                "raw_response_len",
                &self.raw_response.as_ref().map(String::len),
            )
            .field(
                "restored_response_len",
                &self.restored_response.as_ref().map(String::len),
            )
            .field("encrypted", &self.encrypted)
            .field("retention_days", &self.retention_days)
            .finish()
    }
}

/// Encrypt one optional field. `Ok(None)` for an absent or empty input;
/// `Err(())` when the KMS refused, which aborts the whole capture.
async fn seal_field(
    kms: &dyn KmsBackend,
    field: &'static str,
    value: Option<String>,
) -> Result<Option<String>, ()> {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match kms.encrypt(value.as_bytes()).await {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(ciphertext) => Ok(Some(ciphertext)),
            Err(e) => {
                tracing::error!(
                    alert = "raw_capture_encrypt_failed",
                    field,
                    error = %e,
                    "KMS returned non-UTF-8 ciphertext; dropping the capture rather \
                     than storing raw content"
                );
                Err(())
            }
        },
        Err(e) => {
            tracing::error!(
                alert = "raw_capture_encrypt_failed",
                field,
                error = %e,
                "KMS encrypt failed; dropping the capture rather than storing raw content"
            );
            Err(())
        }
    }
}

/// THE GATE. The only function in the codebase that can turn raw request
/// content into something persistable.
///
/// Returns `None` — meaning nothing is stored anywhere — unless the workspace
/// has explicitly opted in AND there is content AND every field encrypted
/// successfully.
pub async fn seal(
    decision: CaptureDecision,
    kms: &dyn KmsBackend,
    raw_prompt: Option<String>,
    raw_response: Option<String>,
    restored_response: Option<String>,
) -> Option<CapturedContent> {
    // (1) The opt-in. Deleting this line is what the WS3-1 tests' deletion
    // check mutates: without it a fresh install captures everything again.
    if !decision.enabled {
        return None;
    }

    // (2) Nothing worth a row.
    if raw_prompt.is_none() && raw_response.is_none() && restored_response.is_none() {
        return None;
    }

    // (3) Encrypt, or store nothing.
    let raw_prompt = seal_field(kms, "raw_prompt", raw_prompt).await.ok()?;
    let raw_response = seal_field(kms, "raw_response", raw_response).await.ok()?;
    let restored_response = seal_field(kms, "restored_response", restored_response)
        .await
        .ok()?;

    // All three turned out empty after filtering — nothing to persist.
    if raw_prompt.is_none() && raw_response.is_none() && restored_response.is_none() {
        return None;
    }

    Some(CapturedContent {
        raw_prompt,
        raw_response,
        restored_response,
        encrypted: true,
        retention_days: decision.retention_days,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const SYNTHETIC: &str = "Anvar Karimov, PINFL 50101901234567";

    /// A KMS that reverses the bytes. Not real crypto — the point is that its
    /// output is (a) different from its input and (b) deterministic, so an
    /// assertion can prove `seal` ran the payload through the KMS at all.
    struct ReversingKms {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl KmsBackend for ReversingKms {
        async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(plaintext.iter().rev().copied().collect())
        }
        async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            Ok(ciphertext.iter().rev().copied().collect())
        }
    }

    struct BrokenKms;

    #[async_trait]
    impl KmsBackend for BrokenKms {
        async fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("vault unreachable")
        }
        async fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
            anyhow::bail!("vault unreachable")
        }
    }

    fn kms() -> (Arc<ReversingKms>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(ReversingKms {
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }

    /// WS3-1. The default decision stores nothing.
    #[tokio::test]
    async fn disabled_capture_stores_nothing() {
        let (kms, calls) = kms();
        let sealed = seal(
            CaptureDecision::default(),
            kms.as_ref(),
            Some(SYNTHETIC.to_owned()),
            Some("upstream reply".to_owned()),
            Some("restored reply".to_owned()),
        )
        .await;
        assert!(
            sealed.is_none(),
            "the default decision must produce nothing to store"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a disabled workspace must not even reach the KMS"
        );
    }

    /// POSITIVE CONTROL for the test above: the SAME inputs with the ONLY
    /// difference being `enabled: true` must produce a different result.
    /// Without this, `disabled_capture_stores_nothing` would also pass for a
    /// `seal` that always returned `None`.
    #[tokio::test]
    async fn enabled_capture_stores_ciphertext() {
        let (kms, calls) = kms();
        let sealed = seal(
            CaptureDecision {
                enabled: true,
                retention_days: 30,
            },
            kms.as_ref(),
            Some(SYNTHETIC.to_owned()),
            Some("upstream reply".to_owned()),
            Some("restored reply".to_owned()),
        )
        .await
        .expect("an opted-in workspace must produce content to store");

        assert_eq!(calls.load(Ordering::SeqCst), 3, "one KMS call per field");
        assert!(sealed.encrypted);
        assert_eq!(sealed.retention_days, 30);

        let stored = sealed.raw_prompt.as_deref().expect("raw_prompt sealed");
        assert_ne!(stored, SYNTHETIC, "the payload was stored verbatim");
        assert!(
            !stored.contains("Anvar Karimov"),
            "the synthetic name survived into the stored value: {stored:?}"
        );
        assert!(
            !stored.contains("50101901234567"),
            "the synthetic PINFL survived into the stored value: {stored:?}"
        );
    }

    /// A KMS outage must lose the capture, not downgrade it to plaintext.
    #[tokio::test]
    async fn encryption_failure_stores_nothing_rather_than_plaintext() {
        let sealed = seal(
            CaptureDecision {
                enabled: true,
                retention_days: 30,
            },
            &BrokenKms,
            Some(SYNTHETIC.to_owned()),
            None,
            None,
        )
        .await;
        assert!(
            sealed.is_none(),
            "a failed encrypt must abandon the capture, never fall back to raw"
        );
    }

    /// An opted-in workspace with nothing to store does not accumulate rows.
    #[tokio::test]
    async fn enabled_capture_with_no_content_stores_nothing() {
        let (kms, _) = kms();
        assert!(seal(
            CaptureDecision {
                enabled: true,
                retention_days: 30
            },
            kms.as_ref(),
            None,
            None,
            None,
        )
        .await
        .is_none());
        // Empty strings are equivalent to absent — an embedding request's
        // empty upstream content must not create a row either.
        assert!(seal(
            CaptureDecision {
                enabled: true,
                retention_days: 30
            },
            kms.as_ref(),
            Some(String::new()),
            Some(String::new()),
            Some(String::new()),
        )
        .await
        .is_none());
    }

    /// The `Debug` impl is an egress path. It must not print the payload.
    #[test]
    fn debug_impl_does_not_print_the_payload() {
        let content = CapturedContent {
            raw_prompt: Some("ciphertext-stand-in".to_owned()),
            raw_response: None,
            restored_response: None,
            encrypted: true,
            retention_days: 30,
        };
        let rendered = format!("{content:?}");
        assert!(
            !rendered.contains("ciphertext-stand-in"),
            "Debug printed the payload: {rendered}"
        );
        // Positive control: it does print SOMETHING useful, so this is not
        // passing because Debug renders an empty string.
        assert!(rendered.contains("raw_prompt_len"), "got: {rendered}");
        assert!(rendered.contains("retention_days"), "got: {rendered}");
    }
}
