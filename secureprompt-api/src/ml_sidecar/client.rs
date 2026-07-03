use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;

use crate::ml_sidecar::types::{
    InjectionRequest, InjectionResponse, MlDetection, NerRequest, NerResponse, RagCheckRequest,
    RagCheckResponse,
};

const FAILURE_THRESHOLD: u32 = 5;
const OPEN_DURATION_SECS: u64 = 30;

/// Minimal atomic circuit breaker: OPEN after 5 consecutive failures, resets after 30s.
#[derive(Debug)]
struct AtomicCircuit {
    consecutive_failures: AtomicU32,
    open_since: AtomicU64, // unix seconds; 0 = closed
}

impl AtomicCircuit {
    fn new() -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            open_since: AtomicU64::new(0),
        }
    }

    fn is_open(&self) -> bool {
        let open_since = self.open_since.load(Ordering::Relaxed);
        if open_since == 0 {
            return false;
        }
        let now = now_secs();
        if now.saturating_sub(open_since) >= OPEN_DURATION_SECS {
            // Half-open: reset and allow one probe
            self.open_since.store(0, Ordering::Relaxed);
            self.consecutive_failures.store(0, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.open_since.store(0, Ordering::Relaxed);
    }

    /// Returns `true` if this failure caused the circuit to transition to OPEN.
    fn record_failure(&self) -> bool {
        let prev = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if prev + 1 == FAILURE_THRESHOLD {
            self.open_since.store(now_secs(), Ordering::Relaxed);
            return true; // just transitioned to OPEN
        }
        false
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Default char budget per NER chunk (well under the sidecar's 32,768-char
/// Pydantic cap — margin kept for multi-byte expansion/JSON overhead).
const DEFAULT_NER_CHUNK_CHARS: usize = 24_000;

/// Default aggregate wall-clock budget (ms) for the whole `detect_if_available`
/// chunk loop — mirrors the sidecar's log-and-truncate philosophy (XLM-R caps
/// do the same) so a slow-but-not-failing sidecar can't block the interactive
/// chat request path for minutes on an oversized prompt (Finding 2).
const DEFAULT_NER_TOTAL_BUDGET_MS: u64 = 30_000;

#[derive(Debug, Clone)]
pub struct MlSidecarClient {
    pub base_url: String,
    pub enabled: bool,
    http: Option<Client>,
    circuit: Option<Arc<AtomicCircuit>>,
    // P0-4: max chars per `/detect/ner` request. Prompts longer than this are
    // tiled via `split_for_ner` so oversized prompts get full coverage
    // instead of a single 422-rejected call.
    ner_chunk_chars: usize,
    // Aggregate wall-clock budget for the whole `detect_if_available` chunk
    // loop (Finding 2, whole-branch review): a slow-but-not-failing sidecar
    // can otherwise block a ~2MB prompt's ~87 serial chunk calls for minutes
    // on the interactive chat request path, before the upstream LLM call.
    ner_total_budget: Duration,
    // Observable counters — always allocated, zero when disabled.
    calls_total: Arc<AtomicU64>,
    failures_total: Arc<AtomicU64>,
    circuit_open_count: Arc<AtomicU64>,
    // Finding 1 (whole-branch review): 429 (NER-queue-full, sidecar
    // saturation) is a distinct, transient signal from other 4xx (malformed/
    // oversized request) — chunks skipped this way get ZERO PII coverage
    // under load, which must be observable in production, not folded into
    // the generic client-error path.
    saturated_total: Arc<AtomicU64>,
}

impl MlSidecarClient {
    #[must_use]
    pub fn new(base_url: String, timeout_ms: u64) -> Self {
        // T-03-05b: Reject non-empty URLs with invalid scheme to prevent SSRF via misconfiguration.
        let enabled = !base_url.is_empty()
            && (base_url.starts_with("http://") || base_url.starts_with("https://"));
        if !base_url.is_empty() && !enabled {
            tracing::warn!(
                url = %base_url,
                "ML_SIDECAR_URL has invalid scheme (expected http:// or https://); sidecar disabled"
            );
        }

        let (http, circuit) = if enabled {
            let h = Client::builder()
                .timeout(Duration::from_millis(timeout_ms))
                .use_rustls_tls()
                .build()
                .expect("reqwest client build failed");
            (Some(h), Some(Arc::new(AtomicCircuit::new())))
        } else {
            (None, None)
        };

        let ner_chunk_chars = std::env::var("ML_NER_CHUNK_CHARS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_NER_CHUNK_CHARS);

        // Finding 2 (whole-branch review): aggregate wall-clock budget for
        // the whole chunk loop, read from ML_NER_TOTAL_BUDGET_MS. Clamped to
        // at least `timeout_ms` so the budget can never be shorter than a
        // single chunk call (which would make the very first chunk break
        // the loop before it even completes).
        let ner_total_budget = std::env::var("ML_NER_TOTAL_BUDGET_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_millis(DEFAULT_NER_TOTAL_BUDGET_MS))
            .max(Duration::from_millis(timeout_ms));

        Self {
            base_url,
            enabled,
            http,
            circuit,
            ner_chunk_chars,
            ner_total_budget,
            calls_total: Arc::new(AtomicU64::new(0)),
            failures_total: Arc::new(AtomicU64::new(0)),
            circuit_open_count: Arc::new(AtomicU64::new(0)),
            saturated_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns ML detections. Returns empty Vec when circuit is OPEN or sidecar disabled (D-13).
    ///
    /// P0-4: the sidecar 422-rejects any single request whose `text` exceeds
    /// 32,768 chars. Before this fix, a >32k prompt got a 4xx which was
    /// treated as a generic failure — zero detections (unredacted
    /// pass-through) AND a circuit-breaker failure, so repeated long prompts
    /// could trip the breaker OPEN and fail-open ALL traffic, not just the
    /// oversized ones. Now: the prompt is tiled into `ner_chunk_chars`-sized
    /// chunks (full coverage) and a 4xx response is treated as "our request
    /// was malformed", never as a sidecar-health signal (see `detect_chunk`).
    pub async fn detect_if_available(&self, prompt: &str) -> Vec<MlDetection> {
        let (http, circuit) = match (&self.http, &self.circuit) {
            (Some(h), Some(c)) if self.enabled => (h, c),
            _ => return Vec::new(),
        };

        if circuit.is_open() {
            return Vec::new();
        }

        let mut all = Vec::new();
        let chunks = split_for_ner(prompt, self.ner_chunk_chars);
        let chunks_total = chunks.len();
        let started = std::time::Instant::now();
        for (chunks_done, (offset, chunk)) in chunks.into_iter().enumerate() {
            // The breaker may have opened mid-loop from a prior chunk's
            // transport/parse failure — stop issuing further chunk calls.
            if circuit.is_open() {
                break;
            }
            // Finding 2: a slow-but-not-failing sidecar has no other
            // deadline on this loop — each per-call timeout only bounds a
            // single chunk, and a ~2MB prompt can tile into dozens of
            // chunks on the interactive chat path (before the upstream LLM
            // call). Stop issuing new chunk calls once the aggregate
            // wall-clock budget is exhausted; already-collected detections
            // are kept (partial PII coverage beats none).
            if chunks_done > 0 && started.elapsed() >= self.ner_total_budget {
                tracing::warn!(
                    chunks_done,
                    chunks_total,
                    "NER chunking hit aggregate budget — remaining chunks skipped (partial PII coverage)"
                );
                break;
            }
            let mut dets = self.detect_chunk(http, circuit, &chunk).await;
            for det in &mut dets {
                det.span = rebase_span(det.span, offset);
            }
            all.extend(dets);
        }
        all
    }

    /// Query `/detect/ner` for a single chunk (already ≤ `ner_chunk_chars`
    /// chars). Spans in the returned `MlDetection`s are relative to the
    /// START of `chunk` — the caller (`detect_if_available`) rebases them to
    /// whole-prompt byte offsets.
    ///
    /// Breaker semantics (unchanged from the pre-chunking single-request
    /// code, for every arm EXCEPT the new 4xx one): success -> record_success
    /// + calls_total++; parse failure or transport failure -> record_failure
    /// + failures_total++ (+ circuit_open_count++ if that failure just
    /// tripped the breaker OPEN).
    async fn detect_chunk(&self, http: &Client, circuit: &AtomicCircuit, chunk: &str) -> Vec<MlDetection> {
        let url = format!("{}/detect/ner", self.base_url);
        let body = NerRequest {
            text: chunk.to_owned(),
        };

        match http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                // Finding 1 (whole-branch review): 429 = the sidecar's NER
                // queue is full (transient saturation under load), NOT a
                // malformed/oversized request. Distinct from the general 4xx
                // arm below: this chunk gets ZERO PII coverage, which must be
                // observable in production (a PII gateway silently failing
                // open under load is exactly the risk this counter guards
                // against). Same fail-open contract as other 4xx — do NOT
                // feed the circuit breaker, or a saturated sidecar would trip
                // the breaker OPEN and fail-open ALL traffic, not just the
                // saturated chunks (consistent with the 422 P0-4 rationale).
                tracing::warn!(
                    status = %resp.status(),
                    "ml sidecar saturated (queue full) — chunk skipped, NO PII coverage"
                );
                self.saturated_total.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
            Ok(resp) if resp.status().is_client_error() => {
                // 4xx (excluding 429, handled above) = OUR request was
                // rejected (e.g. still oversized, or malformed). This is not
                // a sidecar health signal — do NOT feed the circuit breaker,
                // or long prompts fail-open ALL traffic (P0-4).
                tracing::warn!(status = %resp.status(), "ml sidecar rejected NER request");
                Vec::new()
            }
            Ok(resp) => match resp.json::<NerResponse>().await {
                Ok(ner) => {
                    circuit.record_success();
                    self.calls_total.fetch_add(1, Ordering::Relaxed);
                    ner.entities
                        .into_iter()
                        .map(|e| MlDetection {
                            class: e.entity_type,
                            confidence: e.score,
                            span: Some((e.start, e.end)),
                            value: e.text,
                            compliance_categories: e.compliance_categories,
                        })
                        .collect()
                }
                Err(_) => {
                    if circuit.record_failure() {
                        self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                    }
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    Vec::new()
                }
            },
            Err(_) => {
                if circuit.record_failure() {
                    self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                }
                self.failures_total.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
        }
    }

    /// Call `/detect/injection` on the ML sidecar.
    ///
    /// Returns the classifier's confidence that the prompt contains an
    /// injection attempt. Fails open (`is_injection=false`, score=0.0) when
    /// the sidecar is disabled or the circuit is open — same fail-open
    /// contract as `detect_if_available` (D-13). Used by `secure_mode`
    /// enforcement when `block_on_injection_detection=true`.
    pub async fn injection_check_if_available(&self, prompt: &str) -> InjectionResponse {
        let empty = InjectionResponse {
            is_injection: false,
            score: 0.0,
        };
        let (http, circuit) = match (&self.http, &self.circuit) {
            (Some(h), Some(c)) if self.enabled => (h, c),
            _ => return empty,
        };
        if circuit.is_open() {
            return empty;
        }
        let url = format!("{}/detect/injection", self.base_url);
        let body = InjectionRequest {
            text: prompt.to_owned(),
        };
        match http.post(&url).json(&body).send().await {
            Ok(resp) => match resp.json::<InjectionResponse>().await {
                Ok(out) => {
                    circuit.record_success();
                    self.calls_total.fetch_add(1, Ordering::Relaxed);
                    out
                }
                Err(_) => {
                    if circuit.record_failure() {
                        self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                    }
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    empty
                }
            },
            Err(_) => {
                if circuit.record_failure() {
                    self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                }
                self.failures_total.fetch_add(1, Ordering::Relaxed);
                empty
            }
        }
    }

    /// Call `/v1/rag-check` on the ML sidecar. Returns empty response (no matches)
    /// when the circuit is OPEN or the sidecar is disabled (fail-open, D-13).
    pub async fn rag_check_if_available(&self, text: &str, workspace_id: uuid::Uuid) -> RagCheckResponse {
        let empty = RagCheckResponse {
            matches: vec![],
            is_match: false,
        };

        let (http, circuit) = match (&self.http, &self.circuit) {
            (Some(h), Some(c)) if self.enabled => (h, c),
            _ => return empty,
        };

        if circuit.is_open() {
            return empty;
        }

        let url = format!("{}/v1/rag-check", self.base_url);
        let body = RagCheckRequest {
            text: text.to_owned(),
            workspace_id: workspace_id.to_string(),
        };

        match http.post(&url).json(&body).send().await {
            Ok(resp) => match resp.json::<RagCheckResponse>().await {
                Ok(r) => {
                    circuit.record_success();
                    r
                }
                Err(_) => {
                    if circuit.record_failure() {
                        self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                    }
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    empty
                }
            },
            Err(_) => {
                if circuit.record_failure() {
                    self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                }
                self.failures_total.fetch_add(1, Ordering::Relaxed);
                empty
            }
        }
    }

    /// Relay the still-wrapped model blob to the sidecar. Best-effort, fail-open.
    ///
    /// The gateway holds ONLY the ATTEST-KEK and never unwraps the model key —
    /// it sends the ciphertext blob (`wrapped_b64`) and the license ID to the
    /// sidecar, which owns the MODEL-KEK and performs the actual unwrap.
    ///
    /// Independent of the circuit breaker — this is a one-shot internal call
    /// that MUST NOT affect the breaker state (it's not a user-facing request).
    /// A short-lived `reqwest::Client` is used so it has its own timeout and
    /// never interferes with the circuit-guarded `http` field.
    ///
    /// # Errors
    /// Returns `Err(String)` when the HTTP call fails or the sidecar returns
    /// a non-2xx status. The caller is responsible for logging and ignoring
    /// the error (fail-open).
    pub async fn push_wrapped_model_key(&self, wrapped_b64: &str, lic_id: &str, token: &str) -> Result<(), String> {
        let url = format!("{}/internal/model-key", self.base_url);
        let body = serde_json::json!({ "wrapped_key": wrapped_b64, "lic_id": lic_id });
        // Construct a short-lived client with a generous but bounded timeout.
        // We do not reuse `self.http` so this call never trips the circuit breaker.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .use_rustls_tls()
            .build()
            .map_err(|e| format!("failed to build push client: {e}"))?;
        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("sidecar returned {}", resp.status()))
        }
    }

    /// Prometheus metrics for the ML sidecar client.
    /// Append to the main metrics output in the /metrics HTTP handler.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        format!(
            concat!(
                "# TYPE secureprompt_ml_sidecar_calls_total counter\n",
                "secureprompt_ml_sidecar_calls_total {}\n",
                "# TYPE secureprompt_ml_sidecar_failures_total counter\n",
                "secureprompt_ml_sidecar_failures_total {}\n",
                "# TYPE secureprompt_ml_sidecar_circuit_open_total counter\n",
                "secureprompt_ml_sidecar_circuit_open_total {}\n",
                "# TYPE secureprompt_ml_sidecar_saturated_total counter\n",
                "secureprompt_ml_sidecar_saturated_total {}\n",
            ),
            self.calls_total.load(Ordering::Relaxed),
            self.failures_total.load(Ordering::Relaxed),
            self.circuit_open_count.load(Ordering::Relaxed),
            self.saturated_total.load(Ordering::Relaxed),
        )
    }
}

/// Rebase a detection span from chunk-local byte offsets to whole-prompt
/// byte offsets by adding the chunk's starting byte offset. Pure arithmetic,
/// factored out of `detect_if_available` so it's unit-testable without a
/// mock HTTP server (P0-4).
fn rebase_span(span: Option<(usize, usize)>, offset: usize) -> Option<(usize, usize)> {
    span.map(|(s, e)| (s + offset, e + offset))
}

/// Split text into (byte_offset, chunk) pairs of at most `max_chars`
/// characters, cutting at whitespace when one exists in the window. The
/// sidecar caps NER requests at 32,768 chars (Pydantic 422 beyond) — before
/// this, a long prompt got ZERO detections and the 422 poisoned the circuit
/// breaker for all traffic (P0-4).
pub(crate) fn split_for_ner(text: &str, max_chars: usize) -> Vec<(usize, String)> {
    // Defensive clamp: max_chars == 0 would never advance `start` in the
    // hard-cut branch below (infinite loop). The constructor already filters
    // ML_NER_CHUNK_CHARS to > 0, but this function is pub(crate) on a
    // security-critical path — guard here too, don't rely on one caller's
    // invariant.
    let max_chars = max_chars.max(1);
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    if chars.len() <= max_chars {
        return vec![(0, text.to_owned())];
    }
    let mut out = Vec::new();
    let mut start = 0usize; // index into chars
    while start < chars.len() {
        let hard_end = (start + max_chars).min(chars.len());
        let mut cut = hard_end;
        if hard_end < chars.len() {
            // walk back to just AFTER the last whitespace in the window
            let mut j = hard_end;
            while j > start && !chars[j - 1].1.is_whitespace() {
                j -= 1;
            }
            if j > start {
                cut = j;
            }
        }
        let start_byte = chars[start].0;
        let end_byte = if cut < chars.len() { chars[cut].0 } else { text.len() };
        out.push((start_byte, text[start_byte..end_byte].to_owned()));
        start = cut;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ML-05a: Disabled client (empty URL) returns empty detections.
    #[tokio::test]
    async fn test_circuit_open_returns_empty() {
        let client = MlSidecarClient::new(String::new(), 200);
        let result = client.detect_if_available("some prompt with PII").await;
        assert!(result.is_empty(), "disabled client must return empty Vec");
    }

    /// ML-05a: Unreachable sidecar returns empty (fail-open).
    #[tokio::test]
    async fn test_unreachable_sidecar_returns_empty() {
        let client = MlSidecarClient::new("http://127.0.0.1:19999".to_owned(), 50);
        let result = client.detect_if_available("test").await;
        assert!(result.is_empty(), "unreachable sidecar must return empty Vec");
    }

    /// ML-05a: Circuit OPEN after 5 consecutive failures.
    #[test]
    fn test_circuit_opens_after_threshold() {
        let circuit = AtomicCircuit::new();
        for _ in 0..FAILURE_THRESHOLD {
            circuit.record_failure();
        }
        assert!(circuit.is_open(), "circuit must be OPEN after threshold failures");
    }

    /// T-03-05b: Invalid URL scheme disables the client (SSRF protection).
    #[test]
    fn test_invalid_scheme_disables_client() {
        let client = MlSidecarClient::new("ftp://evil.example.com/ner".to_owned(), 200);
        assert!(!client.enabled, "invalid scheme must disable client");
    }

    /// rag_check_if_available returns empty when disabled.
    #[tokio::test]
    async fn test_rag_check_disabled_returns_empty() {
        let client = MlSidecarClient::new(String::new(), 200);
        let result = client
            .rag_check_if_available("some prompt", uuid::Uuid::new_v4())
            .await;
        assert!(!result.is_match, "disabled client must return is_match=false");
        assert!(result.matches.is_empty(), "disabled client must return empty matches");
    }

    /// rag_check_if_available returns empty when sidecar is unreachable.
    #[tokio::test]
    async fn test_rag_check_unreachable_returns_empty() {
        let client = MlSidecarClient::new("http://127.0.0.1:19999".to_owned(), 50);
        let result = client
            .rag_check_if_available("some prompt", uuid::Uuid::new_v4())
            .await;
        assert!(!result.is_match);
        assert!(result.matches.is_empty());
    }

    /// T-03-06b: circuit_open_count increments exactly on the 5th consecutive failure.
    #[tokio::test]
    async fn test_circuit_open_count_increments_on_threshold() {
        let circuit = Arc::new(AtomicCircuit::new());
        let open_count = Arc::new(AtomicU64::new(0));
        for _ in 0..(FAILURE_THRESHOLD - 1) {
            let just_opened = circuit.record_failure();
            assert!(!just_opened);
        }
        let just_opened = circuit.record_failure();
        assert!(just_opened, "5th failure must signal circuit just opened");
        if just_opened {
            open_count.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(open_count.load(Ordering::Relaxed), 1);
    }

    // --- P0-4: split_for_ner ---

    #[test]
    fn split_for_ner_short_text_single_chunk() {
        let out = split_for_ner("hello world", 100);
        assert_eq!(out, vec![(0usize, "hello world".to_string())]);
    }

    #[test]
    fn split_for_ner_tiles_text_at_whitespace() {
        let text = "word ".repeat(1000); // 5000 chars
        let out = split_for_ner(&text, 1200);
        assert!(out.len() > 1);
        // chunks tile the original text exactly
        let mut rebuilt = String::new();
        let mut expect_off = 0usize;
        for (off, chunk) in &out {
            assert_eq!(*off, expect_off);
            rebuilt.push_str(chunk);
            expect_off += chunk.len();
        }
        assert_eq!(rebuilt, text);
        // split points fall between words, not inside them
        for (_, chunk) in &out[..out.len() - 1] {
            assert!(chunk.ends_with(' '), "chunk must end at whitespace");
        }
    }

    #[test]
    fn split_for_ner_multibyte_safe() {
        let text = "Привет мир ".repeat(500);
        let out = split_for_ner(&text, 800);
        let rebuilt: String = out.iter().map(|(_, c)| c.as_str()).collect();
        assert_eq!(rebuilt, text); // no panic on char boundaries, exact tiling
    }

    /// Hard-cut branch: no whitespace anywhere in the window, so the split
    /// must fall back to cutting at exactly max_chars — exact tiling, no
    /// empty chunks, every chunk within the budget, loop terminates.
    #[test]
    fn split_for_ner_hard_cut_no_whitespace() {
        let text = "a".repeat(5000);
        let out = split_for_ner(&text, 1200);
        assert!(out.len() > 1);
        let mut expect_off = 0usize;
        for (off, chunk) in &out {
            assert_eq!(*off, expect_off, "chunks tile with no gaps/overlaps");
            assert!(!chunk.is_empty(), "no empty chunks");
            assert!(chunk.chars().count() <= 1200, "chunk within max_chars");
            expect_off += chunk.len();
        }
        let rebuilt: String = out.iter().map(|(_, c)| c.as_str()).collect();
        assert_eq!(rebuilt, text, "concatenation reproduces the input exactly");
    }

    /// Hard-cut branch with multibyte chars: no whitespace, 2-byte chars —
    /// byte-boundary math must not panic or produce partial chars.
    #[test]
    fn split_for_ner_hard_cut_multibyte_no_whitespace() {
        let text = "я".repeat(3000);
        let out = split_for_ner(&text, 800);
        assert!(out.len() > 1);
        for (_, chunk) in &out {
            assert!(!chunk.is_empty(), "no empty chunks");
            assert!(chunk.chars().count() <= 800, "chunk within max_chars");
        }
        let rebuilt: String = out.iter().map(|(_, c)| c.as_str()).collect();
        assert_eq!(rebuilt, text, "exact tiling, no panic on char boundaries");
    }

    /// max_chars == 0 is clamped to 1 instead of hanging (defensive guard —
    /// the constructor filters ML_NER_CHUNK_CHARS to > 0, but the function
    /// is pub(crate) and must not be able to infinite-loop).
    #[test]
    fn split_for_ner_zero_max_chars_terminates() {
        let out = split_for_ner("abc def", 0);
        assert!(!out.is_empty());
        let rebuilt: String = out.iter().map(|(_, c)| c.as_str()).collect();
        assert_eq!(rebuilt, "abc def");
    }

    // --- P0-4: span rebase arithmetic (pure logic; no mock-server crate in
    // this workspace, so this is the feasible equivalent per the task brief) ---

    #[test]
    fn rebase_span_adds_chunk_offset() {
        assert_eq!(rebase_span(Some((3, 7)), 1000), Some((1003, 1007)));
        assert_eq!(rebase_span(None, 1000), None);
        assert_eq!(rebase_span(Some((0, 0)), 0), Some((0, 0)));
    }

    // --- P0-4: 4xx must not trip the circuit breaker ---
    //
    // No mock-HTTP crate (wiremock/mockito) is in this workspace's
    // dev-dependencies, so this drives a real 4xx response off a raw
    // loopback TCP listener (same pattern already used by
    // `test_unreachable_sidecar_returns_empty` for real-socket testing).
    #[tokio::test]
    async fn test_4xx_does_not_trip_circuit_breaker() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let server = std::thread::spawn(move || {
            for _ in 0..FAILURE_THRESHOLD {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf); // drain the request, best-effort
                let body = b"{\"detail\":\"text exceeds 32768 chars\"}";
                let resp = format!(
                    "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        for _ in 0..FAILURE_THRESHOLD {
            let result = client.detect_if_available("some prompt").await;
            assert!(result.is_empty(), "4xx yields no detections");
        }

        assert_eq!(
            client.circuit_open_count.load(Ordering::Relaxed),
            0,
            "4xx responses must never trip the circuit breaker (P0-4)"
        );
        assert_eq!(
            client.failures_total.load(Ordering::Relaxed),
            0,
            "4xx responses must not count as sidecar failures (P0-4)"
        );
        assert!(!client.circuit.as_ref().unwrap().is_open());

        server.join().expect("mock server thread panicked");
    }

    // --- P0-4: end-to-end chunk + span-rebase through detect_if_available ---
    //
    // Same raw-TCP idiom as the 4xx test: the listener serves a valid
    // one-entity NerResponse (chunk-local span (0,4)) per request. With
    // ner_chunk_chars overridden to 50 (set directly — same module, avoids
    // env races between parallel tests), a 120-char prompt tiles into 3
    // chunks, so the client must issue 3 requests and return 3 detections
    // whose spans are rebased by each chunk's byte offset.
    #[tokio::test]
    async fn test_detect_chunks_and_rebases_spans_end_to_end() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let prompt = "word ".repeat(24); // 120 chars, whitespace-separated
        let expected_chunks = split_for_ner(&prompt, 50);
        assert_eq!(expected_chunks.len(), 3, "test setup: prompt must tile into 3 chunks");
        let n_chunks = expected_chunks.len();

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let server = std::thread::spawn(move || {
            for _ in 0..n_chunks {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf); // drain the request, best-effort
                let body = b"{\"entities\":[{\"entity_type\":\"PERSON\",\"start\":0,\"end\":4,\"score\":0.99,\"text\":\"word\",\"compliance_categories\":[]}]}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        let mut client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        client.ner_chunk_chars = 50;

        let dets = client.detect_if_available(&prompt).await;
        assert_eq!(dets.len(), n_chunks, "one detection per chunk");
        for (det, (off, _)) in dets.iter().zip(expected_chunks.iter()) {
            assert_eq!(
                det.span,
                Some((*off, off + 4)),
                "span must be rebased by the chunk's byte offset {off}"
            );
        }
        assert_eq!(
            client.calls_total.load(Ordering::Relaxed),
            n_chunks as u64,
            "each chunk is a successful sidecar call"
        );
        assert_eq!(client.failures_total.load(Ordering::Relaxed), 0);

        server.join().expect("mock server thread panicked");
    }

    // --- Finding 1 (whole-branch review): 429 is a distinct saturation
    // signal, not a generic 4xx failure, and must never touch the breaker ---

    #[tokio::test]
    async fn test_429_marks_saturated_not_failure() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf); // drain the request, best-effort
            let body = b"{\"detail\":\"NER queue full\"}";
            let resp = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body);
        });

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        let result = client.detect_if_available("some prompt").await;

        assert!(
            result.is_empty(),
            "429 yields no detections (fail-open — still zero PII coverage for this chunk)"
        );
        assert_eq!(
            client.saturated_total.load(Ordering::Relaxed),
            1,
            "429 must be counted distinctly via saturated_total"
        );
        assert_eq!(
            client.failures_total.load(Ordering::Relaxed),
            0,
            "429 must NOT count as a generic sidecar failure"
        );
        assert_eq!(
            client.circuit_open_count.load(Ordering::Relaxed),
            0,
            "429 must never trip the circuit breaker (consistent with other 4xx, P0-4)"
        );
        assert!(!client.circuit.as_ref().unwrap().is_open());

        server.join().expect("mock server thread panicked");
    }

    // --- Finding 2 (whole-branch review): aggregate wall-clock budget
    // truncates the chunk loop ---
    //
    // Deterministic without any sleep: the budget is set to ZERO, so
    // `started.elapsed() >= ner_total_budget` is true the instant the check
    // runs (before chunk index 1 is issued, per the "skip check for the
    // first chunk" rule). The mock server therefore only ever needs to
    // serve ONE request — no timing race, no flakiness.
    #[tokio::test]
    async fn test_aggregate_budget_truncates_chunk_loop() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let prompt = "word ".repeat(24); // 120 chars, whitespace-separated
        let expected_chunks = split_for_ner(&prompt, 50);
        assert_eq!(expected_chunks.len(), 3, "test setup: prompt must tile into 3 chunks");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let server = std::thread::spawn(move || {
            // Only ONE request is expected — the budget check breaks the
            // loop before a second chunk is ever issued.
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf); // drain the request, best-effort
            let body = b"{\"entities\":[{\"entity_type\":\"PERSON\",\"start\":0,\"end\":4,\"score\":0.99,\"text\":\"word\",\"compliance_categories\":[]}]}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body);
        });

        let mut client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        client.ner_chunk_chars = 50;
        client.ner_total_budget = Duration::ZERO;

        let dets = client.detect_if_available(&prompt).await;
        assert_eq!(
            dets.len(),
            1,
            "only the first chunk is processed before the exhausted budget breaks the loop"
        );
        assert_eq!(
            client.calls_total.load(Ordering::Relaxed),
            1,
            "only one sidecar call is issued once the aggregate budget is exhausted"
        );
        // The mock server thread only ever serves ONE connection then exits
        // (unlike test_detect_chunks_and_rebases_spans_end_to_end's `for _
        // in 0..n_chunks` loop) — deliberately, so that if the budget check
        // regresses, chunks 2/3 hit connection-refused (a transport
        // failure) instead of a real response, which would show up here as
        // a nonzero failures_total even though dets.len()/calls_total alone
        // wouldn't catch it.
        assert_eq!(
            client.failures_total.load(Ordering::Relaxed),
            0,
            "no further chunk calls (successful OR failed) are attempted past the budget break"
        );

        server.join().expect("mock server thread panicked");
    }
}
