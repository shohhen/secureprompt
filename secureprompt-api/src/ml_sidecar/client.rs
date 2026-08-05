use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;

use crate::ml_sidecar::types::{
    InjectionOutcome, InjectionRequest, InjectionResponse, MlDetection, MlDetectionOutcome,
    NerRequest, NerResponse, RagCheckRequest, RagCheckResponse, SidecarCoverage,
    SidecarOutage,
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

/// WS4-2 — default wall-clock budget (ms) for ONE forwarded file-scan call.
///
/// 120 s, chosen to sit ABOVE `secureprompt-chat`'s own
/// `SECUREPROMPT_SCAN_TIMEOUT_MS` (60 s) so the chat backend's budget stays the
/// binding one and routing a scan through the gateway does not shorten it.
pub const DEFAULT_SCAN_TIMEOUT_MS: u64 = 120_000;

/// Which verb a forwarded scan call uses. Only the two the sidecar's scan
/// surface serves: `POST` for the two kickoffs, `GET` for the status poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMethod {
    Get,
    Post,
}

/// One sidecar answer, kept as bytes so the gateway hands back exactly what the
/// sidecar said. Deliberately NOT deserialised into a typed scan result: the
/// gateway has no use for the redacted text, and parsing it would put a second
/// copy of the response contract here to drift from the sidecar's.
#[derive(Debug, Clone)]
pub struct SidecarProxyResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: bytes::Bytes,
}

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
    // WS1-5: shared secret sent as `Authorization: Bearer <token>` on every
    // outbound call (`/detect/ner`, `/detect/injection`, `/v1/rag-check`).
    // Sourced from `LicenseConfig::internal_token`
    // (`ML_SIDECAR_INTERNAL_TOKEN`) — the same env var the sidecar itself
    // reads to authenticate these calls. Empty by default so every existing
    // 2-arg `MlSidecarClient::new(...)` call site (tests + any caller that
    // hasn't opted in) keeps compiling unchanged; set via `with_token`.
    token: String,
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
            token: String::new(),
        }
    }

    /// WS1-5: attach the shared secret sent as `Authorization: Bearer
    /// <token>` on every outbound sidecar call. Builder-style so existing
    /// `MlSidecarClient::new(url, timeout_ms)` call sites (main.rs and every
    /// test in this workspace) keep compiling without a signature change;
    /// only the gateway's real startup path needs to call this.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = token.into();
        self
    }

    /// Returns ML detections **plus whether the sidecar actually covered the
    /// input** (WS2-3).
    ///
    /// This used to return a bare `Vec<MlDetection>`, which made an outage
    /// indistinguishable from "there is no PII here": unconfigured client,
    /// disabled client, and an OPEN circuit breaker all returned the same
    /// empty vector as a healthy sidecar scanning clean text, so a sidecar
    /// outage silently degraded every request to the deterministic floor and
    /// still answered 200. `MlDetectionOutcome::coverage` makes the
    /// difference explicit so the caller can apply the workspace's
    /// `sidecar_unavailable` policy (block vs degrade_with_alert).
    ///
    /// P0-4: the sidecar 422-rejects any single request whose `text` exceeds
    /// 32,768 chars. Before this fix, a >32k prompt got a 4xx which was
    /// treated as a generic failure — zero detections (unredacted
    /// pass-through) AND a circuit-breaker failure, so repeated long prompts
    /// could trip the breaker OPEN and fail-open ALL traffic, not just the
    /// oversized ones. Now: the prompt is tiled into `ner_chunk_chars`-sized
    /// chunks (full coverage) and a 4xx response is treated as "our request
    /// was malformed", never as a sidecar-health signal (see `detect_chunk`).
    pub async fn detect_if_available(&self, prompt: &str) -> MlDetectionOutcome {
        let (http, circuit) = match (&self.http, &self.circuit) {
            (Some(h), Some(c)) if self.enabled => (h, c),
            // Two distinct fail-open paths share this arm. `base_url` is the
            // discriminator: empty means ML detection was never configured;
            // non-empty means an operator DID configure it and the client
            // refused the URL (invalid scheme, T-03-05b), which is a
            // misconfiguration they need to hear about.
            _ => {
                return MlDetectionOutcome::absent(if self.base_url.is_empty() {
                    SidecarOutage::Unconfigured
                } else {
                    SidecarOutage::Disabled
                })
            }
        };

        if circuit.is_open() {
            return MlDetectionOutcome::absent(SidecarOutage::CircuitOpen);
        }

        let mut all = Vec::new();
        // Chunk-level coverage bookkeeping. `covered == 0` with at least one
        // attempt means this call produced NO PII coverage at all even though
        // the client was configured, enabled and the breaker was closed — the
        // fourth way an empty `Vec` used to be indistinguishable from "clean
        // text". WS2-6 turns `covered < attempted` into `Partial`.
        let mut attempted = 0usize;
        let mut covered = 0usize;
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
            attempted += 1;
            match self.detect_chunk(http, circuit, &chunk).await {
                Some(mut dets) => {
                    covered += 1;
                    for det in &mut dets {
                        det.span = rebase_span(det.span, offset);
                    }
                    all.extend(dets);
                }
                None => {
                    // This chunk got zero PII coverage. Already counted in
                    // `attempted`, deliberately not in `covered`.
                }
            }
        }

        match classify_coverage(attempted, covered, chunks_total) {
            SidecarCoverage::Complete => MlDetectionOutcome::complete(all),
            SidecarCoverage::Partial { .. } => {
                MlDetectionOutcome::partial(all, covered, chunks_total)
            }
            SidecarCoverage::Absent(reason) => MlDetectionOutcome::absent(reason),
        }
    }

    /// Query `/detect/ner` for a single chunk (already ≤ `ner_chunk_chars`
    /// chars). Spans in the returned `MlDetection`s are relative to the
    /// START of `chunk` — the caller (`detect_if_available`) rebases them to
    /// whole-prompt byte offsets.
    ///
    /// WS2-3: returns `Some(dets)` when the sidecar actually scanned this
    /// chunk — `Some(vec![])` legitimately means "scanned, nothing found" —
    /// and `None` when the chunk got NO coverage (transport error,
    /// unparseable body, 4xx rejection, 429 saturation). The caller needs
    /// that distinction to tell an outage apart from clean text.
    ///
    /// Breaker semantics (unchanged from the pre-chunking single-request
    /// code, for every arm EXCEPT the new 4xx one): success -> record_success
    /// + calls_total++; parse failure or transport failure -> record_failure
    /// + failures_total++ (+ circuit_open_count++ if that failure just
    /// tripped the breaker OPEN).
    async fn detect_chunk(
        &self,
        http: &Client,
        circuit: &AtomicCircuit,
        chunk: &str,
    ) -> Option<Vec<MlDetection>> {
        let url = format!("{}/detect/ner", self.base_url);
        let body = NerRequest {
            text: chunk.to_owned(),
        };

        match http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
        {
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
                None
            }
            Ok(resp) if resp.status().is_client_error() => {
                // 4xx (excluding 429, handled above) = OUR request was
                // rejected (e.g. still oversized, or malformed). This is not
                // a sidecar health signal — do NOT feed the circuit breaker,
                // or long prompts fail-open ALL traffic (P0-4).
                tracing::warn!(status = %resp.status(), "ml sidecar rejected NER request");
                None
            }
            Ok(resp) => match resp.json::<NerResponse>().await {
                Ok(ner) => {
                    circuit.record_success();
                    self.calls_total.fetch_add(1, Ordering::Relaxed);
                    Some(
                        ner.entities
                            .into_iter()
                            .map(|e| MlDetection {
                                class: e.entity_type,
                                confidence: e.score,
                                span: Some((e.start, e.end)),
                                value: e.text,
                                compliance_categories: e.compliance_categories,
                            })
                            .collect(),
                    )
                }
                Err(_) => {
                    if circuit.record_failure() {
                        self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                    }
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    None
                }
            },
            Err(_) => {
                if circuit.record_failure() {
                    self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                }
                self.failures_total.fetch_add(1, Ordering::Relaxed);
                None
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
    pub async fn injection_check_if_available(&self, prompt: &str) -> InjectionOutcome {
        let (http, circuit) = match (&self.http, &self.circuit) {
            (Some(h), Some(c)) if self.enabled => (h, c),
            _ => {
                return InjectionOutcome::absent(if self.base_url.is_empty() {
                    SidecarOutage::Unconfigured
                } else {
                    SidecarOutage::Disabled
                })
            }
        };
        if circuit.is_open() {
            return InjectionOutcome::absent(SidecarOutage::CircuitOpen);
        }
        let url = format!("{}/detect/injection", self.base_url);
        let body = InjectionRequest {
            text: prompt.to_owned(),
        };
        match http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_client_error() || resp.status().is_server_error() => {
                // Fix round 1: a non-2xx here used to be parsed as JSON and,
                // on failure, collapse to `is_injection = false` — the same
                // value a clean prompt produces. Report it as no coverage.
                tracing::warn!(status = %resp.status(), "ml sidecar rejected injection request");
                InjectionOutcome::absent(SidecarOutage::AllCallsFailed)
            }
            Ok(resp) => match resp.json::<InjectionResponse>().await {
                Ok(out) => {
                    circuit.record_success();
                    self.calls_total.fetch_add(1, Ordering::Relaxed);
                    InjectionOutcome::complete(out)
                }
                Err(_) => {
                    if circuit.record_failure() {
                        self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                    }
                    self.failures_total.fetch_add(1, Ordering::Relaxed);
                    InjectionOutcome::absent(SidecarOutage::AllCallsFailed)
                }
            },
            Err(_) => {
                if circuit.record_failure() {
                    self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
                }
                self.failures_total.fetch_add(1, Ordering::Relaxed);
                InjectionOutcome::absent(SidecarOutage::AllCallsFailed)
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

        match http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
        {
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

    /// WS4-2 — forward one file-scan request to the sidecar, verbatim.
    ///
    /// The gateway does not parse the multipart body. It authenticates the
    /// caller, role-gates them, records the scan, and hands the SAME bytes on
    /// with the sidecar's own credential attached — so the sidecar's request
    /// contract, its 15 MiB file ceiling, its 413/429/503 answers and its
    /// response shape all stay exactly as `secureprompt-chat` already expects
    /// them. Anything this gateway re-encoded would be a second place for the
    /// upload contract to drift.
    ///
    /// # Its own client, and why
    ///
    /// Two reasons, both deliberate:
    ///
    ///   * **Timeout.** `self.http` is built with `ML_SIDECAR_TIMEOUT_MS`
    ///     (30 s by default) because a chat request cannot wait longer for a
    ///     detection call. An OCR pass over a scanned PDF can. This client is
    ///     built with [`Self::scan_timeout`] instead, defaulting to 120 s so
    ///     the chat backend's own 60 s budget stays the binding one — routing
    ///     through the gateway must not shorten a scan that worked before.
    ///   * **The circuit breaker.** `self.circuit` guards the detection path
    ///     that every chat request runs through. A slow or failing file scan
    ///     must not open it, because that would degrade every prompt in the
    ///     deployment to the deterministic floor. Same reasoning
    ///     [`Self::push_wrapped_model_key`] states for the same choice.
    ///
    /// The client is built per call, as `push_wrapped_model_key` does. Scans
    /// are human-paced (one per uploaded file), so a fresh connection per scan
    /// costs a TCP handshake against a scan that already takes seconds.
    ///
    /// # Errors
    /// `Err(String)` when the sidecar is unconfigured, the request cannot be
    /// built, or the transport fails. A non-2xx from the sidecar is NOT an
    /// error here — it is returned as [`SidecarProxyResponse`] so the caller
    /// can hand the sidecar's own status and body back to the uploader.
    pub async fn proxy_scan(
        &self,
        method: ProxyMethod,
        path: &str,
        content_type: Option<&str>,
        body: bytes::Bytes,
    ) -> Result<SidecarProxyResponse, String> {
        if !self.enabled {
            return Err("ML sidecar is not configured".to_owned());
        }
        let url = format!("{}{}", self.base_url, path);
        let client = Client::builder()
            .timeout(Self::scan_timeout())
            .use_rustls_tls()
            .build()
            .map_err(|e| format!("failed to build scan client: {e}"))?;

        let mut request = match method {
            ProxyMethod::Get => client.get(&url),
            ProxyMethod::Post => client.post(&url).body(body),
        };
        request = request.header("Authorization", format!("Bearer {}", self.token));
        if let Some(value) = content_type {
            request = request.header(reqwest::header::CONTENT_TYPE, value);
        }

        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let response_content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(|e| e.to_string())?;
        Ok(SidecarProxyResponse {
            status,
            content_type: response_content_type,
            body,
        })
    }

    /// Wall-clock budget for one forwarded scan call.
    ///
    /// `ML_SIDECAR_SCAN_TIMEOUT_MS`, defaulting to
    /// [`DEFAULT_SCAN_TIMEOUT_MS`]. A zero or unparseable value falls back to
    /// the default rather than to "no timeout", the same rule
    /// `request_hygiene::parse_request_deadline` follows: a zero deadline
    /// would abort every scan instantly.
    fn scan_timeout() -> Duration {
        std::env::var("ML_SIDECAR_SCAN_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|ms| *ms > 0)
            .map_or(
                Duration::from_millis(DEFAULT_SCAN_TIMEOUT_MS),
                Duration::from_millis,
            )
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

/// Classify what the chunk loop achieved, from counts alone.
///
/// Pure and total, so every case — including ones the loop can only reach
/// through a timing race — is directly testable. `detect_if_available` calls
/// this and does nothing else with the counts.
///
/// * `attempted` — chunks for which a request was issued.
/// * `covered` — chunks the sidecar actually scanned (`attempted` minus the
///   ones that errored, 4xx'd or 429'd).
/// * `chunks_total` — chunks the prompt tiled into.
///
/// `attempted == 0` deserves its own arm. The loop breaks there only when the
/// breaker opens BETWEEN `detect_if_available`'s pre-loop `is_open()` check
/// and the first top-of-loop check — another task's failures tripping it
/// mid-call. The budget check cannot cause it (guarded by `chunks_done > 0`).
/// Zero chunks were read, so reporting `Complete` (which is what the code did
/// before this arm existed) hands out a clean bill of health for text nothing
/// looked at.
fn classify_coverage(attempted: usize, covered: usize, chunks_total: usize) -> SidecarCoverage {
    if attempted == 0 {
        return SidecarCoverage::Absent(SidecarOutage::CircuitOpen);
    }
    if covered == 0 {
        return SidecarCoverage::Absent(SidecarOutage::AllCallsFailed);
    }
    // Some scanned, some not: either chunk calls failed (`covered <
    // attempted`) or the loop stopped early and never issued the rest
    // (`attempted < chunks_total` — breaker opening mid-loop, or the
    // aggregate budget expiring). Comparing against `chunks_total` rather
    // than `attempted` is what catches the second case.
    if covered < chunks_total {
        return SidecarCoverage::Partial {
            chunks_covered: covered,
            chunks_total,
        };
    }
    SidecarCoverage::Complete
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
        assert!(
            result.detections.is_empty(),
            "disabled client must return no detections"
        );
    }

    /// ML-05a: Unreachable sidecar returns empty (fail-open).
    #[tokio::test]
    async fn test_unreachable_sidecar_returns_empty() {
        let client = MlSidecarClient::new("http://127.0.0.1:19999".to_owned(), 50);
        let result = client.detect_if_available("test").await;
        assert!(
            result.detections.is_empty(),
            "unreachable sidecar must return no detections"
        );
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
            assert!(result.detections.is_empty(), "4xx yields no detections");
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

        let dets = client.detect_if_available(&prompt).await.detections;
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
            result.detections.is_empty(),
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

        let dets = client.detect_if_available(&prompt).await.detections;
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

    // --- WS1-5: every outbound sidecar call must carry
    // `Authorization: Bearer <ML_SIDECAR_INTERNAL_TOKEN>`, matching the
    // sidecar's new fail-closed auth gate on every route except
    // /health, /ready, /metrics. Raw-TCP capture (same idiom as the 4xx/429
    // tests above) so we can inspect the literal request bytes rather than
    // trusting a mock crate to have wired the header through correctly. ---

    /// Spawn a one-shot loopback listener that captures the first request's
    /// raw bytes into `captured` and replies with `body` as a 200 OK JSON
    /// response. Shared by the three "does this call attach the header"
    /// tests below.
    fn spawn_capturing_server(
        body: &'static [u8],
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body);
            request
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn test_detect_if_available_attaches_authorization_header() {
        let (addr, server) = spawn_capturing_server(b"{\"entities\":[]}");

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000)
            .with_token("shared-secret-abc".to_owned());
        let _ = client.detect_if_available("hello world").await;

        let request = server
            .join()
            .expect("mock server thread panicked")
            .to_lowercase();
        assert!(
            request.contains("authorization: bearer shared-secret-abc"),
            "detect_if_available must send the Authorization header; got request:\n{request}"
        );
    }

    #[tokio::test]
    async fn test_injection_check_attaches_authorization_header() {
        let (addr, server) = spawn_capturing_server(b"{\"is_injection\":false,\"score\":0.0}");

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000)
            .with_token("shared-secret-abc".to_owned());
        let _ = client.injection_check_if_available("hello world").await;

        let request = server
            .join()
            .expect("mock server thread panicked")
            .to_lowercase();
        assert!(
            request.contains("authorization: bearer shared-secret-abc"),
            "injection_check_if_available must send the Authorization header; got request:\n{request}"
        );
    }

    #[tokio::test]
    async fn test_rag_check_attaches_authorization_header() {
        let (addr, server) = spawn_capturing_server(b"{\"matches\":[],\"is_match\":false}");

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000)
            .with_token("shared-secret-abc".to_owned());
        let _ = client
            .rag_check_if_available("hello world", uuid::Uuid::new_v4())
            .await;

        let request = server
            .join()
            .expect("mock server thread panicked")
            .to_lowercase();
        assert!(
            request.contains("authorization: bearer shared-secret-abc"),
            "rag_check_if_available must send the Authorization header; got request:\n{request}"
        );
    }

    // --- WS2-3: coverage reporting -------------------------------------
    //
    // `detect_if_available` used to return a bare `Vec<MlDetection>`, so an
    // EMPTY vector meant either "the sidecar ran and found no PII" or "the
    // sidecar never ran at all". The caller could not tell the two apart, so
    // an outage silently degraded the gateway to the deterministic floor with
    // a 200 response. These tests pin the distinction.

    /// POSITIVE CONTROL for the whole coverage block below: with a REACHABLE
    /// sidecar that answers with a real entity, the outcome must carry that
    /// detection AND report `Complete`. Without this, every "coverage is
    /// Absent" assertion below could pass simply because the client never
    /// talks to anything.
    #[tokio::test]
    async fn test_healthy_sidecar_reports_complete_coverage() {
        let (addr, server) = spawn_capturing_server(
            b"{\"entities\":[{\"entity_type\":\"PERSON\",\"start\":0,\"end\":5,\"score\":0.99,\"text\":\"Anvar\",\"compliance_categories\":[]}]}",
        );

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        let outcome = client.detect_if_available("Anvar keldi").await;

        let request = server.join().expect("mock server thread panicked");
        assert!(
            request.to_lowercase().contains("post /detect/ner"),
            "the sidecar must actually have been reached; got request:\n{request}"
        );
        assert_eq!(
            outcome.detections.len(),
            1,
            "a healthy sidecar must yield its detections"
        );
        assert_eq!(outcome.detections[0].class, "PERSON");
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Complete,
            "a healthy sidecar must report Complete coverage"
        );
    }

    /// Fail-open path 1 of 3: no `ML_SIDECAR_URL` at all.
    #[tokio::test]
    async fn test_unconfigured_client_reports_absent_unconfigured() {
        let client = MlSidecarClient::new(String::new(), 200);
        let outcome = client.detect_if_available("Anvar keldi").await;
        assert!(outcome.detections.is_empty());
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Absent(SidecarOutage::Unconfigured)
        );
    }

    /// Fail-open path 2 of 3: a URL is set but the client is disabled
    /// (invalid scheme — T-03-05b's SSRF guard). Distinct from "never
    /// configured": an operator who set a URL believes ML detection is ON.
    #[tokio::test]
    async fn test_invalid_scheme_client_reports_absent_disabled() {
        let client = MlSidecarClient::new("ftp://evil.example.com/ner".to_owned(), 200);
        let outcome = client.detect_if_available("Anvar keldi").await;
        assert!(outcome.detections.is_empty());
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Absent(SidecarOutage::Disabled)
        );
    }

    /// Fail-open path 3 of 3: the circuit breaker is OPEN.
    ///
    /// The loop drives real transport failures against a closed loopback port
    /// until the breaker actually reports OPEN (bounded, and asserted — the
    /// iteration count is NOT derived from `FAILURE_THRESHOLD`, so a change to
    /// that constant surfaces here as a loud failure rather than a silently
    /// re-tuned test). Every pre-open call reports `AllCallsFailed` — zero
    /// chunks covered — which is itself a distinct fail-open path from
    /// `CircuitOpen` and must not be conflated with it.
    #[tokio::test]
    async fn test_open_circuit_reports_absent_circuit_open() {
        let client = MlSidecarClient::new("http://127.0.0.1:19999".to_owned(), 50);

        let mut opened = false;
        for _ in 0..20 {
            let outcome = client.detect_if_available("Anvar keldi").await;
            assert!(outcome.detections.is_empty());
            assert_eq!(
                outcome.coverage,
                SidecarCoverage::Absent(SidecarOutage::AllCallsFailed),
                "before the breaker opens, a dead sidecar reports AllCallsFailed"
            );
            if client.circuit.as_ref().expect("circuit").is_open() {
                opened = true;
                break;
            }
        }
        assert!(opened, "consecutive transport failures must open the breaker");

        let outcome = client.detect_if_available("Anvar keldi").await;
        assert!(outcome.detections.is_empty());
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Absent(SidecarOutage::CircuitOpen),
            "once the breaker is OPEN the outcome must say so, not AllCallsFailed"
        );
    }

    /// A 4xx rejection covers ZERO chunks even though the socket was fine —
    /// the returned detections are empty for the same reason an outage is
    /// empty, so it must report Absent too (and, per P0-4, still must not
    /// touch the breaker).
    #[tokio::test]
    async fn test_4xx_reports_absent_all_calls_failed() {
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
            let _ = stream.read(&mut buf);
            let body = b"{\"detail\":\"text exceeds 32768 chars\"}";
            let resp = format!(
                "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body);
        });

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        let outcome = client.detect_if_available("Anvar keldi").await;

        assert!(outcome.detections.is_empty());
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Absent(SidecarOutage::AllCallsFailed)
        );
        assert_eq!(
            client.circuit_open_count.load(Ordering::Relaxed),
            0,
            "4xx still must not trip the breaker (P0-4)"
        );

        server.join().expect("mock server thread panicked");
    }

    /// A healthy sidecar that genuinely finds nothing is NOT an outage: empty
    /// detections + `Complete`. This is the case the old `Vec` return type
    /// made indistinguishable from every test above.
    #[tokio::test]
    async fn test_healthy_sidecar_with_no_entities_is_not_an_outage() {
        let (addr, server) = spawn_capturing_server(b"{\"entities\":[]}");

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        let outcome = client.detect_if_available("nothing sensitive here").await;

        let request = server.join().expect("mock server thread panicked");
        assert!(
            request.to_lowercase().contains("post /detect/ner"),
            "the sidecar must actually have been reached; got request:\n{request}"
        );
        assert!(outcome.detections.is_empty());
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Complete,
            "empty detections from a LIVE sidecar means 'no PII', not 'no coverage'"
        );
    }

    // --- Fix round 1, CRITICAL 1: partial coverage is NOT complete ------
    //
    // A prompt longer than `ner_chunk_chars` tiles into several chunks. If
    // some chunks are scanned and others are not, the unscanned remainder has
    // had NO PII detection run over it. Reporting that as `Complete` lets a
    // `block` workspace forward unscanned text to the provider, which is the
    // exact failure this whole feature exists to prevent — just above 24k
    // chars instead of at zero.

    /// Chunk 1 answered, chunk 2 refused (server stops accepting): coverage is
    /// PARTIAL, and the surviving detection is still returned.
    #[tokio::test]
    async fn test_some_chunks_uncovered_reports_partial() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let prompt = "word ".repeat(24); // 120 chars
        let expected = split_for_ner(&prompt, 50);
        assert_eq!(expected.len(), 3, "test setup: prompt must tile into 3 chunks");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        // Serve exactly ONE chunk, then drop the listener so every later
        // chunk hits connection-refused.
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = b"{\"entities\":[{\"entity_type\":\"PERSON\",\"start\":0,\"end\":4,\"score\":0.99,\"text\":\"word\",\"compliance_categories\":[]}]}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body);
            drop(listener);
        });

        let mut client = MlSidecarClient::new(format!("http://{addr}"), 200);
        client.ner_chunk_chars = 50;
        let outcome = client.detect_if_available(&prompt).await;

        server.join().expect("mock server thread panicked");
        assert_eq!(
            outcome.detections.len(),
            1,
            "the chunk that WAS scanned still contributes its detection"
        );
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Partial {
                chunks_covered: 1,
                chunks_total: 3
            },
            "1 of 3 chunks scanned is PARTIAL coverage, not Complete"
        );
    }

    /// The aggregate wall-clock budget abandons the remaining chunks. Those
    /// chunks were never even attempted, so the text they cover was never
    /// scanned — also partial, not complete.
    #[tokio::test]
    async fn test_budget_truncated_loop_reports_partial() {
        let (addr, server) = spawn_capturing_server(
            b"{\"entities\":[{\"entity_type\":\"PERSON\",\"start\":0,\"end\":4,\"score\":0.99,\"text\":\"word\",\"compliance_categories\":[]}]}",
        );

        let prompt = "word ".repeat(24); // 120 chars -> 3 chunks at 50
        let mut client = MlSidecarClient::new(format!("http://{addr}"), 200);
        client.ner_chunk_chars = 50;
        client.ner_total_budget = Duration::ZERO;

        let outcome = client.detect_if_available(&prompt).await;
        let _ = server.join();

        assert_eq!(outcome.detections.len(), 1);
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Partial {
                chunks_covered: 1,
                chunks_total: 3
            },
            "chunks skipped by the aggregate budget are unscanned text"
        );
    }

    /// POSITIVE CONTROL for the two tests above: when EVERY chunk of a
    /// multi-chunk prompt is scanned, coverage is Complete. Without this,
    /// "multi-chunk means Partial" could pass by classifying all tiled
    /// prompts as partial, which would make `block` reject healthy traffic.
    #[tokio::test]
    async fn test_all_chunks_covered_reports_complete() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let prompt = "word ".repeat(24);
        let expected = split_for_ner(&prompt, 50);
        let n = expected.len();
        assert_eq!(n, 3, "test setup: prompt must tile into 3 chunks");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            for _ in 0..n {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let body = b"{\"entities\":[]}";
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
        let outcome = client.detect_if_available(&prompt).await;
        server.join().expect("mock server thread panicked");

        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Complete,
            "every chunk scanned is Complete, even across several chunks"
        );
    }

    // --- Fix round 2: `classify_coverage`, directly ---------------------
    //
    // The previous test for the `attempted == 0` branch was VACUOUS. It drove
    // the breaker open and called `detect_if_available`, which returns at the
    // PRE-LOOP `is_open()` check with the identical `Absent(CircuitOpen)` —
    // so deleting the branch left the test passing. Verified by deleting the
    // branch and re-running (see the report). The branch is now a case in the
    // pure `classify_coverage`, which is reachable from a test without
    // needing to win a race inside the chunk loop.

    /// Every (attempted, covered, chunks_total) shape the loop can produce.
    /// Written out as literal triples rather than generated from the
    /// function's own thresholds, so a change to those thresholds shows up
    /// here as a failure instead of being absorbed.
    #[test]
    fn classify_coverage_covers_every_shape() {
        // Zero chunks attempted: the breaker opened between the pre-loop
        // check and the first iteration. THIS is the case the old test
        // claimed but did not cover.
        assert_eq!(
            classify_coverage(0, 0, 3),
            SidecarCoverage::Absent(SidecarOutage::CircuitOpen)
        );
        assert_eq!(
            classify_coverage(0, 0, 1),
            SidecarCoverage::Absent(SidecarOutage::CircuitOpen)
        );

        // Attempted, nothing covered.
        assert_eq!(
            classify_coverage(1, 0, 1),
            SidecarCoverage::Absent(SidecarOutage::AllCallsFailed)
        );
        assert_eq!(
            classify_coverage(3, 0, 3),
            SidecarCoverage::Absent(SidecarOutage::AllCallsFailed),
            "a multi-chunk prompt where every chunk failed is a total outage, \
             not partial coverage"
        );

        // Partial: some chunks failed.
        assert_eq!(
            classify_coverage(3, 2, 3),
            SidecarCoverage::Partial {
                chunks_covered: 2,
                chunks_total: 3
            }
        );
        // Partial: loop stopped early, remaining chunks never issued. This is
        // the case `covered < attempted` alone would MISS.
        assert_eq!(
            classify_coverage(1, 1, 5),
            SidecarCoverage::Partial {
                chunks_covered: 1,
                chunks_total: 5
            },
            "budget-truncated loops never issue the rest; that text is unscanned"
        );

        // Complete, single and multi chunk.
        assert_eq!(classify_coverage(1, 1, 1), SidecarCoverage::Complete);
        assert_eq!(classify_coverage(4, 4, 4), SidecarCoverage::Complete);
    }

    /// Mutation guard: each arm must be individually load-bearing. If any two
    /// of these collapsed to the same value, `classify_coverage` would be
    /// passing the table above by accident.
    #[test]
    fn classify_coverage_arms_are_distinct() {
        let outcomes = [
            classify_coverage(0, 0, 3),
            classify_coverage(3, 0, 3),
            classify_coverage(3, 2, 3),
            classify_coverage(3, 3, 3),
        ];
        for (i, a) in outcomes.iter().enumerate() {
            for b in outcomes.iter().skip(i + 1) {
                assert_ne!(a, b, "two classification arms produced the same result");
            }
        }
    }

    /// The PRE-LOOP breaker check (a different code path from the branch
    /// above — this one never enters the chunk loop at all). Renamed from
    /// `test_zero_chunks_attempted_reports_circuit_open`, which claimed to
    /// cover the mid-loop race and did not.
    #[tokio::test]
    async fn test_open_breaker_short_circuits_before_the_chunk_loop() {
        let client = MlSidecarClient::new("http://127.0.0.1:19999".to_owned(), 50);
        let circuit = client.circuit.as_ref().expect("circuit").clone();

        let mut opened = false;
        for _ in 0..20 {
            let _ = client.detect_if_available("x").await;
            if circuit.is_open() {
                opened = true;
                break;
            }
        }
        assert!(opened, "test premise: the breaker must be OPEN");

        let outcome = client.detect_if_available("x").await;
        assert_eq!(
            outcome.coverage,
            SidecarCoverage::Absent(SidecarOutage::CircuitOpen),
            "an OPEN breaker must never classify as covered"
        );
    }

    /// Positive control for the three tests above: prove the capture
    /// mechanism itself is live by asserting a DIFFERENT, well-known header
    /// (Content-Type, always sent by reqwest's `.json()`) is present. Without
    /// this, a broken capture (e.g. reading zero bytes) would make the
    /// "header must be absent/wrong" style assertions vacuously pass.
    #[tokio::test]
    async fn test_capturing_server_actually_captures_request_headers() {
        let (addr, server) = spawn_capturing_server(b"{\"entities\":[]}");

        let client = MlSidecarClient::new(format!("http://{addr}"), 3000);
        let _ = client.detect_if_available("hello world").await;

        let request = server
            .join()
            .expect("mock server thread panicked")
            .to_lowercase();
        assert!(
            request.contains("content-type: application/json"),
            "capture mechanism must see real request headers; got:\n{request}"
        );
    }
}
