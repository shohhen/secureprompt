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

#[derive(Debug, Clone)]
pub struct MlSidecarClient {
    pub base_url: String,
    pub enabled: bool,
    http: Option<Client>,
    circuit: Option<Arc<AtomicCircuit>>,
    // Observable counters — always allocated, zero when disabled.
    calls_total: Arc<AtomicU64>,
    failures_total: Arc<AtomicU64>,
    circuit_open_count: Arc<AtomicU64>,
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

        Self {
            base_url,
            enabled,
            http,
            circuit,
            calls_total: Arc::new(AtomicU64::new(0)),
            failures_total: Arc::new(AtomicU64::new(0)),
            circuit_open_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns ML detections. Returns empty Vec when circuit is OPEN or sidecar disabled (D-13).
    pub async fn detect_if_available(&self, prompt: &str) -> Vec<MlDetection> {
        let (http, circuit) = match (&self.http, &self.circuit) {
            (Some(h), Some(c)) if self.enabled => (h, c),
            _ => return Vec::new(),
        };

        if circuit.is_open() {
            return Vec::new();
        }

        let url = format!("{}/detect/ner", self.base_url);
        let body = NerRequest {
            text: prompt.to_owned(),
        };

        match http.post(&url).json(&body).send().await {
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
            ),
            self.calls_total.load(Ordering::Relaxed),
            self.failures_total.load(Ordering::Relaxed),
            self.circuit_open_count.load(Ordering::Relaxed),
        )
    }
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
}
