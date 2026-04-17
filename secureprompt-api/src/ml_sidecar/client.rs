use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;

use crate::ml_sidecar::types::{MlDetection, NerRequest, NerResponse};

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

    fn record_failure(&self) {
        let prev = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if prev + 1 >= FAILURE_THRESHOLD {
            self.open_since.store(now_secs(), Ordering::Relaxed);
        }
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
}

impl MlSidecarClient {
    #[must_use]
    pub fn new(base_url: String, timeout_ms: u64) -> Self {
        let enabled = !base_url.is_empty();
        if !enabled {
            return Self {
                base_url,
                enabled: false,
                http: None,
                circuit: None,
            };
        }
        let http = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .use_rustls_tls()
            .build()
            .expect("reqwest client build failed");

        Self {
            base_url,
            enabled: true,
            http: Some(http),
            circuit: Some(Arc::new(AtomicCircuit::new())),
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
                    circuit.record_failure();
                    Vec::new()
                }
            },
            Err(_) => {
                circuit.record_failure();
                Vec::new()
            }
        }
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
}
