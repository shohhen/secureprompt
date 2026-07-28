use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerRequest {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerEntity {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f32,
    pub text: String,
    pub compliance_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerResponse {
    pub entities: Vec<NerEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionRequest {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionResponse {
    pub is_injection: bool,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RagCheckRequest {
    pub text: String,
    pub workspace_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RagCheckMatch {
    pub rule_id: String,
    pub score: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RagCheckResponse {
    pub matches: Vec<RagCheckMatch>,
    pub is_match: bool,
}

/// Internal type for a single ML-detected entity, mapped to the gateway's Detection type.
#[derive(Debug, Clone)]
pub struct MlDetection {
    pub class: String,
    pub confidence: f32,
    pub span: Option<(usize, usize)>,
    pub value: String,
    pub compliance_categories: Vec<String>,
}

/// WS2-3 — why the ML sidecar produced NO coverage for an input.
///
/// Each variant is one of the paths on which `detect_if_available` returns an
/// empty detection set for a reason that has nothing to do with the input
/// text. `as_str` is the bounded Prometheus label — never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarOutage {
    /// No `ML_SIDECAR_URL` configured — ML detection was never deployed.
    Unconfigured,
    /// A URL is configured but the client is disabled (invalid scheme, per
    /// the T-03-05b SSRF guard). Distinct from `Unconfigured` because the
    /// operator believes ML detection is ON.
    Disabled,
    /// The circuit breaker is OPEN after consecutive sidecar failures.
    CircuitOpen,
    /// Every chunk we attempted came back without coverage (transport error,
    /// unparseable body, 4xx rejection, or 429 saturation). The socket may
    /// have been fine; what matters is that zero chunks were scanned.
    AllCallsFailed,
}

impl SidecarOutage {
    /// Bounded label for metrics / response headers / structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Disabled => "disabled",
            Self::CircuitOpen => "circuit_open",
            Self::AllCallsFailed => "all_calls_failed",
        }
    }
}

/// WS2-3 — how much ML coverage a `detect_if_available` call actually
/// produced.
///
/// The point of this type is that an empty `Vec<MlDetection>` is ambiguous:
/// it means "the sidecar ran and found nothing" on a healthy gateway and "the
/// sidecar never ran" during an outage, and the request path used to treat
/// both as "there was no PII".
///
/// WS2-6 will add a third variant here for partial coverage —
/// `Partial { chunks_done, chunks_total }`, the state the chunk loop reaches
/// when `ner_total_budget` expires with chunks left. Matches on this enum are
/// deliberately exhaustive (no `_` arm) at every enforcement point, so adding
/// that variant produces a compile error at each place that has to make a
/// decision about it rather than silently inheriting the `Complete` branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarCoverage {
    /// The sidecar answered for the whole input.
    Complete,
    /// The sidecar produced no coverage at all; only the deterministic
    /// gateway-side floor ran over this input.
    Absent(SidecarOutage),
}

/// WS2-3 — what `detect_if_available` returns: the detections plus whether
/// they can be trusted to represent the whole input.
#[derive(Debug, Clone)]
pub struct MlDetectionOutcome {
    pub detections: Vec<MlDetection>,
    pub coverage: SidecarCoverage,
}

impl MlDetectionOutcome {
    /// Sidecar answered — detections are whatever it found (possibly none).
    #[must_use]
    pub const fn complete(detections: Vec<MlDetection>) -> Self {
        Self {
            detections,
            coverage: SidecarCoverage::Complete,
        }
    }

    /// Sidecar produced nothing at all, for `reason`.
    #[must_use]
    pub const fn absent(reason: SidecarOutage) -> Self {
        Self {
            detections: Vec::new(),
            coverage: SidecarCoverage::Absent(reason),
        }
    }
}
