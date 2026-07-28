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
/// Do NOT match on this enum directly at an enforcement point. Classify it
/// once via [`CoverageLoss::from_coverage`] and act on that — see the note on
/// that function for why there is exactly one classification site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarCoverage {
    /// The sidecar answered for the whole input.
    Complete,
    /// Some chunks of the input were scanned and some were not — the chunk
    /// loop stopped early (aggregate `ner_total_budget` expired, breaker
    /// opened mid-loop) or individual chunk calls failed while others
    /// succeeded.
    ///
    /// The detections that came back are real, but the text in the unscanned
    /// chunks has had NO ML detection run over it. Any prompt longer than
    /// `ner_chunk_chars` (24,000 by default) tiles into several chunks, so
    /// this is the common case for long documents, not an edge case — which
    /// is why it must never be classified as `Complete`.
    Partial {
        chunks_covered: usize,
        chunks_total: usize,
    },
    /// The sidecar produced no coverage at all; only the deterministic
    /// gateway-side floor ran over this input.
    Absent(SidecarOutage),
}

/// WS2-3 — why a request's ML detection cannot be trusted to represent the
/// whole input. The single value every enforcement point acts on.
///
/// Separate from [`SidecarOutage`] because "no coverage at all" and "coverage
/// with holes in it" have different operator meanings (sidecar down vs prompt
/// outran the budget) but identical security consequences: text reached the
/// classification point unscanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageLoss {
    /// No coverage at all, for the given reason.
    Outage(SidecarOutage),
    /// Some of the input was scanned, some was not.
    Partial,
}

impl CoverageLoss {
    /// **The only place `SidecarCoverage` is classified.**
    ///
    /// Fix round 1: an earlier version of this feature matched on
    /// `SidecarCoverage` at four separate enforcement points, two of them via
    /// `if let SidecarCoverage::Absent(..)`. `if let` compiles unchanged when
    /// a variant is added and silently treats the new variant as "covered",
    /// so the compile-time safety net that was claimed for adding `Partial`
    /// did not actually exist at three of the four sites.
    ///
    /// Funnelling every site through this one exhaustive `match` (no `_` arm)
    /// fixes that properly: adding a `SidecarCoverage` variant breaks exactly
    /// this function, and whatever classification is chosen here then
    /// propagates to every decision site consistently — which is stronger
    /// than N independent matches that could classify it N different ways.
    #[must_use]
    pub const fn from_coverage(coverage: &SidecarCoverage) -> Option<Self> {
        match coverage {
            SidecarCoverage::Complete => None,
            SidecarCoverage::Partial { .. } => Some(Self::Partial),
            SidecarCoverage::Absent(reason) => Some(Self::Outage(*reason)),
        }
    }

    /// Bounded label for metrics / response headers / structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outage(reason) => reason.as_str(),
            Self::Partial => "partial_coverage",
        }
    }
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

    /// Sidecar scanned `chunks_covered` of `chunks_total` chunks. The
    /// detections are real; the rest of the input was never looked at.
    #[must_use]
    pub const fn partial(
        detections: Vec<MlDetection>,
        chunks_covered: usize,
        chunks_total: usize,
    ) -> Self {
        Self {
            detections,
            coverage: SidecarCoverage::Partial {
                chunks_covered,
                chunks_total,
            },
        }
    }
}

/// WS2-3 fix round 1 — `injection_check_if_available`'s result plus whether
/// the sidecar actually answered.
///
/// `/detect/injection` fails INDEPENDENTLY of `/detect/ner`: a 5xx or an
/// unparseable body yields `is_injection = false`, which is
/// indistinguishable from "this prompt is clean". A workspace with
/// `block_on_injection_detection` (or `level = strict`) would have its
/// injection gate silently bypassed while NER coverage looked perfectly
/// healthy.
#[derive(Debug, Clone)]
pub struct InjectionOutcome {
    pub response: InjectionResponse,
    pub coverage: SidecarCoverage,
}

impl InjectionOutcome {
    #[must_use]
    pub const fn complete(response: InjectionResponse) -> Self {
        Self {
            response,
            coverage: SidecarCoverage::Complete,
        }
    }

    /// The classifier never answered. `is_injection = false` here means "we
    /// do not know", NOT "clean" — the caller must treat it as coverage loss.
    #[must_use]
    pub fn absent(reason: SidecarOutage) -> Self {
        Self {
            response: InjectionResponse {
                is_injection: false,
                score: 0.0,
            },
            coverage: SidecarCoverage::Absent(reason),
        }
    }
}
