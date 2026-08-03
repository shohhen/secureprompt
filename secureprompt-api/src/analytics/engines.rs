//! WS2-4 — which detection engines produced coverage for a request.
//!
//! # Why a closed enum and not a `Vec<String>`
//!
//! The whole value of this field to an auditor is that it is a claim the
//! product makes about itself, so it must not be constructible from anything
//! that varies with the request. A `Vec<String>` assigned at four call sites
//! could drift, could be spelled three ways, and could — as
//! `MlDetection::entity_type` did before WS3-6 put an allowlist in front of it
//! — end up carrying a value off the ML sidecar's wire. Here the only
//! constructor is [`DetectionEngines::from_coverage`], the strings are three
//! `&'static str` literals, and the ClickHouse column can hold nothing else.
//!
//! # Why the match in `from_coverage` has no `_` arm
//!
//! Same doctrine as [`crate::ml_sidecar::types::CoverageLoss::from_coverage`],
//! and for the same measured reason recorded there: `if let` / `_` over
//! `SidecarCoverage` compiles unchanged when a variant is added and silently
//! classifies the new variant as "covered". A new coverage state must be a
//! compile error here, not a silent over-claim in an audit record.
//!
//! # Scope: the PROMPT-side pass
//!
//! This describes the detection pass that ran over the prompt BEFORE anything
//! was forwarded upstream — the scan that decides what leaves the network, and
//! the one an auditor is asking about. It deliberately does not fold in the
//! response-side pass. See `clickhouse/migrations/009_detection_engines.sql`
//! for why folding them together is what makes `floor_only` misleading.

use crate::ml_sidecar::types::SidecarCoverage;

/// The deterministic Rust floor (`detection::detect_content`).
///
/// Present on every request without exception. It is in-process, has no
/// configuration, no network dependency and no policy gate, and it runs before
/// the sidecar is consulted — so there is no state in which a request was
/// served and this did not run. An `engines` array that does NOT contain it is
/// therefore not "the floor was skipped"; it is a row written before migration
/// 009 existed.
pub const FLOOR: &str = "floor";

/// The ML sidecar, over the whole input.
pub const ML: &str = "ml";

/// The ML sidecar, over SOME chunks of the input only.
///
/// Not a cosmetic distinction. Any prompt longer than `ner_chunk_chars`
/// (24,000 by default) tiles into several `/detect/ner` calls, so on the
/// multi-hundred-KB bank documents this product exists for, partial coverage
/// is the ordinary failure mode rather than an edge case. Collapsing it into
/// [`ML`] would over-claim; collapsing it into floor-only would erase real ML
/// detections that are sitting in the same request's `detection_class_counts`
/// rows with no explanation for how they got there.
pub const ML_PARTIAL: &str = "ml_partial";

/// Which engines produced detection coverage for one request's prompt.
///
/// Construct with [`Self::from_coverage`]. The variants are public only so
/// tests can name an expectation; nothing on the request path should be
/// building one by hand, because the whole point is that the value is derived
/// from the coverage the sidecar actually reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetectionEngines {
    /// The deterministic floor alone — the ML sidecar produced no coverage.
    ///
    /// The DEFAULT, deliberately. A `RequestEvent` that nobody remembered to
    /// call [`crate::analytics::events::RequestEvent::record_engines`] on
    /// under-claims rather than over-claims: it says less scanning happened
    /// than did, which is the safe direction for an audit record to be wrong
    /// in. The reverse default would let a forgotten call site assert that a
    /// model scanned a prompt it never saw.
    #[default]
    FloorOnly,
    /// The floor plus complete ML coverage of the input.
    FloorAndMl,
    /// The floor plus ML coverage of part of the input.
    FloorAndPartialMl,
}

impl DetectionEngines {
    /// The engines implied by what the sidecar actually reported.
    ///
    /// Exhaustive by construction — see the module docs for why there is no
    /// `_` arm.
    #[must_use]
    pub const fn from_coverage(coverage: &SidecarCoverage) -> Self {
        match coverage {
            SidecarCoverage::Complete => Self::FloorAndMl,
            SidecarCoverage::Partial { .. } => Self::FloorAndPartialMl,
            SidecarCoverage::Absent(_) => Self::FloorOnly,
        }
    }

    /// The names, in a stable order, for the ClickHouse `Array(String)` column
    /// and the response header.
    ///
    /// Stable order matters for both consumers: a ClickHouse part diff and an
    /// HTTP header that reordered themselves run to run would be unreadable
    /// and would make every test order-dependent for no benefit.
    #[must_use]
    pub const fn as_slice(self) -> &'static [&'static str] {
        match self {
            Self::FloorOnly => &[FLOOR],
            Self::FloorAndMl => &[FLOOR, ML],
            Self::FloorAndPartialMl => &[FLOOR, ML_PARTIAL],
        }
    }

    /// Comma-separated form for the `x-secureprompt-engines` response header
    /// and structured logs. A `&'static str` rather than a built `String` so
    /// it is self-evidently a bounded label, not free text.
    #[must_use]
    pub const fn as_header_value(self) -> &'static str {
        match self {
            Self::FloorOnly => "floor",
            Self::FloorAndMl => "floor,ml",
            Self::FloorAndPartialMl => "floor,ml_partial",
        }
    }

    /// Owned names, for the ClickHouse row.
    #[must_use]
    pub fn to_names(self) -> Vec<String> {
        self.as_slice().iter().map(|s| (*s).to_owned()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_sidecar::types::SidecarOutage;

    /// The mapping, including the case that distinguishes this field from
    /// `floor_only`: partial coverage is neither "ml" nor "floor alone".
    #[test]
    fn coverage_maps_to_distinct_engine_sets() {
        assert_eq!(
            DetectionEngines::from_coverage(&SidecarCoverage::Complete).as_slice(),
            &[FLOOR, ML]
        );
        assert_eq!(
            DetectionEngines::from_coverage(&SidecarCoverage::Absent(SidecarOutage::CircuitOpen))
                .as_slice(),
            &[FLOOR]
        );
        assert_eq!(
            DetectionEngines::from_coverage(&SidecarCoverage::Partial {
                chunks_covered: 3,
                chunks_total: 47,
            })
            .as_slice(),
            &[FLOOR, ML_PARTIAL]
        );
    }

    /// Every outage reason collapses to floor-only — the reason is carried by
    /// the `x-secureprompt-sidecar-degraded` header and the metric label, not
    /// by this field, which is about WHICH engines ran and not WHY one did
    /// not.
    #[test]
    fn every_outage_reason_is_floor_only() {
        for reason in [
            SidecarOutage::Unconfigured,
            SidecarOutage::Disabled,
            SidecarOutage::CircuitOpen,
            SidecarOutage::AllCallsFailed,
        ] {
            assert_eq!(
                DetectionEngines::from_coverage(&SidecarCoverage::Absent(reason)),
                DetectionEngines::FloorOnly,
                "{reason:?} must not claim the model ran"
            );
        }
        // POSITIVE CONTROL: the same function must NOT return FloorOnly for
        // complete coverage, or the loop above would hold for a constant.
        assert_ne!(
            DetectionEngines::from_coverage(&SidecarCoverage::Complete),
            DetectionEngines::FloorOnly
        );
    }

    /// The forgotten-call-site default must under-claim, never over-claim.
    #[test]
    fn the_default_does_not_claim_the_model_ran() {
        let names = DetectionEngines::default().to_names();
        assert_eq!(names, vec![FLOOR.to_owned()]);
        assert!(
            !names.iter().any(|n| n.starts_with(ML)),
            "a RequestEvent nobody called record_engines on must not assert \
             that an ML model scanned the prompt"
        );
        // PREMISE for that absence: the type CAN produce an `ml` name, so the
        // assertion above is about the default and not about `to_names`
        // being incapable of emitting one.
        assert!(DetectionEngines::FloorAndMl
            .to_names()
            .iter()
            .any(|n| n == ML));
    }

    /// The header value and the array must not be able to disagree — they are
    /// two hand-written matches over the same enum.
    #[test]
    fn header_value_matches_the_array() {
        for engines in [
            DetectionEngines::FloorOnly,
            DetectionEngines::FloorAndMl,
            DetectionEngines::FloorAndPartialMl,
        ] {
            assert_eq!(engines.as_header_value(), engines.as_slice().join(","));
        }
    }
}
