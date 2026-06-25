//! Pure offline-staleness overlay. No I/O, no external license types — operates
//! on epoch-second integers so it is fully unit-testable without the sp-license
//! crate update. See spec §4.4.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineVerdict { Fresh, SoftStale, HardStale }

/// Classify how stale a license is given its last authenticated check-in.
///
/// * `now`               – current system clock (epoch secs)
/// * `highwater`         – max perceived time ever observed (epoch secs)
/// * `last_assertion_at` – issued_at of the newest VERIFIED freshness assertion (0 if none)
/// * `not_before`        – the signed license's not_before (epoch secs), the bootstrap anchor
/// * `soft` / `hard`     – the token's budgets in secs; `None` ⇒ no policy ⇒ always `Fresh`
pub fn classify_offline(
    now: i64,
    highwater: i64,
    last_assertion_at: i64,
    not_before: i64,
    soft: Option<i64>,
    hard: Option<i64>,
) -> OfflineVerdict {
    let (soft, hard) = match (soft, hard) {
        (Some(s), Some(h)) => (s, h),
        _ => return OfflineVerdict::Fresh, // no policy → never stale
    };
    // Issuance enforces hard >= soft; assert in dev so a malformed token surfaces
    // (an inverted window would let `> hard` shadow the recoverable soft band).
    debug_assert!(hard >= soft, "revalidate_hard_secs ({hard}) must be >= soft ({soft})");
    // Perceived time cannot move backwards (defeats clock rollback).
    let perceived_now = now.max(highwater);
    // Last good check is the newest of (verified assertion, signed not_before anchor).
    let last_good = last_assertion_at.max(not_before);
    let offline = (perceived_now - last_good).max(0);
    if offline > hard {
        OfflineVerdict::HardStale
    } else if offline > soft {
        OfflineVerdict::SoftStale
    } else {
        OfflineVerdict::Fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Anchors: issued 1000, not_before 1000. soft=100, hard=300.
    fn c(now: i64, hw: i64, last: i64) -> OfflineVerdict {
        classify_offline(now, hw, last, 1000, Some(100), Some(300))
    }
    #[test] fn no_policy_is_always_fresh() {
        assert_eq!(classify_offline(99_999, 0, 0, 1000, None, None), OfflineVerdict::Fresh);
    }
    #[test] fn within_soft_is_fresh() { assert_eq!(c(1080, 1080, 1000), OfflineVerdict::Fresh); }
    #[test] fn past_soft_is_soft_stale() { assert_eq!(c(1200, 1200, 1000), OfflineVerdict::SoftStale); }
    #[test] fn past_hard_is_hard_stale() { assert_eq!(c(1400, 1400, 1000), OfflineVerdict::HardStale); }
    #[test] fn clock_rollback_uses_highwater() {
        // system clock rolled back to 1010, but highwater saw 1400 → still HardStale.
        assert_eq!(c(1010, 1400, 1000), OfflineVerdict::HardStale);
    }
    #[test] fn fresh_install_seeds_from_not_before() {
        // never checked in (last=0); now just past not_before, within soft.
        assert_eq!(classify_offline(1050, 1050, 0, 1000, Some(100), Some(300)), OfflineVerdict::Fresh);
    }
    #[test] fn newer_assertion_resets_offline() {
        // last assertion at 1350, now 1400 → offline 50 → Fresh despite old not_before.
        assert_eq!(c(1400, 1400, 1350), OfflineVerdict::Fresh);
    }
    #[test] fn one_sided_budget_is_fresh() {
        // Only one budget set ⇒ no enforceable policy ⇒ always Fresh, even when very stale.
        assert_eq!(classify_offline(99_999, 99_999, 0, 1000, Some(100), None), OfflineVerdict::Fresh);
        assert_eq!(classify_offline(99_999, 99_999, 0, 1000, None, Some(300)), OfflineVerdict::Fresh);
    }
}
