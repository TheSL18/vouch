//! Turn a pile of [`Finding`]s into a single [`Verdict`].
//!
//! The score is a capped sum of severity weights, but the *decision* is not a
//! pure threshold: a single `Critical` finding refuses the package outright,
//! because "lots of small risks" and "one rootkit" should not be averaged
//! together.

use vouch_core::{Decision, Finding, Severity, Verdict};

/// At or above this score, a package needs a human before proceeding.
const REVIEW_THRESHOLD: u32 = 25;
/// At or above this score, `vouch` refuses outright.
const REFUSE_THRESHOLD: u32 = 60;

pub fn build_verdict(package: &str, findings: Vec<Finding>) -> Verdict {
    let score: u32 = findings
        .iter()
        .map(|f| f.severity.weight())
        .sum::<u32>()
        .min(100);

    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);

    let decision = if has_critical || score >= REFUSE_THRESHOLD {
        Decision::Refused
    } else if score >= REVIEW_THRESHOLD {
        Decision::Review
    } else {
        Decision::Vouched
    };

    // Show the worst findings first.
    let mut findings = findings;
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    Verdict {
        package: package.to_string(),
        score,
        decision,
        findings,
    }
}
