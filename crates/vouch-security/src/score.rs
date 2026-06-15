//! Turn a pile of [`Finding`]s into a single [`Verdict`].
//!
//! The score is a capped sum of severity weights, but the *decision* is not a
//! pure threshold: a single `Critical` finding refuses the package outright,
//! because "lots of small risks" and "one rootkit" should not be averaged
//! together.

use std::collections::BTreeMap;

use vouch_core::{Decision, Finding, Severity, Verdict};

/// At or above this score, a package needs a human before proceeding.
const REVIEW_THRESHOLD: u32 = 25;
/// At or above this score, `vouch` refuses outright.
const REFUSE_THRESHOLD: u32 = 60;

pub fn build_verdict(package: &str, findings: Vec<Finding>) -> Verdict {
    // Score by *distinct rule*, taking each rule's highest severity. The same
    // rule firing many times in one recipe (e.g. a package that symlinks six
    // systemd timer units) is a single concern, not six — linear stacking would
    // wrongly push legitimate packages to REFUSED.
    let mut per_rule: BTreeMap<&str, Severity> = BTreeMap::new();
    for f in &findings {
        per_rule
            .entry(f.id.as_str())
            .and_modify(|s| *s = (*s).max(f.severity))
            .or_insert(f.severity);
    }
    let score: u32 = per_rule.values().map(|s| s.weight()).sum::<u32>().min(100);

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
