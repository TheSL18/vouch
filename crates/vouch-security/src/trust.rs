//! Trust signals derived from AUR metadata.
//!
//! "Atomic Arch" worked by adopting *orphaned* packages and pushing malicious
//! updates from brand-new maintainer accounts. None of these signals are proof
//! of malice on their own — they raise the bar for review.

use vouch_core::{Finding, PackageMeta, Severity};

/// Packages updated very recently get extra scrutiny: the attack pushed
/// malicious commits in waves, and a sudden update is the moment to look.
const RECENT_UPDATE_SECS: i64 = 7 * 24 * 3600;
/// Below this many votes a package is essentially unvetted by the community.
const LOW_VOTES: u64 = 10;

pub fn evaluate(meta: &PackageMeta) -> Vec<Finding> {
    let mut findings = Vec::new();

    // The single strongest signal from the incident.
    if meta.maintainer.is_none() {
        findings.push(Finding {
            id: "trust.orphaned".into(),
            severity: Severity::High,
            title: "Package is orphaned (no maintainer)".into(),
            detail: "Orphaned AUR packages can be adopted by anyone. This was the \
                     primary entry point of the June 2026 'Atomic Arch' attack. \
                     Treat any orphaned package as untrusted until reviewed."
                .into(),
            location: None,
        });
    }

    if meta.num_votes < LOW_VOTES {
        findings.push(Finding {
            id: "trust.low-votes".into(),
            severity: Severity::Low,
            title: format!("Low community trust ({} votes)", meta.num_votes),
            detail: "Few votes means little community review. Popular packages are \
                     more likely to have many eyes on changes."
                .into(),
            location: None,
        });
    }

    // We can't compute "now" without a clock; the CLI passes the current time
    // in via `evaluate_at`. The default path treats recency as unknown.
    findings
}

/// Same as [`evaluate`] but with an explicit "now" so recency can be judged.
/// `now` is a Unix timestamp in seconds.
pub fn evaluate_at(meta: &PackageMeta, now: i64) -> Vec<Finding> {
    let mut findings = evaluate(meta);

    let age_since_update = now - meta.last_modified;
    if age_since_update >= 0 && age_since_update <= RECENT_UPDATE_SECS {
        findings.push(Finding {
            id: "trust.recent-update".into(),
            severity: Severity::Low,
            title: "Updated within the last 7 days".into(),
            detail: "A very recent update is exactly when a hijacked package would \
                     push its payload. Review the diff against the version you last \
                     trusted."
                .into(),
            location: None,
        });
    }

    if meta.out_of_date.is_some() {
        findings.push(Finding {
            id: "trust.out-of-date".into(),
            severity: Severity::Info,
            title: "Flagged out-of-date".into(),
            detail: "An out-of-date flag can mean the maintainer is inactive — a \
                     precursor to orphaning and adoption."
                .into(),
            location: None,
        });
    }

    findings
}
