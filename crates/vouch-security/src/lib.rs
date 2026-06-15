//! The reason `vouch` exists: the engine that decides whether a package can
//! be vouched for.
//!
//! It combines two independent signal sources —
//!   * [`trust`]: who maintains the package and how the community treats it
//!     (orphaned? freshly adopted? unpopular? out of date?), and
//!   * [`scan`]: static inspection of the PKGBUILD and `.install` hooks for
//!     the dangerous patterns seen in supply-chain attacks like "Atomic Arch"
//!     (downloading and running code at build/install time, eBPF rootkits,
//!     persistence, obfuscation).
//!
//! and turns the resulting [`Finding`]s into a single [`Verdict`].

pub mod scan;
pub mod score;
pub mod trust;

use vouch_core::{PackageMeta, Verdict};
use vouch_pkgbuild::SourceBundle;

/// Vet a package end-to-end: gather trust + static findings, then score them.
///
/// `now` is the current Unix timestamp (seconds), used to judge how recently
/// the package was updated. Pass it in rather than reading the clock here so
/// the engine stays pure and testable.
pub fn evaluate(meta: &PackageMeta, bundle: &SourceBundle, now: i64) -> Verdict {
    let mut findings = trust::evaluate_at(meta, now);
    findings.extend(scan::evaluate(bundle));
    score::build_verdict(&meta.name, findings)
}
