//! Shared types for `vouch` — the security-first AUR helper.
//!
//! Everything here is dependency-light on purpose: the other crates
//! (`vouch-rpc`, `vouch-pkgbuild`, `vouch-security`, `vouch-cli`) all speak
//! these types so the security verdict is the single source of truth.

use serde::{Deserialize, Serialize};

/// Metadata about an AUR package as reported by the AUR RPC.
///
/// Field names mirror the RPC payload where useful, but are normalized to
/// snake_case Rust idioms. A `maintainer` of `None` means the package is
/// **orphaned** — a key signal in the "Atomic Arch" attack, where attackers
/// adopted abandoned packages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMeta {
    pub name: String,
    pub package_base: String,
    pub version: String,
    pub description: Option<String>,
    pub maintainer: Option<String>,
    pub num_votes: u64,
    pub popularity: f64,
    /// Unix timestamp the package was first submitted to the AUR.
    pub first_submitted: i64,
    /// Unix timestamp of the last update.
    pub last_modified: i64,
    /// `Some(ts)` if flagged out-of-date.
    pub out_of_date: Option<i64>,
    pub url: Option<String>,
    /// Runtime dependencies (may carry version constraints, e.g. `pacman>6.1`).
    #[serde(default)]
    pub depends: Vec<String>,
    /// Build-time dependencies.
    #[serde(default)]
    pub make_depends: Vec<String>,
    /// Test-time dependencies.
    #[serde(default)]
    pub check_depends: Vec<String>,
}

impl PackageMeta {
    /// Every dependency relevant to building this package (runtime + make +
    /// check), in declaration order. Names may still carry version constraints.
    pub fn build_deps(&self) -> impl Iterator<Item = &str> {
        self.depends
            .iter()
            .chain(&self.make_depends)
            .chain(&self.check_depends)
            .map(String::as_str)
    }
}

/// How severe a single finding is. Ordering matters: `Critical > High > ...`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Points this severity contributes to the risk score (0–100, capped).
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 3,
            Severity::Medium => 8,
            Severity::High => 20,
            Severity::Critical => 40,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// A single thing `vouch` noticed while vetting a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id, e.g. `scan.npm-install` or `trust.orphaned`.
    pub id: String,
    pub severity: Severity,
    /// One-line human summary.
    pub title: String,
    /// Longer explanation of why this matters / what to check.
    pub detail: String,
    /// Where it was seen, e.g. `PKGBUILD:42` or `foo.install`.
    pub location: Option<String>,
}

/// What `vouch` decided to do with a package after vetting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Clean enough to vouch for.
    Vouched,
    /// Needs a human to look before proceeding.
    Review,
    /// Refused — too risky to install as-is.
    Refused,
}

impl Decision {
    pub fn label(self) -> &'static str {
        match self {
            Decision::Vouched => "VOUCHED",
            Decision::Review => "REVIEW REQUIRED",
            Decision::Refused => "REFUSED",
        }
    }
}

/// The aggregate result of vetting one package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub package: String,
    /// 0 (clean) – 100 (max risk).
    pub score: u32,
    pub decision: Decision,
    pub findings: Vec<Finding>,
}

impl Verdict {
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
