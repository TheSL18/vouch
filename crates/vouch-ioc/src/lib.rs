//! Indicators of compromise (IoC) — known-bad threat intelligence.
//!
//! The static scanner reasons about *behavior* ("this runs `npm install`").
//! This crate reasons about *identity*: it matches a recipe against a list of
//! things already known to be malicious — the npm payload names from the
//! "Atomic Arch" campaign (`atomic-lockfile`, `js-digest`, `lockfile-js`),
//! plus any banned maintainer accounts, hijacked package names, malicious
//! domains, or file hashes the community has published.
//!
//! Any IoC match is treated as `Critical`: if a recipe references a known
//! payload, there is nothing to debate.
//!
//! Indicators come from two places, merged:
//!   * a small **built-in** baseline (the documented Atomic Arch payload names),
//!   * an optional user feed at `$XDG_DATA_HOME/vouch/ioc.json`, which can be
//!     populated from community lists such as `aur-malware-check`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vouch_core::{Finding, Severity};

/// A set of known-bad indicators.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Indicators {
    /// Hijacked / known-malicious AUR package (or base) names.
    #[serde(default)]
    pub bad_package_names: BTreeSet<String>,
    /// Banned attacker maintainer accounts.
    #[serde(default)]
    pub bad_maintainers: BTreeSet<String>,
    /// Substrings that should never appear in a recipe (payload package names,
    /// C2 domains, etc.). Matched case-insensitively.
    #[serde(default)]
    pub bad_strings: BTreeSet<String>,
    /// SHA-256 (hex) of known-malicious files.
    #[serde(default)]
    pub bad_sha256: BTreeSet<String>,
}

impl Indicators {
    /// The compiled-in baseline. Conservative on purpose: it carries the
    /// concrete npm payload package names documented in the June 2026
    /// "Atomic Arch" AUR supply-chain attack. Account names and hashes are left
    /// to the user feed, which can track the community IoC lists.
    pub fn builtin() -> Self {
        let bad_strings = ["atomic-lockfile", "js-digest", "lockfile-js"]
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        Indicators {
            bad_package_names: BTreeSet::new(),
            bad_maintainers: BTreeSet::new(),
            bad_strings,
            bad_sha256: BTreeSet::new(),
        }
    }

    /// Built-in baseline merged with the user feed (if present). Never fails:
    /// a missing or malformed feed falls back to the baseline.
    pub fn load_default() -> Self {
        let mut ind = Self::builtin();
        if let Some(path) = user_feed_path()
            && let Ok(extra) = Self::load_file(&path)
        {
            ind.merge(extra);
        }
        ind
    }

    /// Load indicators from a JSON file.
    pub fn load_file(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("reading IoC feed {}", path.display()))?;
        serde_json::from_str(&data).with_context(|| format!("parsing IoC feed {}", path.display()))
    }

    /// Fold another indicator set into this one.
    pub fn merge(&mut self, other: Indicators) {
        self.bad_package_names.extend(other.bad_package_names);
        self.bad_maintainers.extend(other.bad_maintainers);
        self.bad_strings.extend(other.bad_strings);
        self.bad_sha256.extend(other.bad_sha256);
    }

    pub fn total(&self) -> usize {
        self.bad_package_names.len()
            + self.bad_maintainers.len()
            + self.bad_strings.len()
            + self.bad_sha256.len()
    }

    /// Check package identity (name + maintainer) against the indicators.
    pub fn check_meta(&self, name: &str, maintainer: Option<&str>) -> Vec<Finding> {
        let mut findings = Vec::new();
        if self.bad_package_names.contains(name) {
            findings.push(critical(
                "ioc.bad-package",
                format!("Package '{name}' is on a known-malicious list"),
                "This exact package name matches a known supply-chain compromise. \
                 Do not install it.",
                None,
            ));
        }
        if let Some(m) = maintainer
            && self.bad_maintainers.contains(m)
        {
            findings.push(critical(
                "ioc.bad-maintainer",
                format!("Maintainer '{m}' is a known-bad account"),
                "This account is flagged as having published malicious packages.",
                None,
            ));
        }
        findings
    }

    /// Scan recipe file contents for known-bad strings and file hashes.
    pub fn scan_content<'a>(
        &self,
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let needles: Vec<String> = self.bad_strings.iter().map(|s| s.to_lowercase()).collect();

        for (name, content) in files {
            let haystack = content.to_lowercase();
            for needle in &needles {
                if haystack.contains(needle) {
                    findings.push(critical(
                        "ioc.bad-string",
                        format!("Recipe references known IoC '{needle}'"),
                        "This string matches a known-malicious payload/indicator \
                         (e.g. an 'Atomic Arch' npm package). The recipe is compromised.",
                        Some(name.to_string()),
                    ));
                }
            }
            if !self.bad_sha256.is_empty() {
                let digest = sha256_hex(content.as_bytes());
                if self.bad_sha256.contains(&digest) {
                    findings.push(critical(
                        "ioc.bad-hash",
                        format!("File '{name}' matches a known-malicious hash"),
                        "The exact contents of this file are on a known-bad hash list.",
                        Some(name.to_string()),
                    ));
                }
            }
        }
        findings
    }
}

/// Default user feed location: `$XDG_DATA_HOME/vouch/ioc.json`
/// (falling back to `~/.local/share/vouch/ioc.json`).
pub fn user_feed_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    Some(base.join("vouch").join("ioc.json"))
}

/// Merge a feed file into the user's stored indicators, creating it if needed.
pub fn import_feed(path: &Path) -> Result<usize> {
    let incoming = Indicators::load_file(path)?;
    let dest = user_feed_path().context("cannot locate a data directory for the IoC feed")?;
    let mut current = Indicators::load_file(&dest).unwrap_or_default();
    current.merge(incoming);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&current).context("serializing IoC feed")?;
    fs::write(&dest, json).with_context(|| format!("writing {}", dest.display()))?;
    Ok(current.total())
}

fn critical(id: &str, title: String, detail: &str, location: Option<String>) -> Finding {
    Finding {
        id: id.to_string(),
        severity: Severity::Critical,
        title,
        detail: detail.to_string(),
        location,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_flags_atomic_arch_payload() {
        let ind = Indicators::builtin();
        let findings = ind.scan_content([(
            "PKGBUILD",
            "source=('https://r.example/atomic-lockfile.tgz')\nbuild() { :; }\n",
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "ioc.bad-string");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn clean_content_is_clean() {
        let ind = Indicators::builtin();
        assert!(
            ind.scan_content([("PKGBUILD", "pkgname=foo\nbuild() { make; }\n")])
                .is_empty()
        );
    }

    #[test]
    fn matches_bad_maintainer_and_package() {
        let mut ind = Indicators::default();
        ind.bad_maintainers.insert("evil-acct".into());
        ind.bad_package_names.insert("totally-legit".into());
        assert_eq!(ind.check_meta("totally-legit", Some("someone")).len(), 1);
        assert_eq!(ind.check_meta("ok", Some("evil-acct")).len(), 1);
        assert!(ind.check_meta("ok", Some("good")).is_empty());
    }

    #[test]
    fn matches_known_hash() {
        let content = "malware\n";
        let mut ind = Indicators::default();
        ind.bad_sha256.insert(sha256_hex(content.as_bytes()));
        let findings = ind.scan_content([("evil.install", content)]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "ioc.bad-hash");
    }

    #[test]
    fn merge_combines_sets() {
        let mut a = Indicators::builtin();
        let n0 = a.total();
        let mut b = Indicators::default();
        b.bad_strings.insert("new-bad-thing".into());
        a.merge(b);
        assert_eq!(a.total(), n0 + 1);
    }
}
