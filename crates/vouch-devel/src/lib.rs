//! Development (VCS) package tracking — a "devel database" à la paru.
//!
//! VCS packages (`-git`, `-svn`, …, but also any package whose `source=()`
//! points at a moving upstream branch) keep the *same* `pkgver` until they are
//! rebuilt. So you cannot tell "is there a newer commit?" from the AUR version
//! alone — and worse, plenty of such packages don't even carry a `-git` suffix
//! or embed a commit in their version (e.g. `session-desktop 1.18.0-1` builds
//! from a git branch). Name- or version-based heuristics miss those entirely.
//!
//! This crate records, per package, the exact upstream commit each of its VCS
//! sources was at **when vouch built it**. On a later upgrade check we re-query
//! the upstream HEAD (`git ls-remote`) and compare: if any source advanced, the
//! package is a rebuild candidate. Because tracking is keyed on the recipe's
//! *sources* rather than its name, it catches release-versioned devel packages
//! the moment vouch has built them once.
//!
//! State lives in a single JSON file at `$XDG_DATA_HOME/vouch/devel.json`
//! (falling back to `~/.local/share/vouch/devel.json`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Which upstream reference a VCS source tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    /// No fragment — follow the default branch (`HEAD`).
    Head,
    /// `#branch=<name>` — follow a named branch.
    Branch(String),
    /// `#commit=…` / `#tag=…` / `#revision=…` — pinned, never a devel upgrade.
    Pinned,
}

/// One VCS source parsed out of a PKGBUILD `source=()` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcsSource {
    /// VCS kind: `git`, `svn`, `hg`, `bzr`.
    pub vcs: String,
    /// The bare clone URL (fragment stripped), e.g. `https://github.com/x/y.git`.
    pub url: String,
    /// The reference the source follows.
    pub reference: Reference,
}

const PROTOS: &[&str] = &["git+", "svn+", "hg+", "bzr+"];

/// Parse every VCS source declared in a PKGBUILD. Best-effort and text-based:
/// we don't execute the recipe, just scan for `vcs+<url>[#fragment]` tokens
/// (the form makepkg uses), which is exactly what lives in `source=()`.
pub fn parse_vcs_sources(pkgbuild: &str) -> Vec<VcsSource> {
    let mut out = Vec::new();
    for proto in PROTOS {
        let vcs = &proto[..proto.len() - 1]; // "git+" -> "git"
        let mut from = 0;
        while let Some(rel) = pkgbuild[from..].find(proto) {
            let start = from + rel + proto.len();
            let after = &pkgbuild[start..];
            let end = after
                .find(|c: char| c == '\'' || c == '"' || c == ')' || c == '\n' || c.is_whitespace())
                .unwrap_or(after.len());
            from = start + end;
            let token = &after[..end];
            if token.is_empty() {
                continue;
            }
            let (url, frag) = match token.split_once('#') {
                Some((u, f)) => (u, Some(f)),
                None => (token, None),
            };
            if url.is_empty() {
                continue;
            }
            let reference = match frag {
                None | Some("") => Reference::Head,
                Some(f) => match f.split('&').find_map(|p| p.strip_prefix("branch=")) {
                    Some(b) if !b.is_empty() => Reference::Branch(b.to_string()),
                    _ => Reference::Pinned, // commit=/tag=/revision=… : fixed point
                },
            };
            out.push(VcsSource {
                vcs: vcs.to_string(),
                url: url.to_string(),
                reference,
            });
        }
    }
    out
}

/// Whether a PKGBUILD declares any VCS source at all (worth tracking).
pub fn has_vcs_sources(pkgbuild: &str) -> bool {
    !parse_vcs_sources(pkgbuild).is_empty()
}

/// Resolve the *current* upstream commit of every resolvable git source in a
/// PKGBUILD, as a `url -> commit` map. Pinned sources and non-git VCS (which
/// `git ls-remote` can't query) are skipped; an unreachable source is omitted
/// rather than guessed. An empty map means "nothing we can compare".
pub fn resolve_current(pkgbuild: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for src in parse_vcs_sources(pkgbuild) {
        if src.vcs != "git" {
            continue; // only git is queryable via ls-remote
        }
        let refname = match &src.reference {
            Reference::Head => "HEAD",
            Reference::Branch(b) => b.as_str(),
            Reference::Pinned => continue,
        };
        if let Some(commit) = ls_remote(&src.url, refname) {
            map.insert(src.url, commit);
        }
    }
    map
}

/// `git ls-remote <url> <ref>` → the commit hash of the first matching ref
/// (lowercase), or `None` if unreachable / no such ref.
pub fn ls_remote(url: &str, refname: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["ls-remote", url, refname])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .map(|h| h.to_ascii_lowercase())
}

/// What vouch recorded for one package the last time it built it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevelEntry {
    /// Unix timestamp the package was last built/recorded.
    pub recorded_at: i64,
    /// `url -> commit` for each VCS source, as built.
    pub sources: BTreeMap<String, String>,
}

/// The on-disk devel database (a single JSON file).
#[derive(Debug, Clone, Default)]
pub struct DevelDb {
    path: PathBuf,
    map: BTreeMap<String, DevelEntry>,
}

impl DevelDb {
    /// Open (or start empty) the default per-user devel database under
    /// `$XDG_DATA_HOME/vouch/devel.json`.
    pub fn open_default() -> Result<Self> {
        Self::open(default_path()?)
    }

    /// Open a devel database rooted at an explicit file (used in tests).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let map = match fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data)
                .with_context(|| format!("parsing devel database {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path, map })
    }

    /// The recorded entry for `package`, if any.
    pub fn get(&self, package: &str) -> Option<&DevelEntry> {
        self.map.get(package)
    }

    /// Whether `package` is tracked as a devel package.
    pub fn is_tracked(&self, package: &str) -> bool {
        self.map.contains_key(package)
    }

    /// Every tracked package name.
    pub fn tracked_packages(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }

    /// Record (or replace) the commits `package` was just built against, and
    /// persist. A package with no resolvable sources is dropped from tracking
    /// rather than stored empty.
    pub fn record(
        &mut self,
        package: &str,
        sources: BTreeMap<String, String>,
        now: i64,
    ) -> Result<()> {
        if sources.is_empty() {
            self.map.remove(package);
        } else {
            self.map.insert(
                package.to_string(),
                DevelEntry {
                    recorded_at: now,
                    sources,
                },
            );
        }
        self.persist()
    }

    /// Drop tracking for `package`. Returns whether it was tracked.
    pub fn forget(&mut self, package: &str) -> Result<bool> {
        let existed = self.map.remove(package).is_some();
        if existed {
            self.persist()?;
        }
        Ok(existed)
    }

    fn persist(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)
                .with_context(|| format!("creating data directory {}", dir.display()))?;
            restrict_dir(dir);
        }
        let json = serde_json::to_string_pretty(&self.map).context("serializing devel database")?;
        write_private(&self.path, &json)
            .with_context(|| format!("writing devel database {}", self.path.display()))
    }
}

/// Given a tracked entry and the freshly-resolved current commits, decide
/// whether upstream advanced: any source whose commit changed (or a source not
/// previously seen) counts as a new commit. An empty `current` (nothing
/// resolvable right now) is treated as "no change" — we never invent an upgrade
/// we can't substantiate.
pub fn entry_has_new_commits(entry: &DevelEntry, current: &BTreeMap<String, String>) -> bool {
    current
        .iter()
        .any(|(url, commit)| entry.sources.get(url).is_none_or(|seen| seen != commit))
}

fn default_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .context("cannot locate a data directory (set HOME or XDG_DATA_HOME)")?;
    Ok(base.join("vouch").join("devel.json"))
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

    #[test]
    fn parses_plain_git_head_source() {
        let pkgbuild = "source=('myapp::git+https://github.com/foo/bar.git')\n";
        let s = parse_vcs_sources(pkgbuild);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].vcs, "git");
        assert_eq!(s[0].url, "https://github.com/foo/bar.git");
        assert_eq!(s[0].reference, Reference::Head);
    }

    #[test]
    fn parses_branch_and_pins() {
        let branch = parse_vcs_sources("source=(git+https://x/y.git#branch=dev)");
        assert_eq!(branch[0].reference, Reference::Branch("dev".into()));

        for frag in ["#commit=abcdef", "#tag=v1.2.3", "#revision=42"] {
            let s = parse_vcs_sources(&format!("source=(git+https://x/y.git{frag})"));
            assert_eq!(s[0].reference, Reference::Pinned, "fragment {frag}");
            assert_eq!(s[0].url, "https://x/y.git");
        }
    }

    #[test]
    fn parses_multiple_mixed_sources() {
        let pkgbuild = "\
source=('LICENSE'
        'app::git+https://github.com/a/b.git#branch=main'
        'lib::git+https://gitlab.com/c/d.git')\n";
        let s = parse_vcs_sources(pkgbuild);
        assert_eq!(s.len(), 2);
        assert!(has_vcs_sources(pkgbuild));
        assert!(!has_vcs_sources("source=('only-a-tarball-1.0.tar.gz')"));
    }

    #[test]
    fn new_commit_detection() {
        let entry = DevelEntry {
            recorded_at: 0,
            sources: BTreeMap::from([("https://x/y.git".to_string(), "aaaa".to_string())]),
        };
        // same commit -> no change
        let same = BTreeMap::from([("https://x/y.git".to_string(), "aaaa".to_string())]);
        assert!(!entry_has_new_commits(&entry, &same));
        // advanced commit -> change
        let moved = BTreeMap::from([("https://x/y.git".to_string(), "bbbb".to_string())]);
        assert!(entry_has_new_commits(&entry, &moved));
        // a brand-new source -> change
        let added = BTreeMap::from([("https://x/z.git".to_string(), "cccc".to_string())]);
        assert!(entry_has_new_commits(&entry, &added));
        // nothing resolvable right now -> no invented upgrade
        assert!(!entry_has_new_commits(&entry, &BTreeMap::new()));
    }

    #[test]
    fn record_load_forget_roundtrip() {
        let dir = std::env::temp_dir().join(format!("vouch-devel-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("devel.json");

        let mut db = DevelDb::open(&path).unwrap();
        let sources = BTreeMap::from([("https://x/y.git".to_string(), "deadbeef".to_string())]);
        db.record("session-desktop", sources, 123).unwrap();

        let db2 = DevelDb::open(&path).unwrap();
        assert!(db2.is_tracked("session-desktop"));
        assert_eq!(
            db2.get("session-desktop").unwrap().sources["https://x/y.git"],
            "deadbeef"
        );

        let mut db3 = DevelDb::open(&path).unwrap();
        assert!(db3.forget("session-desktop").unwrap());
        assert!(!db3.forget("session-desktop").unwrap());

        let _ = fs::remove_dir_all(&dir);
    }
}
