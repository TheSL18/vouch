//! Precise queries against the local pacman/ALPM databases via `libalpm`.
//!
//! `vouch-resolve` needs to answer two questions accurately:
//!   * *Can the official (and any configured) repositories satisfy this
//!     dependency?* — including provides, version constraints and sonames. If
//!     so, it's `pacman`'s job, not an AUR build target.
//!   * *Is this package already installed, and at what version?*
//!
//! These are exactly what `libalpm` answers, so we ask it directly rather than
//! shelling out or reimplementing dependency satisfaction. The configured
//! repositories (including third-party ones like `chaotic-aur` or `cachyos`)
//! are read from `pacman.conf` so classification matches the user's real
//! trust configuration.
//!
//! Opening the database is fallible (libalpm missing, permissions, an exotic
//! layout); callers should treat failure as "I can't tell" and fall back to a
//! safe default rather than crashing.

use anyhow::{Context, Result};

/// A handle onto the local pacman databases (sync repos + installed packages).
pub struct Db {
    handle: alpm::Alpm,
}

impl Db {
    /// Open ALPM using the paths and repositories from `pacman.conf`, falling
    /// back to the standard locations.
    pub fn open() -> Result<Self> {
        let root = pacman_conf("RootDir").unwrap_or_else(|| "/".to_string());
        let dbpath = pacman_conf("DBPath").unwrap_or_else(|| "/var/lib/pacman".to_string());
        let handle =
            alpm::Alpm::new(root.as_str(), dbpath.as_str()).context("initializing libalpm")?;
        for repo in repo_list() {
            // A repo we can't register (e.g. its .db isn't synced) just won't
            // contribute to satisfaction checks; that's fine.
            let _ = handle.register_syncdb(repo.as_str(), alpm::SigLevel::NONE);
        }
        Ok(Self { handle })
    }

    /// Whether any configured sync repository can satisfy `dep` (a dependency
    /// atom that may carry a version constraint or be a soname/provide).
    pub fn repo_satisfies(&self, dep: &str) -> bool {
        self.handle
            .syncdbs()
            .iter()
            .any(|db| db.pkgs().find_satisfier(dep).is_some())
    }

    /// The installed version of `name`, or `None` if it isn't installed.
    pub fn installed_version(&self, name: &str) -> Option<String> {
        self.handle
            .localdb()
            .pkg(name)
            .ok()
            .map(|p| p.version().to_string())
    }

    /// Installed packages that no configured repository provides — i.e. the
    /// "foreign" packages, which on a normal system are exactly the ones that
    /// came from the AUR. Returns `(name, installed_version)`.
    pub fn foreign_packages(&self) -> Vec<(String, String)> {
        self.handle
            .localdb()
            .pkgs()
            .iter()
            .filter_map(|p| {
                let name = p.name();
                let in_repo = self.handle.syncdbs().iter().any(|db| db.pkg(name).is_ok());
                (!in_repo).then(|| (name.to_string(), p.version().to_string()))
            })
            .collect()
    }
}

/// Whether `available` is a strictly newer version than `installed`, using
/// libalpm's own version-comparison rules (epochs, `pkgrel`, etc.).
pub fn newer(available: &str, installed: &str) -> bool {
    alpm::vercmp(installed, available) == std::cmp::Ordering::Less
}

/// Read a single scalar from `pacman-conf` (e.g. `DBPath`, `RootDir`).
fn pacman_conf(key: &str) -> Option<String> {
    let out = std::process::Command::new("pacman-conf")
        .arg(key)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The configured repositories, in order, as listed by `pacman-conf`.
fn repo_list() -> Vec<String> {
    std::process::Command::new("pacman-conf")
        .arg("--repo-list")
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
