//! Fetch the build recipe for an AUR package without executing anything.
//!
//! This is deliberately read-only: we pull the raw `PKGBUILD` and any
//! `*.install` hook files from the AUR's cgit `plain` view so the security
//! engine can statically inspect them *before* a single line ever runs. The
//! "Atomic Arch" payloads lived precisely in `PKGBUILD` functions and
//! `.install` hooks, so these are the files that matter most.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;

const CGIT_PLAIN: &str = "https://aur.archlinux.org/cgit/aur.git/plain";
const USER_AGENT: &str = concat!("vouch/", env!("CARGO_PKG_VERSION"));

/// One fetched file from the package repo.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// File name as it lives in the repo, e.g. `PKGBUILD` or `foo.install`.
    pub name: String,
    pub content: String,
}

/// Everything `vouch` fetched for a package, ready to be scanned.
#[derive(Debug, Clone)]
pub struct SourceBundle {
    pub package_base: String,
    pub pkgbuild: String,
    /// `.install` hook files referenced by the PKGBUILD (may be empty).
    pub install_files: Vec<SourceFile>,
}

impl SourceBundle {
    /// Iterate over every fetched file as `(name, content)`, PKGBUILD first.
    pub fn files(&self) -> impl Iterator<Item = (&str, &str)> {
        std::iter::once(("PKGBUILD", self.pkgbuild.as_str())).chain(
            self.install_files
                .iter()
                .map(|f| (f.name.as_str(), f.content.as_str())),
        )
    }
}

fn fetch_plain(package_base: &str, file: &str) -> Result<String> {
    // cgit `plain` view: .../plain/<file>?h=<package_base>
    let url = format!("{CGIT_PLAIN}/{file}?h={package_base}");
    let resp = ureq::get(&url)
        .set("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("fetching {file} for {package_base}"))?;
    resp.into_string()
        .with_context(|| format!("reading {file} body for {package_base}"))
}

/// Fetch the PKGBUILD (by package base) plus any `.install` hooks it declares.
pub fn fetch(package_base: &str) -> Result<SourceBundle> {
    let pkgbuild = fetch_plain(package_base, "PKGBUILD")?;
    let install_names = referenced_install_files(&pkgbuild, package_base);

    let mut install_files = Vec::new();
    for name in install_names {
        // A declared hook that 404s shouldn't abort the whole audit.
        if let Ok(content) = fetch_plain(package_base, &name) {
            install_files.push(SourceFile { name, content });
        }
    }

    Ok(SourceBundle {
        package_base: package_base.to_string(),
        pkgbuild,
        install_files,
    })
}

/// Load a package's recipe from a local directory (one containing a
/// `PKGBUILD`), reading the same files [`fetch`] would. Used both to audit a
/// local checkout and to re-audit a freshly cloned AUR repo — *what we are
/// about to build* — rather than trusting the earlier metadata fetch.
pub fn load_local(dir: &Path) -> Result<SourceBundle> {
    let pkgbuild_path = dir.join("PKGBUILD");
    let pkgbuild = fs::read_to_string(&pkgbuild_path)
        .with_context(|| format!("reading {}", pkgbuild_path.display()))?;

    let package_base = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("local")
        .to_string();

    let mut install_files = Vec::new();
    for name in referenced_install_files(&pkgbuild, &package_base) {
        let path = dir.join(&name);
        if let Ok(content) = fs::read_to_string(&path) {
            install_files.push(SourceFile { name, content });
        }
    }

    Ok(SourceBundle {
        package_base,
        pkgbuild,
        install_files,
    })
}

/// Clone an AUR package's git repository into `dest` (shallow). This fetches
/// the *complete* recipe — PKGBUILD plus any local patches/sources — which is
/// what a real build needs. Network only; nothing is executed.
pub fn clone(package_base: &str, dest: &Path) -> Result<()> {
    // AUR package names are validated by the AUR; still, refuse anything that
    // could escape the URL path.
    if package_base.is_empty()
        || package_base
            .contains(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+')))
    {
        bail!("invalid package base name: {package_base:?}");
    }
    let url = format!("https://aur.archlinux.org/{package_base}.git");
    let status = Command::new("git")
        .args(["clone", "--depth", "1", "--quiet", &url])
        .arg(dest)
        .status()
        .context("running git clone")?;
    if !status.success() {
        bail!("git clone of {url} failed");
    }
    Ok(())
}

/// Pull `install=` declarations out of a PKGBUILD and resolve simple
/// `$pkgname` / `$pkgbase` substitutions to candidate file names.
fn referenced_install_files(pkgbuild: &str, package_base: &str) -> Vec<String> {
    // Matches: install=foo.install | install='foo.install' | install="..."
    // (regex crate has no backreferences, so quotes are stripped afterwards.)
    let re = Regex::new(r#"(?m)^\s*install=["']?([^"'\s]+)"#).expect("static regex");
    let mut names = Vec::new();
    for cap in re.captures_iter(pkgbuild) {
        let raw = &cap[1];
        let resolved = raw
            .replace("${pkgbase}", package_base)
            .replace("$pkgbase", package_base)
            .replace("${pkgname}", package_base)
            .replace("$pkgname", package_base);
        if !names.contains(&resolved) {
            names.push(resolved);
        }
    }
    names
}
