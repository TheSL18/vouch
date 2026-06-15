//! Build an AUR package the safe way: `makepkg` in two phases, the build
//! phase with the network unshared.
//!
//! The split is the whole point:
//!   * **Phase 1 — verify sources** (`makepkg --verifysource`): network is
//!     allowed so declared `source=()` files can be fetched, and their
//!     checksums are verified against the PKGBUILD. The filesystem is still
//!     confined to the build directory.
//!   * **Phase 2 — build & package** (`makepkg` with no network): extract,
//!     `prepare()`, `build()`, `check()`, `package()` all run with **no route
//!     off the machine**. A recipe that tries to `npm install` or `curl | bash`
//!     a payload here simply fails to reach anything — the exact countermeasure
//!     to the "Atomic Arch" attack.
//!
//! If a working sandbox cannot be established, this **refuses to build** rather
//! than degrade to an unsandboxed `makepkg`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use vouch_sandbox::Sandbox;

const MAKEPKG: &str = "/usr/bin/makepkg";

/// The artifacts produced by a successful build.
#[derive(Debug)]
pub struct BuildOutcome {
    /// Paths to the built `*.pkg.tar.*` files, inside the build directory.
    pub packages: Vec<PathBuf>,
}

/// Build the package whose recipe lives in `pkgdir`, enforcing the
/// network-denied build phase. `pkgdir` must contain a `PKGBUILD`.
pub fn build_in_sandbox(pkgdir: &Path) -> Result<BuildOutcome> {
    if !vouch_sandbox::available() {
        bail!(
            "secure build sandbox unavailable (bwrap missing or unprivileged user \
             namespaces disabled). Refusing to build unsandboxed."
        );
    }

    let pkgdir = pkgdir
        .canonicalize()
        .with_context(|| format!("package directory {}", pkgdir.display()))?;
    if !pkgdir.join("PKGBUILD").is_file() {
        bail!("no PKGBUILD found in {}", pkgdir.display());
    }

    // Phase 1: fetch + verify source integrity (network allowed, fs confined).
    let status = Sandbox::new(&pkgdir)
        .allow_network(true)
        .run(MAKEPKG, ["--verifysource", "--nodeps", "--noconfirm"])
        .context("source-verification phase")?;
    if !status.success() {
        bail!("source download / integrity verification failed");
    }

    // Phase 2: extract, prepare, build, package — NETWORK DENIED. `-f` so a
    // rebuild of an already-vouched package overwrites the stale artifact
    // instead of erroring out.
    let status = Sandbox::new(&pkgdir)
        .allow_network(false)
        .run(MAKEPKG, ["--noconfirm", "--nodeps", "-f"])
        .context("sandboxed build phase")?;
    if !status.success() {
        bail!("build failed inside the network-denied sandbox");
    }

    let packages = collect_packages(&pkgdir)?;
    if packages.is_empty() {
        bail!("build reported success but produced no package artifact");
    }
    Ok(BuildOutcome { packages })
}

fn collect_packages(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // matches foo-1-1-x86_64.pkg.tar.zst and .pkg.tar.xz etc.
            if name.contains(".pkg.tar.") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
