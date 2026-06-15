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

/// Build the package whose recipe lives in `pkgdir`. `pkgdir` must contain a
/// `PKGBUILD`.
///
/// `allow_build_network` controls the build phase only: when `false` (the
/// secure default) `prepare()`/`build()`/`package()` run with **no network**.
/// When `true` — an explicit, per-package opt-in for recipes that genuinely
/// fetch at build time (electron/npm/cargo/go) — the build phase keeps network
/// access. The package is still fully vetted; only the runtime isolation is
/// relaxed, by deliberate choice.
pub fn build_in_sandbox(pkgdir: &Path, allow_build_network: bool) -> Result<BuildOutcome> {
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

    // Phase 2: extract, prepare, build, package. Network denied by default;
    // allowed only by explicit per-package opt-in. `-f` overwrites a stale
    // artifact. We do *not* pass `--nodeps`: makepkg verifies declared
    // dependencies against the (read-only) local pacman db, so a build with a
    // missing dependency fails fast with a clear message instead of a cryptic
    // compile error. `vouch install` pre-installs the repo dependencies so the
    // check passes; it never lets makepkg fetch/install anything itself
    // (no `-s`), keeping the build offline.
    let status = Sandbox::new(&pkgdir)
        .allow_network(allow_build_network)
        .run(MAKEPKG, ["--noconfirm", "-f"])
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

/// Like [`build_in_sandbox`], but captures the build's combined output and
/// returns it alongside the outcome instead of streaming it live. Intended for
/// parallel builds, where interleaved live output from several `makepkg`
/// processes would be unreadable. On failure the captured log is included in
/// the error.
pub fn build_in_sandbox_captured(
    pkgdir: &Path,
    allow_build_network: bool,
) -> Result<(BuildOutcome, String)> {
    if !vouch_sandbox::available() {
        bail!(
            "secure build sandbox unavailable (bwrap missing or unprivileged user \
             namespaces disabled). Refusing to build."
        );
    }
    let pkgdir = pkgdir
        .canonicalize()
        .with_context(|| format!("package directory {}", pkgdir.display()))?;
    if !pkgdir.join("PKGBUILD").is_file() {
        bail!("no PKGBUILD found in {}", pkgdir.display());
    }

    let mut log = String::new();
    let mut record = |out: &std::process::Output| {
        log.push_str(&String::from_utf8_lossy(&out.stdout));
        log.push_str(&String::from_utf8_lossy(&out.stderr));
    };

    let verify = Sandbox::new(&pkgdir)
        .allow_network(true)
        .output(MAKEPKG, ["--verifysource", "--nodeps", "--noconfirm"])
        .context("source-verification phase")?;
    record(&verify);
    if !verify.status.success() {
        bail!("source download / integrity verification failed:\n{log}");
    }

    let build = Sandbox::new(&pkgdir)
        .allow_network(allow_build_network)
        .output(MAKEPKG, ["--noconfirm", "-f"])
        .context("sandboxed build phase")?;
    record(&build);
    if !build.status.success() {
        bail!("build failed inside the sandbox:\n{log}");
    }

    let packages = collect_packages(&pkgdir)?;
    if packages.is_empty() {
        bail!("build reported success but produced no package artifact");
    }
    Ok((BuildOutcome { packages }, log))
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
