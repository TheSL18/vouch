//! Dependency resolution for the AUR layer.
//!
//! Given one or more target packages, walk their dependency graph and split it
//! into two parts:
//!   * **repo dependencies** — anything the official repositories can provide
//!     (including version constraints, virtual packages and sonames). `pacman`
//!     resolves and installs these; `vouch` does not build them.
//!   * **AUR build targets** — packages that exist *only* in the AUR and must
//!     be built. These form a graph that is topologically ordered so each is
//!     built after its own AUR dependencies.
//!
//! Why this matters for security: a package's dependencies are an attack
//! surface too. The "Atomic Arch" payloads could just as easily have ridden in
//! on a transitive AUR dependency. By enumerating the *entire* AUR build set,
//! `vouch` can vet every package the install will execute — not just the one
//! you typed.
//!
//! Classification rule: a dependency is an AUR build target iff it exists as an
//! AUR package **and** no configured repository can satisfy it. The repository
//! side is answered precisely by `libalpm` (via [`vouch_alpm`]), so provides,
//! version constraints, sonames and third-party repos (`chaotic-aur`,
//! `cachyos`, …) are all handled — a package available as a signed binary is
//! preferred over rebuilding it from the AUR.
//!
//! If ALPM can't be opened, we fall back to "AUR is authoritative" (a dep that
//! exists in the AUR is built), which is safe — we'd rather vet+sandbox-build
//! than silently trust.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::Command;

use anyhow::{Context, Result, bail};
use vouch_core::PackageMeta;

/// The outcome of resolving one or more targets.
#[derive(Debug, Clone)]
pub struct ResolvedPlan {
    /// The user-requested AUR packages (canonical names).
    pub explicit_targets: Vec<String>,
    /// AUR packages to build, in dependency order (each after its AUR deps).
    pub aur_build_order: Vec<String>,
    /// The build order grouped into dependency layers: every package in a layer
    /// depends only on earlier layers, so a whole layer can be built in
    /// parallel. `aur_build_order` is `layers` flattened.
    pub layers: Vec<Vec<String>>,
    /// Repo/system dependencies (concrete provider package names).
    pub repo_deps: Vec<String>,
    /// Repo dependencies needed *only* to build (make/check deps that are not
    /// also runtime deps). Candidates for removal after install (`--rmdeps`).
    pub make_only_deps: Vec<String>,
}

/// Resolve a single target. See [`resolve_many`].
pub fn resolve(target: &str) -> Result<ResolvedPlan> {
    resolve_many(&[target])
}

/// Resolve several targets into one combined plan (shared dependencies are
/// built once).
pub fn resolve_many(targets: &[&str]) -> Result<ResolvedPlan> {
    let mut aur_nodes: BTreeSet<String> = BTreeSet::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Repo providers split by how they're needed, so we can tell build-only
    // dependencies (make/check) apart from runtime ones for `--rmdeps`.
    let mut repo_runtime: BTreeSet<String> = BTreeSet::new();
    let mut repo_build: BTreeSet<String> = BTreeSet::new();
    let mut metas: BTreeMap<String, PackageMeta> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut explicit_targets: Vec<String> = Vec::new();

    // Best-effort: if libalpm can't be opened we fall back to AUR-authoritative
    // classification (a dep that exists in the AUR is built).
    let alpm = vouch_alpm::Db::open().ok();

    for &t in targets {
        let meta = vouch_rpc::info(t)
            .context("looking up target on the AUR")?
            .with_context(|| format!("'{t}' is not in the AUR"))?;
        let name = meta.name.clone();
        metas.entry(name.clone()).or_insert(meta);
        if aur_nodes.insert(name.clone()) {
            queue.push_back(name.clone());
        }
        if !explicit_targets.contains(&name) {
            explicit_targets.push(name);
        }
    }

    while let Some(pkg) = queue.pop_front() {
        let meta = metas
            .get(&pkg)
            .expect("queued packages always have cached metadata")
            .clone();

        // Runtime deps and build-time deps are classified the same way, but
        // tracked separately so we know which repo packages are *only* needed
        // to build (make/check, minus anything also needed at runtime).
        let runtime_atoms: Vec<&str> = meta.depends.iter().map(String::as_str).collect();
        let build_atoms: Vec<&str> = meta
            .make_depends
            .iter()
            .chain(&meta.check_depends)
            .map(String::as_str)
            .collect();

        // One RPC call to learn which dep names exist in the AUR.
        let bare_names: BTreeSet<String> = runtime_atoms
            .iter()
            .chain(&build_atoms)
            .map(|d| strip_version(d).to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let dep_refs: Vec<&str> = bare_names.iter().map(String::as_str).collect();
        let in_aur = vouch_rpc::info_many(&dep_refs).context("classifying dependencies")?;
        let aur_names: BTreeSet<String> = in_aur.iter().map(|m| m.name.clone()).collect();
        for m in in_aur {
            metas.entry(m.name.clone()).or_insert(m);
        }

        // Process runtime deps first so a dep listed as both runtime and make
        // counts as runtime (and is never treated as build-only).
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for &raw in &runtime_atoms {
            classify_dep(
                raw,
                &aur_names,
                alpm.as_ref(),
                &mut seen,
                &pkg,
                &mut edges,
                &mut aur_nodes,
                &mut queue,
                &mut repo_runtime,
            );
        }
        for &raw in &build_atoms {
            classify_dep(
                raw,
                &aur_names,
                alpm.as_ref(),
                &mut seen,
                &pkg,
                &mut edges,
                &mut aur_nodes,
                &mut queue,
                &mut repo_build,
            );
        }
    }

    let aur_build_order = topo_order(&aur_nodes, &edges)?;
    let layers = build_layers(&aur_nodes, &edges);
    // Build-only deps: needed to build, never at runtime.
    let make_only_deps: Vec<String> = repo_build.difference(&repo_runtime).cloned().collect();
    let repo_deps: Vec<String> = repo_runtime.union(&repo_build).cloned().collect();
    Ok(ResolvedPlan {
        explicit_targets,
        aur_build_order,
        layers,
        repo_deps,
        make_only_deps,
    })
}

/// Classify one dependency atom: an AUR build target (recorded as a graph edge
/// and queued) if the AUR has it and no repo satisfies it; otherwise a repo
/// provider recorded into `repo_set`. `seen` dedups within the current package.
#[allow(clippy::too_many_arguments)]
fn classify_dep(
    raw: &str,
    aur_names: &BTreeSet<String>,
    alpm: Option<&vouch_alpm::Db>,
    seen: &mut BTreeSet<String>,
    pkg: &str,
    edges: &mut BTreeMap<String, BTreeSet<String>>,
    aur_nodes: &mut BTreeSet<String>,
    queue: &mut VecDeque<String>,
    repo_set: &mut BTreeSet<String>,
) {
    let name = strip_version(raw).to_string();
    if name.is_empty() || !seen.insert(name.clone()) {
        return;
    }
    // The original atom keeps version precision for the provider lookup.
    let provider = alpm.and_then(|a| a.provider(raw));
    if aur_names.contains(&name) && provider.is_none() {
        edges
            .entry(pkg.to_string())
            .or_default()
            .insert(name.clone());
        if aur_nodes.insert(name.clone()) {
            queue.push_back(name);
        }
    } else {
        // Concrete provider name (falling back to the bare name) so it can be
        // handed straight to `pacman -S`.
        repo_set.insert(provider.unwrap_or(name));
    }
}

/// Group the AUR nodes into dependency layers: layer *n* contains every package
/// all of whose AUR dependencies are in layers `< n`. Packages within a layer
/// are independent and can be built in parallel. Deterministic (each layer is
/// sorted). Assumes an acyclic graph (the caller has run [`topo_order`]).
fn build_layers(
    nodes: &BTreeSet<String>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Vec<String>> {
    let mut assigned: BTreeSet<String> = BTreeSet::new();
    let mut layers: Vec<Vec<String>> = Vec::new();
    while assigned.len() < nodes.len() {
        let layer: Vec<String> = nodes
            .iter()
            .filter(|n| !assigned.contains(*n))
            .filter(|n| {
                edges
                    .get(*n)
                    .is_none_or(|deps| deps.iter().all(|d| assigned.contains(d)))
            })
            .cloned()
            .collect();
        if layer.is_empty() {
            break; // defensive: a cycle would stall here, but topo_order rejects them
        }
        for n in &layer {
            assigned.insert(n.clone());
        }
        layers.push(layer);
    }
    layers
}

/// An installed AUR package with a newer version available upstream.
#[derive(Debug, Clone)]
pub struct Upgrade {
    pub name: String,
    pub installed: String,
    pub available: String,
}

/// Find installed AUR (foreign) packages whose AUR version is newer than what
/// is installed. Packages no longer in the AUR are skipped.
pub fn find_upgrades() -> Result<Vec<Upgrade>> {
    let alpm = vouch_alpm::Db::open().context("opening libalpm")?;
    let foreign = alpm.foreign_packages();
    if foreign.is_empty() {
        return Ok(Vec::new());
    }

    // Query the AUR for current versions, in chunks to keep URLs sane.
    let names: Vec<&str> = foreign.iter().map(|(n, _)| n.as_str()).collect();
    let mut available: BTreeMap<String, String> = BTreeMap::new();
    for chunk in names.chunks(50) {
        for meta in vouch_rpc::info_many(chunk).context("querying AUR versions")? {
            available.insert(meta.name.clone(), meta.version.clone());
        }
    }

    let mut upgrades: Vec<Upgrade> = foreign
        .into_iter()
        .filter_map(|(name, installed)| {
            let avail = available.get(&name)?;
            vouch_alpm::newer(avail, &installed).then(|| Upgrade {
                name,
                installed,
                available: avail.clone(),
            })
        })
        .collect();
    upgrades.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(upgrades)
}

/// Name suffixes that mark a VCS (development) package.
const VCS_SUFFIXES: &[&str] = &["-git", "-svn", "-hg", "-bzr", "-cvs", "-darcs"];

/// Find installed VCS/"-git" packages whose upstream has new commits (devel
/// upgrades). For each, compare the upstream HEAD to the commit hash embedded in
/// the installed version; if it differs (or can't be determined) the package is
/// a rebuild candidate. This is the `--devel` counterpart to [`find_upgrades`],
/// which only catches version-bump upgrades.
pub fn find_devel_upgrades() -> Result<Vec<Upgrade>> {
    let alpm = vouch_alpm::Db::open().context("opening libalpm")?;
    let vcs: Vec<(String, String)> = alpm
        .foreign_packages()
        .into_iter()
        .filter(|(n, _)| VCS_SUFFIXES.iter().any(|s| n.ends_with(s)))
        .collect();
    if vcs.is_empty() {
        return Ok(Vec::new());
    }

    // Keep only those still in the AUR (map name -> package base).
    let names: Vec<&str> = vcs.iter().map(|(n, _)| n.as_str()).collect();
    let mut base_of: BTreeMap<String, String> = BTreeMap::new();
    for chunk in names.chunks(50) {
        for m in vouch_rpc::info_many(chunk).context("querying AUR")? {
            base_of.insert(m.name.clone(), m.package_base);
        }
    }

    let mut upgrades = Vec::new();
    for (name, installed) in vcs {
        let Some(base) = base_of.get(&name) else {
            continue;
        };
        // None (undeterminable) -> rebuild to be safe; Some(false) -> up to date.
        if upstream_changed(base, &installed).unwrap_or(true) {
            upgrades.push(Upgrade {
                name,
                installed,
                available: "latest commit".to_string(),
            });
        }
    }
    upgrades.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(upgrades)
}

/// `Some(true)` if the upstream HEAD differs from the commit baked into
/// `installed_version`, `Some(false)` if the same, `None` if undeterminable.
fn upstream_changed(package_base: &str, installed_version: &str) -> Option<bool> {
    let bundle = vouch_pkgbuild::fetch(package_base).ok()?;
    let url = first_vcs_url(&bundle.pkgbuild)?;
    let installed = extract_commit(installed_version)?;
    let head = git_ls_remote_head(&url)?;
    Some(!head.starts_with(&installed))
}

/// Extract the first VCS source URL from a PKGBUILD, e.g.
/// `source=('name::git+https://x/y.git#branch=z')` -> `https://x/y.git`.
fn first_vcs_url(pkgbuild: &str) -> Option<String> {
    for proto in ["git+", "svn+", "hg+", "bzr+"] {
        if let Some(start) = pkgbuild.find(proto) {
            let after = &pkgbuild[start + proto.len()..];
            let end = after
                .find(|c: char| c == '#' || c == '\'' || c == '"' || c.is_whitespace() || c == ')')
                .unwrap_or(after.len());
            let url = &after[..end];
            if !url.is_empty() {
                return Some(url.to_string());
            }
        }
    }
    None
}

/// The first hexadecimal run of length >= 7 in a version string (the short
/// commit hash baked into a VCS `pkgver`, e.g. `r567.2d12974-1` -> `2d12974`).
fn extract_commit(version: &str) -> Option<String> {
    let bytes = version.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start >= 7 {
                return Some(version[start..i].to_ascii_lowercase());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// `git ls-remote <url> HEAD` -> the HEAD commit hash (lowercase), if reachable.
fn git_ls_remote_head(url: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["ls-remote", url, "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    line.split_whitespace()
        .next()
        .map(|h| h.to_ascii_lowercase())
}

/// Strip a version constraint / soname tail from a dependency atom:
/// `pacman>6.1` → `pacman`, `go>=1.24` → `go`, `libalpm.so>=14` → `libalpm.so`.
pub fn strip_version(dep: &str) -> &str {
    let end = dep.find(['<', '>', '=']).unwrap_or(dep.len());
    dep[..end].trim()
}

/// Topologically order the AUR nodes so each package comes after the AUR
/// dependencies it needs. Errors on a dependency cycle. Deterministic.
fn topo_order(
    nodes: &BTreeSet<String>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<String>> {
    // 0 = unvisited, 1 = in progress (on the stack), 2 = done.
    let mut state: BTreeMap<String, u8> = nodes.iter().map(|n| (n.clone(), 0u8)).collect();
    let mut order: Vec<String> = Vec::with_capacity(nodes.len());
    for n in nodes {
        visit(n, edges, &mut state, &mut order)?;
    }
    Ok(order)
}

fn visit(
    node: &str,
    edges: &BTreeMap<String, BTreeSet<String>>,
    state: &mut BTreeMap<String, u8>,
    order: &mut Vec<String>,
) -> Result<()> {
    match state.get(node).copied().unwrap_or(0) {
        2 => return Ok(()),
        1 => bail!("dependency cycle detected at '{node}'"),
        _ => {}
    }
    state.insert(node.to_string(), 1);
    if let Some(deps) = edges.get(node) {
        for dep in deps {
            visit(dep, edges, state, order)?;
        }
    }
    state.insert(node.to_string(), 2);
    order.push(node.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_version_constraints() {
        assert_eq!(strip_version("pacman>6.1"), "pacman");
        assert_eq!(strip_version("go>=1.24"), "go");
        assert_eq!(strip_version("git"), "git");
        assert_eq!(strip_version("libalpm.so>=14"), "libalpm.so");
        assert_eq!(strip_version("foo=1.0"), "foo");
        assert_eq!(strip_version("bar<2"), "bar");
    }

    fn nodes(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn edges(pairs: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[test]
    fn orders_dependencies_before_dependents() {
        // a depends on b, b depends on c  =>  build c, then b, then a.
        let n = nodes(&["a", "b", "c"]);
        let e = edges(&[("a", &["b"]), ("b", &["c"])]);
        let order = topo_order(&n, &e).unwrap();
        let pos = |x: &str| order.iter().position(|s| s == x).unwrap();
        assert!(pos("c") < pos("b"));
        assert!(pos("b") < pos("a"));
    }

    #[test]
    fn detects_cycles() {
        let n = nodes(&["a", "b"]);
        let e = edges(&[("a", &["b"]), ("b", &["a"])]);
        assert!(topo_order(&n, &e).is_err());
    }

    #[test]
    fn layers_group_independent_packages() {
        // a -> b -> c, plus an independent d.
        let n = nodes(&["a", "b", "c", "d"]);
        let e = edges(&[("a", &["b"]), ("b", &["c"])]);
        let layers = build_layers(&n, &e);
        // c and d have no deps -> layer 0; b -> layer 1; a -> layer 2.
        assert_eq!(layers, vec![vec!["c", "d"], vec!["b"], vec!["a"]]);
        // Flattening a layering is always a valid build order.
        let flat: Vec<String> = layers.into_iter().flatten().collect();
        let pos = |x: &str| flat.iter().position(|s| s == x).unwrap();
        assert!(pos("c") < pos("b") && pos("b") < pos("a"));
    }
}
