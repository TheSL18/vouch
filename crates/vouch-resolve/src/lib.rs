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
//! AUR package (the AUR is authoritative for "is this an AUR package?").
//! Everything else — real repo packages, virtual packages, sonames — is left to
//! `pacman`, which resolves them at install time. This deliberately avoids
//! reimplementing soname/provides resolution.
//!
//! Trade-off: a name that exists in *both* the official repos and the AUR is
//! treated as an AUR build target (so `vouch` vets and sandbox-builds it). Such
//! collisions are rare; preferring the signed repo copy in that case needs the
//! sync database and is deferred to the planned ALPM integration.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result, bail};
use vouch_core::PackageMeta;

/// The outcome of resolving one or more targets.
#[derive(Debug, Clone)]
pub struct ResolvedPlan {
    /// The user-requested AUR packages (canonical names).
    pub explicit_targets: Vec<String>,
    /// AUR packages to build, in dependency order (each after its AUR deps).
    pub aur_build_order: Vec<String>,
    /// Repo/system dependencies, for display. `pacman` actually resolves these.
    pub repo_deps: Vec<String>,
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
    let mut repo_deps: BTreeSet<String> = BTreeSet::new();
    let mut metas: BTreeMap<String, PackageMeta> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut explicit_targets: Vec<String> = Vec::new();

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

        // Unique, version-stripped dependency names.
        let deps: BTreeSet<String> = meta
            .build_deps()
            .map(strip_version)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        // One RPC call to learn which of these even exist in the AUR.
        let dep_refs: Vec<&str> = deps.iter().map(String::as_str).collect();
        let in_aur = vouch_rpc::info_many(&dep_refs).context("classifying dependencies")?;
        let aur_names: BTreeSet<String> = in_aur.iter().map(|m| m.name.clone()).collect();
        for m in in_aur {
            metas.entry(m.name.clone()).or_insert(m);
        }

        let node_edges = edges.entry(pkg.clone()).or_default();
        for dep in deps {
            // AUR is authoritative: if the dep is an AUR package, it's a build
            // target we must vet and build; otherwise pacman handles it.
            if aur_names.contains(&dep) {
                node_edges.insert(dep.clone());
                if aur_nodes.insert(dep.clone()) {
                    queue.push_back(dep);
                }
            } else {
                repo_deps.insert(dep);
            }
        }
    }

    let aur_build_order = topo_order(&aur_nodes, &edges)?;
    Ok(ResolvedPlan {
        explicit_targets,
        aur_build_order,
        repo_deps: repo_deps.into_iter().collect(),
    })
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
}
