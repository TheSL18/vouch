<div align="center">

# 🐺 vouch

**A security-first AUR helper that vouches for packages before it installs them.**

*No aval, no install.*

[![CI](https://github.com/TheSL18/vouch/actions/workflows/ci.yml/badge.svg)](https://github.com/TheSL18/vouch/actions/workflows/ci.yml)

</div>

---

`vouch` is an [AUR](https://aur.archlinux.org/) helper for Arch Linux that refuses
to install anything it cannot *vouch* for. Before a package is built or installed
it passes through layered checks; only then does `vouch` act. Classic helpers
(`yay`, `paru`) execute a package's recipe as-is — `vouch` inverts that default.

It was born as a direct response to the June 2026 **"Atomic Arch"** supply-chain
attack, in which attackers adopted orphaned AUR packages and modified their
`PKGBUILD` / `.install` files to pull a malicious npm package (`atomic-lockfile`,
`js-digest`) that dropped an infostealer and an eBPF rootkit.

```console
$ vouch install some-aur-app
vouch: vetting some-aur-app 2.1.0-1
  maintainer: jane   votes: 1820   popularity: 22.4
  ✗ CRITICAL Pipes a downloaded file straight into a shell [some-aur-app.install:7]
vouch: REFUSED refuses to install this package (risk 60/100)
```

## Defense in depth

`vouch` layers independent checks so a single bypass isn't enough:

| Layer | What it does |
|-------|--------------|
| **Trust** | Flags orphaned / freshly-adopted packages, low community votes, very recent updates, out-of-date flags. |
| **Behavioral scan** | Detects `npm`/`bun`/`pip` installs at build time, `curl \| bash`, eBPF / `getdents64` hooks, base64-obfuscated payloads, setuid bits, persistence (cron, systemd, shell rc, autostart), downloads from ephemeral hosts / raw IPs, history wiping. |
| **Structural scan** | Understands shell functions: network calls inside `build()`/`package()` (sources belong in `source=()`), and `.install` hooks that run as **root**. |
| **Threat intel (IoC)** | Matches recipes against known-bad indicators — the Atomic Arch npm payload names, plus banned maintainers, hijacked package names, malicious strings/domains and file hashes from updatable feeds. Any match is `Critical`. |
| **Build sandbox** | Builds inside bubblewrap with the **network unshared** during `build()`/`package()`, so a recipe has no route to fetch a payload. Refuses to build if it can't sandbox. |
| **TOFU** | Remembers the exact recipe you approved; a later build of the *unchanged* recipe is low-friction, but a change stops you and shows a **diff** of what changed — the countermeasure to a malicious update of an already-trusted package. |

The scoring engine turns findings into a 0–100 risk score (each rule counts once).
Any `Critical` finding refuses the package outright; otherwise the verdict is
**vouched** (proceed), **review required** (needs `--yes`), or **refused**.

## Commands

```console
vouch search <query>         # search the AUR by name + description
vouch audit <pkg>            # fetch + vet a package, print a verdict (read-only)
vouch build <pkg|dir>        # vet, then build in the network-denied sandbox
vouch install <pkg…>         # resolve deps, vet the whole tree, build in order, install
vouch upgrade                # rebuild installed AUR packages with newer AUR versions
vouch ioc [--import FILE]    # show / import indicators-of-compromise feeds
vouch forget <pkg>           # drop a stored approval (re-arms TOFU)
```

Useful flags: `--dry-run` (plan only), `--yes` (accept REVIEW / a changed recipe),
`--force` (override a REFUSED verdict — discouraged), `--allow-build-network`
(let a recipe fetch at build time; per-package, remembered, reduces isolation),
`--rmdeps` (remove build-only dependencies after installing), `--no-devel`
(`upgrade` only: skip the VCS/`-git` upstream-commit check, which is on by default),
`--no-sandbox` (build without isolation, for recipes that need FUSE/unionfs like
some flutter/electron packages — the recipe is still vetted).

### pacman-style syntax

`vouch` also accepts pacman-style flags, like `yay`/`paru`, so it can be a
drop-in:

```console
vouch -Syu              # full upgrade: repos via pacman, then the AUR via vouch
vouch -S <pkg…>         # install (repo targets → pacman, AUR targets → vouch)
vouch -Ss <query>       # search repos + the AUR
vouch -Sy               # refresh sync databases
vouch -R/-Q/-U/… <…>    # handed straight to pacman
```

Both styles work; use whichever you prefer.

Exit codes: `0` vouched · `1` review required · `2` refused · `3` error.

### Examples

```console
$ vouch install pamac-aur --dry-run     # see the full plan + per-package verdicts
$ vouch build ./my-pkgbuild-dir         # vet & build a local recipe
$ vouch upgrade --dry-run               # list AUR packages with newer versions
$ vouch ioc --import aur-malware.json   # load a community IoC feed
```

## How it works

For an AUR install, `vouch`:

1. **Resolves** the full dependency graph (recursively) and splits it into AUR
   build targets and repo dependencies, using `libalpm` to classify precisely —
   provides, version constraints, sonames and every configured repo (including
   `chaotic-aur`, `cachyos`, …). A package available as a signed binary is
   preferred over an AUR rebuild.
2. **Vets every AUR package** in the tree (trust + behavioral + structural +
   IoC). A dependency is an attack surface too, so all of them are checked.
3. **Installs the repo dependencies** with `pacman -S --asdeps` (resolved to
   concrete packages via libalpm), so each build's `makepkg` finds its declared
   dependencies — `vouch` never lets `makepkg` fetch them itself.
4. **Builds** the packages in dependency layers inside a network-denied
   bubblewrap sandbox: sources are fetched and checksum-verified with the
   network on, then `build()`/`package()` run with the network **off**.
   Independent packages in the same layer build in parallel; each built AUR
   dependency is installed before the next layer (its dependents) is built.
5. **Installs** the built packages with `pacman -U`.

## Build

```sh
cargo build --release
./target/release/vouch audit <package>
```

`vouch` is an Arch Linux tool: it links `libalpm` and uses `bubblewrap`,
`makepkg` and `pacman` at runtime.

## Documentation

See the [`wiki/`](wiki/) directory for full docs in **English** and **Spanish**
(installation, usage, the security model, and an FAQ).

## Workspace layout

```
vouch-core       shared types (PackageMeta, Finding, Severity, Verdict)
vouch-rpc        AUR RPC v5 client
vouch-pkgbuild   read-only fetch / local load / clone of PKGBUILD + .install
vouch-security   the engine: trust + scan + IoC + scoring
vouch-sandbox    hardened, network-denied bubblewrap build sandbox
vouch-build      two-phase sandboxed makepkg orchestration
vouch-review     trust-on-first-use review state + recipe change diffs
vouch-resolve    recursive AUR dependency resolution + build ordering + upgrades
vouch-alpm       libalpm queries: precise repo-vs-AUR, installed versions
vouch-ioc        indicators-of-compromise / threat-intel matching
vouch-cli        the `vouch` binary
```

## Roadmap

- [x] Network-denied build sandbox (bubblewrap)
- [x] Audit-gated build path
- [x] TOFU review state + change-diff gating
- [x] `vouch install`: recursive dependency resolution + build order + pacman
- [x] IoC / threat-intel feed checks (built-in + importable)
- [x] Per-package opt-in for build-time network (electron/npm packages)
- [x] ALPM integration (precise repo-vs-AUR via libalpm, installed versions)
- [x] `vouch upgrade`: AUR-layer `-Syu`
- [x] Dependency provisioning: install repo + built-AUR deps so real builds work
- [x] Parallel builds of independent dependency-graph branches (by layer)
- [x] `vouch search` (AUR search)
- [x] `--rmdeps`: remove build-only dependencies after installing
