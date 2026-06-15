# vouch

**A security-first AUR helper that vouches for packages before it installs them.**

`vouch` is an [AUR](https://aur.archlinux.org/) helper for Arch Linux that refuses
to install anything it can't *vouch* for. Before building or installing a package
it runs a set of validations and produces a risk verdict — only then does it act.

It was born as a direct response to the June 2026 **"Atomic Arch"** supply-chain
attack, in which attackers adopted orphaned AUR packages and modified their
`PKGBUILD` / `.install` files to pull a malicious npm package (`atomic-lockfile`,
`js-digest`) that dropped an infostealer and an eBPF rootkit. Classic AUR helpers
(`yay`, `paru`) executed those recipes blindly. `vouch` inverts that default:
**no aval, no install.**

```
$ vouch audit google-chrome
vouch: vetting google-chrome 149.0.7827.114-1
  maintainer: gromit   votes: 2353   popularity: 13.11

  ✗ HIGH     Writes to an autostart / shell-init / scheduler location [PKGBUILD:67]
  ! MEDIUM   Defines a post_install() hook (runs as root) [google-chrome.install:10]
  · LOW      Updated within the last 7 days

vouch: REVIEW REQUIRED needs your review before installing (risk 31/100)
```

## What it validates

| Layer | Signal |
|-------|--------|
| **Trust** | Orphaned / freshly-adopted packages, low community votes, very recent updates, out-of-date flags. |
| **Static scan** | `npm`/`bun`/`pip` installs at build time, `curl \| bash`, eBPF / `getdents64` hooks, base64-obfuscated payloads, setuid bits, persistence (cron, systemd, shell rc, autostart), downloads from ephemeral hosts or raw IPs, history wiping. |
| **Structural scan** | Network calls inside `build()`/`package()` (sources belong in `source=()`), and `.install` hook functions that run as **root**. |
| **Scoring** | Severity-weighted risk score (0–100). Any `Critical` finding ⇒ refused outright. |

## Status

- `vouch audit <pkg>` — fetch a package's real AUR metadata + recipe and print
  a verdict. **Read-only**; never builds.
- `vouch build <pkg|dir>` — audit, gate on the verdict, then build inside a
  **network-denied sandbox** (bubblewrap). Two phases: sources are fetched and
  checksum-verified with the network on; `prepare()`/`build()`/`package()` run
  with the network **off**, so a recipe can't pull a payload. Produces a
  `.pkg.tar.*` for you to install with `pacman -U`. Refuses to build if a
  sandbox can't be established — never falls back to an unsandboxed build.
- **Trust-on-first-use (TOFU)**: `vouch` records the exact recipe you approved.
  A later build of the *same, unchanged* recipe proceeds with low friction; if
  the PKGBUILD or a `.install` hook **changed since you vouched for it**, the
  build stops and shows you a diff of exactly what changed before you re-approve
  with `--yes`. This is the direct countermeasure to a *malicious update of an
  already-trusted package* — the heart of the "Atomic Arch" attack. A legitimate
  but custom recipe is therefore a **one-time** review, not a per-build nag.
- `vouch install <pkg…>` (alias `i`) — resolve the full AUR dependency graph,
  **vet every package in it** (deps are an attack surface too), build them in
  dependency order in the sandbox, and install with `pacman` (which resolves
  the repo dependencies). `--dry-run` resolves + vets + prints the plan without
  building or installing anything.
- `vouch forget <pkg>` — drop a stored approval and re-arm TOFU for it.

### Roadmap

- [x] No-network build sandbox (bubblewrap)
- [x] Audit-gated build path
- [x] TOFU review state + change-diff gating
- [x] `vouch install`: recursive dependency resolution + build order + pacman
- [ ] Per-package opt-in for build-time network (electron/npm packages)
- [ ] Community IoC feed checks (e.g. `aur-malware-check`)
- [ ] ALPM integration (precise repo-vs-AUR, installed-version checks)
- [ ] In-sandbox dependency provisioning (drop `--nodeps`)

## Build

```sh
cargo build --release
./target/release/vouch audit <package>
```

Exit codes: `0` vouched · `1` review required · `2` refused · `3` error.

## Workspace layout

```
vouch-core       shared types (PackageMeta, Finding, Severity, Verdict)
vouch-rpc        AUR RPC v5 client
vouch-pkgbuild   read-only fetch / local load / clone of PKGBUILD + .install
vouch-security   the engine: trust + scan + scoring
vouch-sandbox    hardened, network-denied bubblewrap build sandbox
vouch-build      two-phase sandboxed makepkg orchestration
vouch-review     trust-on-first-use review state + recipe change diffs
vouch-resolve    recursive AUR dependency resolution + build ordering
vouch-cli        the `vouch` binary
```

## License

MIT OR Apache-2.0
