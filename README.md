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

Milestone 1 (current): `vouch audit <pkg>` — fetches a package's real AUR metadata
and build recipe and prints a verdict. **Never builds or installs.** Read-only.

### Roadmap

- [ ] `vouch -S` install path, gated by the audit verdict
- [ ] PKGBUILD diff vs last reviewed version (TOFU)
- [ ] No-network build sandbox (bubblewrap / systemd-nspawn)
- [ ] Community IoC feed checks (e.g. `aur-malware-check`)
- [ ] ALPM integration (dependency resolution, build order, repo packages)
- [ ] Local file audit (`vouch audit --file ./PKGBUILD`) for CI

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
vouch-pkgbuild   read-only fetch of PKGBUILD + .install files
vouch-security   the engine: trust + scan + scoring
vouch-cli        the `vouch` binary
```

## License

MIT OR Apache-2.0
