# Usage (English)

## Commands

| Command | What it does |
|---------|--------------|
| `vouch search <query>` | Search the AUR by name and description (most-voted first). Alias: `s`. |
| `vouch audit <pkg>` | Fetch a package's AUR metadata + recipe and print a verdict. **Read-only** — never builds. |
| `vouch build <pkg\|dir>` | Vet, gate, then build in the network-denied sandbox. Accepts an AUR name or a local directory with a `PKGBUILD`. Does not install. |
| `vouch install <pkg…>` | Resolve the dependency graph, vet every AUR package, build in order, install with pacman. Alias: `i`. |
| `vouch upgrade` | Rebuild installed AUR packages whose AUR version is newer (an AUR-layer `-Syu`). Alias: `u`. |
| `vouch ioc [--import FILE]` | Show loaded indicators of compromise, or merge a JSON feed. |
| `vouch forget <pkg>` | Drop the stored approval for a package, re-arming trust-on-first-use. |

## Flags

- `--dry-run` — resolve and vet everything, print the plan, build/install nothing.
- `--yes` — proceed past a **REVIEW** verdict, or accept a recipe that **changed**
  since you last vouched for it.
- `--force` — build even when the verdict is **REFUSED**. Strongly discouraged;
  prints a loud warning.
- `--allow-build-network` — let this package's `build()` reach the network (for
  recipes that legitimately fetch at build time, e.g. electron/npm). It is
  **per-package**, requires the package to still pass vetting, is **remembered**
  for the unchanged recipe, and reduces build isolation (a clear notice prints).
- `--rmdeps` — after installing, remove build-only dependencies (make/check deps
  that aren't needed at runtime) that nothing else requires (`pacman -Rns`).

## Verdicts and exit codes

| Verdict | Meaning | Exit code |
|---------|---------|-----------|
| VOUCHED | Clean enough to proceed | `0` |
| REVIEW REQUIRED | A human should look first (`--yes` to proceed) | `1` |
| REFUSED | Too risky; will not build (`--force` to override) | `2` |
| (error) | Network/parse/etc. failure | `3` |

## Typical workflows

**Vet before trusting anything**
```console
$ vouch audit firefox-patch-bin
```

**Install with a preview first**
```console
$ vouch install pamac-aur --dry-run     # see the plan and per-package verdicts
$ vouch install pamac-aur               # build (sandboxed) + install
```

**A package that genuinely needs network at build time**
```console
$ vouch build some-electron-app --allow-build-network
# remembered: a later unchanged rebuild won't need the flag again
```

**Keep AUR packages current**
```console
$ vouch upgrade --dry-run    # list what's newer in the AUR
$ vouch upgrade              # vet + rebuild + install the upgrades
```

**Threat-intel feeds**
```console
$ vouch ioc                          # show indicator counts and the feed path
$ vouch ioc --import aur-malware.json # merge a community list (e.g. aur-malware-check)
```

## Where state lives

- Review approvals (TOFU): `$XDG_DATA_HOME/vouch/reviews/` (default `~/.local/share/vouch/reviews/`).
- IoC user feed: `$XDG_DATA_HOME/vouch/ioc.json`.
