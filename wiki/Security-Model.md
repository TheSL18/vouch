# Security Model (English)

`vouch` assumes the AUR is **untrusted by default**. A package's maintainer can
change, an account can be compromised, and a recipe runs arbitrary code on your
machine at build *and* install time. `vouch` layers independent checks so that no
single bypass is enough, and makes the dangerous default — silent execution —
impossible.

## The layers

### 1. Trust signals
Derived from AUR metadata: orphaned packages (the entry point of "Atomic Arch"),
freshly-adopted ones, low community votes, very recent updates, out-of-date flags.
None is proof of malice; together they raise the bar for review.

### 2. Behavioral scan
Pattern analysis of `PKGBUILD` and `.install` files for techniques seen in
supply-chain attacks: `npm`/`bun`/`pip` installs at build time, `curl | bash`,
eBPF / `getdents64` hooks (rootkits), base64-obfuscated blobs, setuid bits,
persistence (cron, systemd units, shell rc files, autostart), downloads from
ephemeral hosts or raw IPs, shell-history wiping.

### 3. Structural scan
Understands shell function bodies, so context matters: a network call inside
`build()`/`package()` (sources belong in the checksummed `source=()` array) is
flagged, and every `.install` hook is surfaced because pacman runs it **as root**.

### 4. Threat intelligence (IoC)
Matches recipes against *known-bad* indicators rather than behavior: the documented
Atomic Arch npm payload names, plus banned maintainer accounts, hijacked package
names, malicious strings/domains, and file hashes. Indicators ship as a built-in
baseline and can be extended from community feeds (`vouch ioc --import`). Any match
is `Critical`. This catches a known payload even when it's referenced indirectly
and the behavioral rules wouldn't fire.

### 5. Build sandbox (runtime enforcement)
The scanner is advisory and can be fooled by obfuscation; the sandbox cannot.
Builds run inside **bubblewrap** with a read-only system, a single writable build
directory, all namespaces unshared, and — crucially — the **network unshared
during `build()`/`package()`**. Sources are fetched and checksum-verified in a
separate network-on phase. A recipe that tries to `npm install` or `curl | bash`
a payload during the build simply has **no route off the machine**. If a sandbox
cannot be established, `vouch` refuses to build rather than fall back.

### 6. Trust-on-first-use (TOFU)
The most dangerous moment in Atomic Arch wasn't the first install — it was the
malicious *update* to a package you already trusted. `vouch` records the exact
recipe content you approved. An unchanged recipe rebuilds with low friction; a
**changed** one stops you and shows a diff of precisely what changed before you
re-approve. A legitimate custom recipe is therefore a one-time review, not a nag.

## Scoring and decisions

Findings are weighted by severity into a 0–100 score; **each rule counts once**,
so a legitimate package that (say) symlinks six systemd timers isn't pushed to
REFUSED by repetition. Any single `Critical` finding refuses outright. Otherwise:
`< 25` → vouched, `25–59` → review required, `≥ 60` → refused.

## Whole-tree vetting

For an install, **every** AUR package in the dependency graph is vetted — not just
the one you typed. A transitive dependency is just as capable of carrying a payload.

## Precise repo-vs-AUR (libalpm)

`vouch` asks `libalpm` whether any configured repository can satisfy a dependency
(handling provides, version constraints and sonames, across third-party repos like
`chaotic-aur`/`cachyos`). If a signed binary exists, it's preferred over rebuilding
from the AUR — matching your real trust configuration.

## Honest limitations

- Builds currently pass `--nodeps`; make-dependencies must already be present.
- `--force` and `--allow-build-network` are escape hatches: explicit, logged, and
  per-package, but they do relax guarantees by your choice.
- The static scanner is a heuristic. It is one layer; the sandbox and TOFU are the
  ones that hold even when the scanner is fooled.
