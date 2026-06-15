# vouch — Wiki (English)

**A security-first AUR helper that vouches for packages before it installs them.**

`vouch` is an [AUR](https://aur.archlinux.org/) helper for Arch Linux built around
one idea: **never run a package recipe you haven't checked.** Classic helpers
build and install whatever the AUR hands them; `vouch` vets first and refuses
what it can't vouch for.

It was created in response to the June 2026 **"Atomic Arch"** supply-chain attack,
where hijacked AUR packages pulled a malicious npm payload (`atomic-lockfile`,
`js-digest`) that dropped an infostealer and an eBPF rootkit.

## Pages

- **[Usage](Usage)** — commands, flags and everyday workflows.
- **[Security Model](Security-Model)** — what each layer checks and why.
- **[FAQ](FAQ)** — common questions.

## Quick start

```sh
git clone https://github.com/TheSL18/vouch
cd vouch
cargo build --release
./target/release/vouch audit <package>
```

```console
$ vouch audit some-aur-app          # read-only: fetch + vet + verdict
$ vouch install some-aur-app        # resolve + vet tree + sandbox build + install
$ vouch upgrade                     # AUR-layer -Syu
```

## Requirements

`vouch` is an Arch Linux tool. At build time it links **libalpm**; at runtime it
uses **bubblewrap** (sandbox), **makepkg** and **pacman**. Unprivileged user
namespaces must be enabled for the build sandbox.

## Status

Early but functional: audit, build (sandboxed), install (with full-tree vetting),
upgrade, IoC feeds, and trust-on-first-use are all implemented. See the
[roadmap](https://github.com/TheSL18/vouch#roadmap) for what's next.
