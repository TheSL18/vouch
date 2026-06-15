# FAQ (English)

**Is `vouch` a drop-in replacement for `yay` / `paru`?**
Not yet. It covers audit, build, install, and an AUR-layer upgrade, but it isn't a
full pacman front-end. It coexists with your existing helper.

**Does it modify my system?**
Only `vouch install` / `vouch upgrade` call `pacman` (with `sudo`), and they ask
for confirmation first. `audit` and `--dry-run` never touch anything.

**A legitimate package I trust gets flagged. Is that a false positive?**
`vouch` *surfaces* risky patterns; it doesn't claim they're malicious. A custom
`.install` hook, for example, is shown as a MEDIUM note but usually stays VOUCHED.
You review it once — trust-on-first-use then stays quiet until the recipe changes.

**My package genuinely needs network during `build()` (electron/npm).**
Use `--allow-build-network`. It's per-package, the package is still vetted, the
choice is remembered for the unchanged recipe, and a reduced-isolation notice is
printed. The default stays locked down.

**Why was a package built instead of taken from a repo (or vice-versa)?**
`vouch` asks `libalpm` whether any configured repository can satisfy the
dependency. If you have a binary repo like `chaotic-aur`, packages it provides are
used from there (signed) instead of rebuilt from the AUR.

**The build sandbox won't start.**
It needs unprivileged user namespaces and `bubblewrap`. If a sandbox can't be
established, `vouch` refuses to build rather than build unsandboxed — by design.

**How do I update the threat-intel indicators?**
`vouch ioc --import <file.json>` merges a JSON feed (e.g. a community list such as
`aur-malware-check`) into your local indicators at `$XDG_DATA_HOME/vouch/ioc.json`.

**I changed my mind about a package I vouched for.**
`vouch forget <pkg>` drops the stored approval and re-arms trust-on-first-use.

**Can I override a REFUSED verdict?**
`--force`, if you fully understand the findings. It prints a loud warning. This
exists for rare expert cases, not routine use.

**What do the exit codes mean?**
`0` vouched · `1` review required · `2` refused · `3` error. Handy for scripting.
