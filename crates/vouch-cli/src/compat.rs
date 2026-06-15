//! pacman-style command-line compatibility.
//!
//! So `vouch` can be a drop-in for `yay`/`paru`, it accepts pacman-style
//! invocations (`vouch -Syu`, `vouch -S pkg`, `vouch -Ss query`, …) in addition
//! to its own subcommands. This module only *parses* such an invocation into an
//! [`Action`]; `main` decides how to carry it out (vetting AUR work through the
//! normal pipeline, passing the rest to `pacman`).
//!
//! vouch's own gate flags (`--force`, `--yes`, `--allow-build-network`,
//! `--rmdeps`, `--no-devel`, `--no-sandbox`, `--dry-run`) are recognized here
//! too, so they work the same whether you write `vouch -S pkg --force` or
//! `vouch install pkg --force`.

/// vouch gate/build options that apply to an install or upgrade, parsed out of a
/// pacman-style invocation so they aren't silently dropped.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Opts {
    pub force: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub allow_build_network: bool,
    pub rmdeps: bool,
    pub no_devel: bool,
    pub no_sandbox: bool,
}

/// What a pacman-style invocation maps to.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// `-Syu` — full upgrade: repos via pacman, then the AUR layer via vouch.
    /// Any extra targets are installed afterwards.
    FullUpgrade {
        targets: Vec<String>,
        noconfirm: bool,
        opts: Opts,
    },
    /// `-S <targets>` — install (repo targets go to pacman, AUR ones to vouch).
    /// `refresh` is set when `-y` was also given (`-Sy pkg`).
    Install {
        targets: Vec<String>,
        noconfirm: bool,
        refresh: bool,
        opts: Opts,
    },
    /// `-Ss <query>` — search repos (pacman) and the AUR (vouch).
    Search { query: Vec<String> },
    /// `-Sy` — refresh sync databases only.
    Refresh { noconfirm: bool },
    /// `-R`/`-Q`/`-D`/`-F`/`-T`/`-U` — handed straight to pacman. `sudo` is true
    /// for operations that modify the system.
    Passthrough { sudo: bool },
    /// Couldn't make sense of it; the message explains why.
    Unsupported(String),
}

/// Parse a pacman-style argument list (everything after the program name).
pub fn parse(args: &[String]) -> Action {
    let mut op: Option<char> = None;
    let mut mods: std::collections::BTreeSet<char> = Default::default();
    let mut targets: Vec<String> = Vec::new();
    let mut noconfirm = false;
    let mut opts = Opts::default();

    for a in args {
        if a == "--noconfirm" {
            noconfirm = true;
        } else if let Some(long) = a.strip_prefix("--") {
            // Recognize vouch's own flags; other long options are ignored here.
            match long {
                "force" => opts.force = true,
                "yes" => opts.yes = true,
                "dry-run" => opts.dry_run = true,
                "allow-build-network" => opts.allow_build_network = true,
                "rmdeps" => opts.rmdeps = true,
                "no-devel" => opts.no_devel = true,
                "no-sandbox" => opts.no_sandbox = true,
                _ => {}
            }
        } else if let Some(short) = a.strip_prefix('-') {
            for c in short.chars() {
                if op.is_none() && "SRQDFTU".contains(c) {
                    op = Some(c);
                } else {
                    mods.insert(c);
                }
            }
        } else {
            targets.push(a.clone());
        }
    }

    match op {
        Some('S') => {
            if mods.contains(&'s') {
                Action::Search { query: targets }
            } else if mods.contains(&'u') {
                Action::FullUpgrade {
                    targets,
                    noconfirm,
                    opts,
                }
            } else if !targets.is_empty() {
                Action::Install {
                    targets,
                    noconfirm,
                    refresh: mods.contains(&'y'),
                    opts,
                }
            } else if mods.contains(&'y') {
                Action::Refresh { noconfirm }
            } else {
                Action::Unsupported("`-S` needs a target, `-u`, `-s` or `-y`".into())
            }
        }
        Some(c) if matches!(c, 'R' | 'Q' | 'D' | 'F' | 'T' | 'U') => Action::Passthrough {
            sudo: matches!(c, 'R' | 'D' | 'U'),
        },
        _ => Action::Unsupported("unrecognized pacman-style operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn full_upgrade() {
        assert_eq!(
            parse(&args(&["-Syu"])),
            Action::FullUpgrade {
                targets: vec![],
                noconfirm: false,
                opts: Opts::default(),
            }
        );
        // -Syyu and a trailing --noconfirm.
        assert_eq!(
            parse(&args(&["-Syyu", "--noconfirm"])),
            Action::FullUpgrade {
                targets: vec![],
                noconfirm: true,
                opts: Opts::default(),
            }
        );
    }

    #[test]
    fn install_and_search() {
        assert_eq!(
            parse(&args(&["-S", "paru", "firefox"])),
            Action::Install {
                targets: args(&["paru", "firefox"]),
                noconfirm: false,
                refresh: false,
                opts: Opts::default(),
            }
        );
        assert_eq!(
            parse(&args(&["-Ss", "wazuh"])),
            Action::Search {
                query: args(&["wazuh"])
            }
        );
    }

    #[test]
    fn refresh_only() {
        assert_eq!(parse(&args(&["-Sy"])), Action::Refresh { noconfirm: false });
    }

    #[test]
    fn install_with_refresh() {
        // `-Sy pkg` installs and asks for a db refresh first.
        assert_eq!(
            parse(&args(&["-Sy", "session-desktop"])),
            Action::Install {
                targets: args(&["session-desktop"]),
                noconfirm: false,
                refresh: true,
                opts: Opts::default(),
            }
        );
    }

    #[test]
    fn vouch_flags_are_threaded() {
        // The bug this guards against: vouch's gate flags were dropped in
        // pacman-style mode, so `--force` did nothing.
        let want = Opts {
            force: true,
            ..Opts::default()
        };
        match parse(&args(&["-Sy", "session-desktop", "--force"])) {
            Action::Install { opts, refresh, .. } => {
                assert_eq!(opts, want);
                assert!(refresh);
            }
            other => panic!("expected Install, got {other:?}"),
        }
        // Order-independent and works in the -S form too.
        match parse(&args(&["-S", "--force", "pkg"])) {
            Action::Install { opts, .. } => assert_eq!(opts, want),
            other => panic!("expected Install, got {other:?}"),
        }
        // Several flags at once on an upgrade.
        match parse(&args(&["-Syu", "--yes", "--no-devel", "--rmdeps"])) {
            Action::FullUpgrade { opts, .. } => {
                assert!(opts.yes && opts.no_devel && opts.rmdeps);
                assert!(!opts.force);
            }
            other => panic!("expected FullUpgrade, got {other:?}"),
        }
    }

    #[test]
    fn passthrough_ops() {
        assert_eq!(
            parse(&args(&["-Rns", "foo"])),
            Action::Passthrough { sudo: true }
        );
        assert_eq!(parse(&args(&["-Q"])), Action::Passthrough { sudo: false });
        assert_eq!(
            parse(&args(&["-Qi", "bash"])),
            Action::Passthrough { sudo: false }
        );
        assert_eq!(
            parse(&args(&["-U", "./x.pkg.tar.zst"])),
            Action::Passthrough { sudo: true }
        );
    }

    #[test]
    fn unsupported() {
        assert!(matches!(parse(&args(&["-S"])), Action::Unsupported(_)));
        assert!(matches!(parse(&args(&["-Z"])), Action::Unsupported(_)));
    }
}
