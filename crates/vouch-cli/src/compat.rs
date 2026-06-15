//! pacman-style command-line compatibility.
//!
//! So `vouch` can be a drop-in for `yay`/`paru`, it accepts pacman-style
//! invocations (`vouch -Syu`, `vouch -S pkg`, `vouch -Ss query`, …) in addition
//! to its own subcommands. This module only *parses* such an invocation into an
//! [`Action`]; `main` decides how to carry it out (vetting AUR work through the
//! normal pipeline, passing the rest to `pacman`).

/// What a pacman-style invocation maps to.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// `-Syu` — full upgrade: repos via pacman, then the AUR layer via vouch.
    /// Any extra targets are installed afterwards.
    FullUpgrade {
        targets: Vec<String>,
        noconfirm: bool,
    },
    /// `-S <targets>` — install (repo targets go to pacman, AUR ones to vouch).
    Install {
        targets: Vec<String>,
        noconfirm: bool,
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

    for a in args {
        if a == "--noconfirm" {
            noconfirm = true;
        } else if a.starts_with("--") {
            // Other long options aren't interpreted here.
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
                Action::FullUpgrade { targets, noconfirm }
            } else if !targets.is_empty() {
                Action::Install { targets, noconfirm }
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
                noconfirm: false
            }
        );
        // -Syyu and a trailing --noconfirm.
        assert_eq!(
            parse(&args(&["-Syyu", "--noconfirm"])),
            Action::FullUpgrade {
                targets: vec![],
                noconfirm: true
            }
        );
    }

    #[test]
    fn install_and_search() {
        assert_eq!(
            parse(&args(&["-S", "paru", "firefox"])),
            Action::Install {
                targets: args(&["paru", "firefox"]),
                noconfirm: false
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
