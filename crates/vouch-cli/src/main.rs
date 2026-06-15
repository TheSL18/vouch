//! `vouch` — a security-first AUR helper.
//!
//! Subcommands:
//! * `audit <pkg>` — fetch a package's AUR metadata + recipe and print a risk
//!   verdict. Read-only; never builds.
//! * `build <pkg|dir>` — audit, gate on the verdict, then build the package
//!   inside a network-denied sandbox. Does not install.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use owo_colors::{AnsiColors, OwoColorize};
use vouch_core::{Decision, PackageMeta, Severity, Verdict};

#[derive(Parser)]
#[command(
    name = "vouch",
    version,
    about = "A security-first AUR helper that vouches for packages before it installs them."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Vet an AUR package and print a risk verdict (fetches, never builds).
    Audit {
        /// AUR package name.
        package: String,
        /// Emit the verdict as JSON instead of a human report.
        #[arg(long)]
        json: bool,
    },
    /// Build an AUR package (or local PKGBUILD dir) in a network-denied sandbox.
    Build {
        /// AUR package name, or a path to a directory containing a PKGBUILD.
        target: String,
        /// Build even if the verdict is REFUSED (strongly discouraged).
        #[arg(long)]
        force: bool,
        /// Proceed past a REVIEW verdict without an interactive stop.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Audit { package, json } => match audit(&package, json) {
            Ok(verdict) => exit_code_for(verdict.decision),
            Err(e) => fail(e),
        },
        Command::Build { target, force, yes } => match build(&target, force, yes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
    }
}

fn fail(e: anyhow::Error) -> ExitCode {
    eprintln!("{} {e:#}", "error:".red().bold());
    ExitCode::from(3)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ----------------------------------------------------------------------------
// audit
// ----------------------------------------------------------------------------

fn audit(package: &str, json: bool) -> Result<Verdict> {
    let meta = vouch_rpc::info(package)
        .context("looking up package on the AUR")?
        .with_context(|| {
            format!("'{package}' is not in the AUR (official-repo packages aren't vetted here)")
        })?;
    let bundle =
        vouch_pkgbuild::fetch(&meta.package_base).context("fetching the package build recipe")?;
    let verdict = vouch_security::evaluate(&meta, &bundle, now_unix());

    if json {
        println!("{}", serde_json::to_string_pretty(&verdict)?);
    } else {
        print_meta(&meta);
        print_findings(&verdict);
    }
    Ok(verdict)
}

// ----------------------------------------------------------------------------
// build
// ----------------------------------------------------------------------------

fn build(target: &str, force: bool, yes: bool) -> Result<()> {
    // Refuse early if we can't sandbox — never build unsandboxed.
    if !vouch_sandbox::available() {
        bail!(
            "secure build sandbox unavailable (bwrap missing or unprivileged user \
             namespaces disabled). Refusing to build."
        );
    }

    let path = Path::new(target);
    let build_dir = if path.is_dir() && path.join("PKGBUILD").is_file() {
        audit_local_and_gate(path, force, yes)?;
        path.to_path_buf()
    } else {
        audit_aur_and_clone(target, force, yes)?
    };

    println!("{} building in a network-denied sandbox…", "vouch:".bold());
    let outcome = vouch_build::build_in_sandbox(&build_dir)?;

    println!();
    println!("{} {}", "vouch:".bold(), "build complete".green().bold());
    for p in &outcome.packages {
        println!("  {} {}", "✓".green(), p.display());
    }
    println!(
        "  {} review then install with: {}",
        "→".dimmed(),
        format!(
            "sudo pacman -U {}",
            outcome
                .packages
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
        .dimmed()
    );
    Ok(())
}

/// Audit a local package directory (scan only) and apply the gate.
fn audit_local_and_gate(dir: &Path, force: bool, yes: bool) -> Result<()> {
    let bundle = vouch_pkgbuild::load_local(dir).context("loading local PKGBUILD")?;
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("local");
    let verdict = vouch_security::scan_only(name, &bundle);
    print_findings(&verdict);
    gate(&verdict, force, yes)
}

/// Audit an AUR package, gate, clone its repo, re-audit the cloned recipe, and
/// return the directory to build.
fn audit_aur_and_clone(package: &str, force: bool, yes: bool) -> Result<PathBuf> {
    let meta = vouch_rpc::info(package)
        .context("looking up package on the AUR")?
        .with_context(|| format!("'{package}' is not in the AUR"))?;
    let bundle =
        vouch_pkgbuild::fetch(&meta.package_base).context("fetching the package build recipe")?;
    let verdict = vouch_security::evaluate(&meta, &bundle, now_unix());
    print_meta(&meta);
    print_findings(&verdict);
    gate(&verdict, force, yes)?;

    let dest = unique_build_dir(&meta.package_base);
    println!(
        "{} cloning {} …",
        "vouch:".bold(),
        format!("aur/{}", meta.package_base).dimmed()
    );
    vouch_pkgbuild::clone(&meta.package_base, &dest).context("cloning AUR repo")?;

    // Defense in depth: re-scan exactly what we cloned (and will build), in
    // case it differs from the metadata-time fetch.
    let cloned = vouch_pkgbuild::load_local(&dest).context("loading cloned PKGBUILD")?;
    let reverdict = vouch_security::scan_only(&meta.package_base, &cloned);
    if reverdict.score > verdict.score {
        println!(
            "{} cloned recipe scored higher than metadata fetch — re-vetting",
            "vouch:".yellow()
        );
        print_findings(&reverdict);
        gate(&reverdict, force, yes)?;
    }
    Ok(dest)
}

/// Enforce the verdict before any build happens.
fn gate(verdict: &Verdict, force: bool, yes: bool) -> Result<()> {
    match verdict.decision {
        Decision::Vouched => Ok(()),
        Decision::Review => {
            if yes {
                Ok(())
            } else {
                bail!(
                    "verdict is REVIEW REQUIRED (risk {}/100). Read the findings above, \
                     then re-run with --yes to proceed.",
                    verdict.score
                )
            }
        }
        Decision::Refused => {
            if force {
                eprintln!(
                    "{} overriding a REFUSED verdict (--force). This is dangerous.",
                    "warning:".yellow().bold()
                );
                Ok(())
            } else {
                bail!(
                    "verdict is REFUSED (risk {}/100). vouch will not build this. \
                     Override with --force only if you fully understand the findings.",
                    verdict.score
                )
            }
        }
    }
}

fn unique_build_dir(base: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("vouch-build-{base}-{stamp}"))
}

// ----------------------------------------------------------------------------
// presentation
// ----------------------------------------------------------------------------

fn print_meta(meta: &PackageMeta) {
    println!(
        "{} {} {}",
        "vouch:".bold(),
        "vetting".dimmed(),
        format!("{} {}", meta.name, meta.version).bold()
    );
    let maint = meta.maintainer.as_deref().unwrap_or("(orphaned)");
    println!(
        "  maintainer: {maint}   votes: {}   popularity: {:.2}",
        meta.num_votes, meta.popularity
    );
    println!();
}

fn print_findings(verdict: &Verdict) {
    if verdict.findings.is_empty() {
        println!("  {} no findings", "✓".green());
    } else {
        for f in &verdict.findings {
            let mark = match f.severity {
                Severity::Critical | Severity::High => "✗",
                Severity::Medium => "!",
                _ => "·",
            };
            let loc = f
                .location
                .as_deref()
                .map(|l| format!(" [{l}]"))
                .unwrap_or_default();
            println!(
                "  {} {:<8} {}{}",
                mark.color(severity_color(f.severity)),
                f.severity.label().color(severity_color(f.severity)),
                f.title,
                loc.dimmed()
            );
        }
    }

    println!();
    let (color, verb) = match verdict.decision {
        Decision::Vouched => (AnsiColors::Green, "vouches for this package"),
        Decision::Review => (AnsiColors::Yellow, "needs your review before installing"),
        Decision::Refused => (AnsiColors::Red, "refuses to install this package"),
    };
    println!(
        "{} {} {} (risk {}/100)",
        "vouch:".bold(),
        verdict.decision.label().color(color).bold(),
        verb.color(color),
        verdict.score
    );
}

fn severity_color(s: Severity) -> AnsiColors {
    match s {
        Severity::Critical => AnsiColors::Red,
        Severity::High => AnsiColors::BrightRed,
        Severity::Medium => AnsiColors::Yellow,
        Severity::Low => AnsiColors::BrightBlue,
        Severity::Info => AnsiColors::BrightBlack,
    }
}

/// 0 = vouched, 1 = review required, 2 = refused, 3 = error (set by `fail`).
fn exit_code_for(decision: Decision) -> ExitCode {
    match decision {
        Decision::Vouched => ExitCode::from(0),
        Decision::Review => ExitCode::from(1),
        Decision::Refused => ExitCode::from(2),
    }
}
