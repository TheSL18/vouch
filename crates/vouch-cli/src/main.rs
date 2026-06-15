//! `vouch` — a security-first AUR helper.
//!
//! Subcommands:
//! * `audit <pkg>` — fetch a package's AUR metadata + recipe and print a risk
//!   verdict, plus how it relates to what you last vouched for. Read-only.
//! * `build <pkg|dir>` — audit, gate on the verdict *and* on whether the recipe
//!   changed since you last vouched (TOFU), then build inside a network-denied
//!   sandbox. Records your approval. Does not install.
//! * `forget <pkg>` — drop the stored review record for a package.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use owo_colors::{AnsiColors, OwoColorize};
use vouch_core::{Decision, PackageMeta, Severity, Verdict};
use vouch_pkgbuild::SourceBundle;
use vouch_review::{ReviewStatus, ReviewStore, ReviewedFile, render_diff};

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
        /// Proceed past a REVIEW verdict, or accept a changed recipe.
        #[arg(long)]
        yes: bool,
    },
    /// Resolve dependencies, vet every AUR package, build them in order, and
    /// install. Aliased as `-S` in spirit.
    #[command(visible_alias = "i")]
    Install {
        /// One or more AUR package names to install.
        #[arg(required = true)]
        targets: Vec<String>,
        /// Build even if a verdict is REFUSED (strongly discouraged).
        #[arg(long)]
        force: bool,
        /// Proceed past REVIEW verdicts / changed recipes without stopping.
        #[arg(long)]
        yes: bool,
        /// Resolve and vet everything, print the plan, but build/install nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Forget the stored review record for a package (re-arms TOFU for it).
    Forget {
        /// Package name (or local directory name) to forget.
        package: String,
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
        Command::Install {
            targets,
            force,
            yes,
            dry_run,
        } => match install(&targets, force, yes, dry_run) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Forget { package } => match forget(&package) {
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
// audit (read-only)
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
        show_review_status(&meta.package_base, &bundle);
    }
    Ok(verdict)
}

/// Print how the current recipe relates to what the user last vouched for.
/// Read-only: never records anything.
fn show_review_status(key: &str, bundle: &SourceBundle) {
    let Ok(store) = ReviewStore::open_default() else {
        return;
    };
    let files = reviewed_files(bundle);
    match store.status(key, &files) {
        Ok(ReviewStatus::New) => {
            println!("{} not vouched before (new to you)", "review:".bold());
        }
        Ok(ReviewStatus::Unchanged { record }) => {
            println!(
                "{} unchanged since you vouched it {}",
                "review:".bold(),
                human_since(record.approved_at)
            );
        }
        Ok(ReviewStatus::Changed { previous, .. }) => {
            println!(
                "{} {} changed since you vouched it {}",
                "review:".bold(),
                "⚠".yellow().bold(),
                human_since(previous.approved_at)
            );
            print_review_diff(&render_diff(&previous, &files));
        }
        Err(_) => {}
    }
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
    let store = ReviewStore::open_default().context("opening the review store")?;

    let path = Path::new(target);
    let (build_dir, key, bundle, verdict) = if path.is_dir() && path.join("PKGBUILD").is_file() {
        let bundle = vouch_pkgbuild::load_local(path).context("loading local PKGBUILD")?;
        let key = bundle.package_base.clone();
        let verdict = vouch_security::scan_only(&key, &bundle);
        print_findings(&verdict);
        (path.to_path_buf(), key, bundle, verdict)
    } else {
        prepare_aur_build(target, force, yes)?
    };

    // Authoritative gate on exactly what we will build: verdict + TOFU. Records
    // the approval once consent is given.
    gate_with_tofu(&store, &key, &bundle, &verdict, force, yes)?;

    println!("{} building in a network-denied sandbox…", "vouch:".bold());
    let outcome = vouch_build::build_in_sandbox(&build_dir)?;

    println!();
    println!("{} {}", "vouch:".bold(), "build complete".green().bold());
    for p in &outcome.packages {
        println!("  {} {}", "✓".green(), p.display());
    }
    let list = outcome
        .packages
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "  {} review then install with: {}",
        "→".dimmed(),
        format!("sudo pacman -U {list}").dimmed()
    );
    Ok(())
}

/// Fetch + audit an AUR package, refuse early on a clearly bad verdict, then
/// clone the full repo and return what to build (the cloned recipe is what the
/// gate and TOFU then act on — it is exactly what gets built).
fn prepare_aur_build(
    package: &str,
    force: bool,
    yes: bool,
) -> Result<(PathBuf, String, SourceBundle, Verdict)> {
    let meta = vouch_rpc::info(package)
        .context("looking up package on the AUR")?
        .with_context(|| format!("'{package}' is not in the AUR"))?;
    let fetched =
        vouch_pkgbuild::fetch(&meta.package_base).context("fetching the package build recipe")?;
    let verdict = vouch_security::evaluate(&meta, &fetched, now_unix());
    print_meta(&meta);
    print_findings(&verdict);
    // Don't even clone a package we'd refuse to build.
    gate(&verdict, force, yes)?;

    let dest = unique_build_dir(&meta.package_base);
    println!(
        "{} cloning {} …",
        "vouch:".bold(),
        format!("aur/{}", meta.package_base).dimmed()
    );
    vouch_pkgbuild::clone(&meta.package_base, &dest).context("cloning AUR repo")?;

    // Re-scan the cloned recipe — what we actually build — rather than trusting
    // the metadata-time fetch.
    let cloned = vouch_pkgbuild::load_local(&dest).context("loading cloned PKGBUILD")?;
    let cverdict = vouch_security::scan_only(&meta.package_base, &cloned);
    Ok((dest, meta.package_base, cloned, cverdict))
}

/// Combine the static verdict with the TOFU change check, then — on consent —
/// record the approval. This is what makes a legitimate but custom recipe a
/// one-time review: unchanged recipes proceed quietly; changed ones force a
/// fresh look at the diff.
fn gate_with_tofu(
    store: &ReviewStore,
    key: &str,
    bundle: &SourceBundle,
    verdict: &Verdict,
    force: bool,
    yes: bool,
) -> Result<()> {
    let files = reviewed_files(bundle);
    match store.status(key, &files)? {
        ReviewStatus::New => {
            println!(
                "{} first time vouching this recipe (trust-on-first-use)",
                "vouch:".bold()
            );
            gate(verdict, force, yes)?;
        }
        ReviewStatus::Unchanged { record } => {
            println!(
                "{} unchanged since you vouched it {} (risk was {}/100)",
                "vouch:".bold(),
                human_since(record.approved_at),
                record.score_at_approval
            );
            // Even an unchanged recipe is re-checked: a newly-added rule or IoC
            // can move a previously-vouched recipe to REFUSED.
            if verdict.decision == Decision::Refused {
                gate(verdict, force, yes)?;
            }
        }
        ReviewStatus::Changed { previous, .. } => {
            println!(
                "{} {} this recipe CHANGED since you vouched it {}",
                "vouch:".bold(),
                "⚠".yellow().bold(),
                human_since(previous.approved_at)
            );
            print_review_diff(&render_diff(&previous, &files));
            // A change always demands fresh consent, whatever the score.
            if verdict.decision == Decision::Refused {
                gate(verdict, force, yes)?;
            } else if !yes {
                bail!(
                    "recipe changed since your last vouch. Review the diff above, then \
                     re-run with --yes to vouch for the new version."
                );
            }
        }
    }

    // We reached here without bailing → consent given. Record it.
    store
        .approve(key, files, verdict.score, now_unix())
        .context("recording review approval")?;
    Ok(())
}

/// Enforce the static verdict before any build happens.
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

// ----------------------------------------------------------------------------
// install (-S): resolve -> vet every AUR package -> build in order -> pacman
// ----------------------------------------------------------------------------

fn install(targets: &[String], force: bool, yes: bool, dry_run: bool) -> Result<()> {
    let store = ReviewStore::open_default().context("opening the review store")?;
    if !dry_run && !vouch_sandbox::available() {
        bail!(
            "secure build sandbox unavailable (bwrap missing or unprivileged user \
             namespaces disabled). Refusing to build."
        );
    }

    let roots: Vec<&str> = targets.iter().map(String::as_str).collect();
    let plan = vouch_resolve::resolve_many(&roots).context("resolving dependencies")?;
    print_plan(&plan);

    // Vet (and, unless dry-run, build) every AUR package in dependency order.
    // A single REFUSED package aborts the whole operation — dependencies are
    // an attack surface too.
    let mut built: Vec<(String, Vec<PathBuf>)> = Vec::new();
    for name in &plan.aur_build_order {
        println!("\n{} {}", "::".blue().bold(), name.bold());
        if dry_run {
            dry_run_vet(name)?;
            continue;
        }
        let (dest, key, bundle, verdict) = prepare_aur_build(name, force, yes)?;
        gate_with_tofu(&store, &key, &bundle, &verdict, force, yes)?;
        let outcome = vouch_build::build_in_sandbox(&dest)?;
        built.push((name.clone(), outcome.packages));
    }

    if dry_run {
        println!(
            "\n{} dry run — nothing built or installed.",
            "vouch:".bold()
        );
        print_pacman_plan(&plan);
        return Ok(());
    }

    pacman_install(&plan, &built, yes)
}

/// Print the resolved plan up front so the user sees the whole blast radius.
fn print_plan(plan: &vouch_resolve::ResolvedPlan) {
    println!("{} resolution", "vouch:".bold());
    println!(
        "  AUR packages to build ({}, in order): {}",
        plan.aur_build_order.len(),
        plan.aur_build_order.join(" → ").bold()
    );
    if !plan.repo_deps.is_empty() {
        println!(
            "  repo dependencies (pacman will resolve): {}",
            plan.repo_deps.join(" ").dimmed()
        );
    }
}

/// Read-only vet of one AUR package for `--dry-run`: verdict + TOFU status,
/// and what the gate would decide — without cloning, building or recording.
fn dry_run_vet(name: &str) -> Result<()> {
    let meta = vouch_rpc::info(name)
        .context("looking up package on the AUR")?
        .with_context(|| format!("'{name}' is not in the AUR"))?;
    let bundle =
        vouch_pkgbuild::fetch(&meta.package_base).context("fetching the package build recipe")?;
    let verdict = vouch_security::evaluate(&meta, &bundle, now_unix());
    print_meta(&meta);
    print_findings(&verdict);
    show_review_status(&meta.package_base, &bundle);
    let would = match verdict.decision {
        Decision::Vouched => "would build".green().to_string(),
        Decision::Review => "would require --yes".yellow().to_string(),
        Decision::Refused => "would be REFUSED (needs --force)".red().to_string(),
    };
    println!("  {} {would}", "→".dimmed());
    Ok(())
}

/// Print the exact pacman commands an install would run.
fn print_pacman_plan(plan: &vouch_resolve::ResolvedPlan) {
    let sudo = if is_root() { "" } else { "sudo " };
    println!(
        "  {} {sudo}pacman -U --asdeps <built AUR dependencies>",
        "would run:".dimmed()
    );
    println!(
        "  {} {sudo}pacman -U <built {}>",
        "would run:".dimmed(),
        plan.explicit_targets.join(", ")
    );
    println!(
        "  {}",
        "(pacman resolves and installs the repo dependencies listed above)".dimmed()
    );
}

/// Install the built packages with pacman: dependencies as `--asdeps`, the
/// explicitly-requested targets as explicit. pacman pulls repo deps itself.
fn pacman_install(
    plan: &vouch_resolve::ResolvedPlan,
    built: &[(String, Vec<PathBuf>)],
    yes: bool,
) -> Result<()> {
    let mut dep_pkgs: Vec<&PathBuf> = Vec::new();
    let mut explicit_pkgs: Vec<&PathBuf> = Vec::new();
    for (name, pkgs) in built {
        if plan.explicit_targets.contains(name) {
            explicit_pkgs.extend(pkgs.iter());
        } else {
            dep_pkgs.extend(pkgs.iter());
        }
    }

    println!("\n{} ready to install:", "vouch:".bold());
    if !dep_pkgs.is_empty() {
        println!(
            "  dependencies (--asdeps): {}",
            join_paths(&dep_pkgs).dimmed()
        );
    }
    println!("  targets: {}", join_paths(&explicit_pkgs).bold());

    if !yes && !confirm("Proceed with pacman installation?")? {
        bail!("installation cancelled by user");
    }

    if !dep_pkgs.is_empty() {
        run_pacman(&["-U", "--asdeps", "--needed"], &dep_pkgs)?;
    }
    if !explicit_pkgs.is_empty() {
        run_pacman(&["-U", "--needed"], &explicit_pkgs)?;
    }
    println!(
        "{} {}",
        "vouch:".bold(),
        "installation complete".green().bold()
    );
    Ok(())
}

fn run_pacman(args: &[&str], pkgs: &[&PathBuf]) -> Result<()> {
    let (program, lead): (&str, &[&str]) = if is_root() {
        ("pacman", &[])
    } else {
        ("sudo", &["pacman"])
    };
    let mut cmd = std::process::Command::new(program);
    cmd.args(lead)
        .args(args)
        .args(pkgs.iter().map(|p| p.as_os_str()));
    let status = cmd.status().context("running pacman")?;
    if !status.success() {
        bail!("pacman exited with failure");
    }
    Ok(())
}

/// Best-effort euid check without pulling in libc: read `/proc/self/status`.
/// If we can't tell, assume non-root and prefix `sudo` (the safe default).
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
        })
        .map(|euid| euid == "0")
        .unwrap_or(false)
}

fn join_paths(pkgs: &[&PathBuf]) -> String {
    pkgs.iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt} [y/N] ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

// ----------------------------------------------------------------------------
// forget
// ----------------------------------------------------------------------------

fn forget(package: &str) -> Result<()> {
    let store = ReviewStore::open_default().context("opening the review store")?;
    if store.forget(package)? {
        println!("{} forgot review record for {package}", "vouch:".bold());
    } else {
        println!("{} no review record for {package}", "vouch:".bold());
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// presentation
// ----------------------------------------------------------------------------

fn reviewed_files(bundle: &SourceBundle) -> Vec<ReviewedFile> {
    bundle
        .files()
        .map(|(name, content)| ReviewedFile::new(name, content))
        .collect()
}

fn human_since(ts: i64) -> String {
    let days = (now_unix() - ts).max(0) / 86_400;
    match days {
        0 => "today".to_string(),
        1 => "yesterday".to_string(),
        n => format!("{n} days ago"),
    }
}

fn print_review_diff(diff: &str) {
    for line in diff.lines() {
        if let Some(name) = line.strip_prefix("--- ") {
            println!("    {} {}", "in".dimmed(), name.bold());
        } else if line.starts_with('+') {
            println!("    {}", line.green());
        } else if line.starts_with('-') {
            println!("    {}", line.red());
        } else {
            println!("    {}", line.dimmed());
        }
    }
}

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
        // Group repeated hits of the same rule into one line (with all the
        // locations) so the report mirrors how the score counts them.
        let mut groups: Vec<(&vouch_core::Finding, Vec<String>)> = Vec::new();
        for f in &verdict.findings {
            if let Some(g) = groups.iter_mut().find(|(rep, _)| rep.id == f.id) {
                g.1.extend(f.location.clone());
            } else {
                groups.push((f, f.location.clone().into_iter().collect()));
            }
        }
        for (f, locs) in groups {
            let mark = match f.severity {
                Severity::Critical | Severity::High => "✗",
                Severity::Medium => "!",
                _ => "·",
            };
            let loc = match locs.len() {
                0 => String::new(),
                1 => format!(" [{}]", locs[0]),
                n => format!(" [{n} places: {}]", locs.join(", ")),
            };
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

fn unique_build_dir(base: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("vouch-build-{base}-{stamp}"))
}

/// 0 = vouched, 1 = review required, 2 = refused, 3 = error (set by `fail`).
fn exit_code_for(decision: Decision) -> ExitCode {
    match decision {
        Decision::Vouched => ExitCode::from(0),
        Decision::Review => ExitCode::from(1),
        Decision::Refused => ExitCode::from(2),
    }
}
