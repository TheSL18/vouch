//! `vouch` — a security-first AUR helper.
//!
//! Subcommands:
//! * `audit <pkg>` — fetch a package's AUR metadata + recipe and print a risk
//!   verdict, plus how it relates to what you last vouched for. Read-only.
//! * `build <pkg|dir>` — audit, gate on the verdict *and* on whether the recipe
//!   changed since you last vouched (TOFU), then build inside a network-denied
//!   sandbox. Records your approval. Does not install.
//! * `install <pkg…>` — resolve the AUR dependency graph, vet every package,
//!   build in order, and install with pacman. `--dry-run` plans only.
//! * `upgrade` — rebuild installed AUR packages with newer AUR versions.
//! * `forget <pkg>` — drop the stored review record for a package.
//! * `ioc` — show / import indicators-of-compromise feeds.

mod compat;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use owo_colors::{AnsiColors, OwoColorize};
use vouch_core::{Decision, PackageMeta, Severity, Verdict};
use vouch_pkgbuild::SourceBundle;
use vouch_review::{ReviewStatus, ReviewStore, ReviewedFile, render_diff};

#[derive(Parser)]
#[command(
    name = "vouch",
    version,
    about = "A security-first AUR helper that vouches for packages before it installs them.",
    after_help = PACMAN_STYLE_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Shown at the end of `vouch --help`, since the pacman-style front-end is
/// handled before clap and wouldn't otherwise appear.
const PACMAN_STYLE_HELP: &str = "\
Pacman-style syntax (also accepted, like yay/paru):
  vouch -Syu              Full upgrade: repos via pacman, then the AUR
  vouch -S <pkg...>       Install (repo targets -> pacman, AUR targets -> vouch)
  vouch -Ss <query>       Search repos and the AUR
  vouch -Sy               Refresh the sync databases
  vouch -R/-Q/-U/... <..> Handed straight to pacman

Both styles work; use whichever you prefer.";

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
        /// Allow this package's build phase to access the network (for recipes
        /// that genuinely fetch at build time, e.g. electron/npm). Per-package
        /// and remembered for the unchanged recipe; reduces build isolation.
        #[arg(long)]
        allow_build_network: bool,
        /// Build without the isolation sandbox (for recipes needing FUSE/unionfs,
        /// e.g. some flutter/electron packages). The package is still vetted.
        #[arg(long)]
        no_sandbox: bool,
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
        /// Allow the build phase of these packages to access the network
        /// (electron/npm-style recipes). Applies to every package in this run.
        #[arg(long)]
        allow_build_network: bool,
        /// After installing, remove build-only dependencies that are no longer
        /// needed (`pacman -Rns`).
        #[arg(long)]
        rmdeps: bool,
        /// Build without the isolation sandbox (for recipes needing FUSE/unionfs).
        #[arg(long)]
        no_sandbox: bool,
    },
    /// Upgrade installed AUR packages whose AUR version is newer (like `-Syu`
    /// for the AUR layer). Vets and rebuilds each in the sandbox before install.
    #[command(visible_alias = "u")]
    Upgrade {
        /// Build even if a verdict is REFUSED (strongly discouraged).
        #[arg(long)]
        force: bool,
        /// Proceed past REVIEW verdicts / changed recipes without stopping.
        #[arg(long)]
        yes: bool,
        /// Only list what would be upgraded; build/install nothing.
        #[arg(long)]
        dry_run: bool,
        /// Allow the build phase to access the network (electron/npm recipes).
        #[arg(long)]
        allow_build_network: bool,
        /// After installing, remove build-only dependencies that are no longer
        /// needed (`pacman -Rns`).
        #[arg(long)]
        rmdeps: bool,
        /// Skip checking VCS packages (`-git`, `-svn`, …) for new upstream
        /// commits. By default they are checked (a `git ls-remote` each).
        #[arg(long)]
        no_devel: bool,
        /// Build without the isolation sandbox (for recipes needing FUSE/unionfs).
        #[arg(long)]
        no_sandbox: bool,
    },
    /// Forget the stored review record for a package (re-arms TOFU for it).
    Forget {
        /// Package name (or local directory name) to forget.
        package: String,
    },
    /// Search the AUR by name and description.
    #[command(visible_alias = "s")]
    Search {
        /// Search terms.
        #[arg(required = true)]
        query: Vec<String>,
    },
    /// Show loaded indicators of compromise, or import a feed.
    Ioc {
        /// Import and merge a JSON IoC feed (e.g. a community list) into your
        /// local indicators.
        #[arg(long, value_name = "FILE")]
        import: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    // Accept pacman-style invocations (`vouch -Syu`, `-S pkg`, `-Ss query`, …)
    // alongside vouch's own subcommands. -h/-V still go to clap.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().is_some_and(|a| {
        a.starts_with('-') && !matches!(a.as_str(), "-h" | "--help" | "-V" | "--version")
    }) {
        return run_pacman_style(&raw);
    }

    let cli = Cli::parse();
    match cli.command {
        Command::Audit { package, json } => match audit(&package, json) {
            Ok(verdict) => exit_code_for(verdict.decision),
            Err(e) => fail(e),
        },
        Command::Build {
            target,
            force,
            yes,
            allow_build_network,
            no_sandbox,
        } => match build(&target, force, yes, allow_build_network, no_sandbox) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Install {
            targets,
            force,
            yes,
            dry_run,
            allow_build_network,
            rmdeps,
            no_sandbox,
        } => match install(
            &targets,
            force,
            yes,
            dry_run,
            allow_build_network,
            rmdeps,
            no_sandbox,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Upgrade {
            force,
            yes,
            dry_run,
            allow_build_network,
            rmdeps,
            no_devel,
            no_sandbox,
        } => match upgrade(
            force,
            yes,
            dry_run,
            allow_build_network,
            rmdeps,
            !no_devel,
            no_sandbox,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Forget { package } => match forget(&package) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Search { query } => match search(&query.join(" ")) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Ioc { import } => match ioc(import.as_deref()) {
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
// pacman-style front-end (so `vouch -Syu` etc. work like yay/paru)
// ----------------------------------------------------------------------------

fn run_pacman_style(raw: &[String]) -> ExitCode {
    let res = match compat::parse(raw) {
        compat::Action::FullUpgrade { targets, noconfirm } => full_upgrade(&targets, noconfirm),
        compat::Action::Install { targets, noconfirm } => install_targets(&targets, noconfirm),
        compat::Action::Search { query } => {
            // Repo matches first (read-only pacman), then the AUR via vouch.
            let mut a = vec!["-Ss".to_string()];
            a.extend(query.iter().cloned());
            let _ = run_pacman_raw(&a, false);
            search(&query.join(" "))
        }
        compat::Action::Refresh { noconfirm } => {
            let mut a = vec!["-Sy".to_string()];
            if noconfirm {
                a.push("--noconfirm".into());
            }
            run_pacman_raw(&a, true)
        }
        compat::Action::Passthrough { sudo } => run_pacman_raw(raw, sudo),
        compat::Action::Unsupported(msg) => Err(anyhow!(
            "{msg}. For AUR operations use vouch's subcommands \
             (e.g. `vouch install <pkg>`, `vouch upgrade`, `vouch search <q>`)."
        )),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

/// `-Syu`: upgrade the repos with pacman, then the AUR layer with vouch, then
/// install any extra targets.
fn full_upgrade(targets: &[String], noconfirm: bool) -> Result<()> {
    let mut a = vec!["-Syu".to_string()];
    if noconfirm {
        a.push("--noconfirm".into());
    }
    println!("{} upgrading repo packages…", "vouch:".bright_cyan().bold());
    run_pacman_raw(&a, true)?;

    println!("{} upgrading AUR packages…", "vouch:".bright_cyan().bold());
    // -Syu is a full upgrade, so include VCS/devel packages by default.
    upgrade(false, noconfirm, false, false, false, true, false)?;

    if !targets.is_empty() {
        install_targets(targets, noconfirm)?;
    }
    Ok(())
}

/// `-S <targets>`: repo targets go to pacman, AUR targets through vouch's
/// vetted install pipeline.
fn install_targets(targets: &[String], noconfirm: bool) -> Result<()> {
    let (repo, aur) = classify_targets(targets);
    if !repo.is_empty() {
        println!(
            "{} installing repo packages: {}",
            "vouch:".bright_cyan().bold(),
            repo.join(" ").dimmed()
        );
        let mut a = vec!["-S".to_string()];
        if noconfirm {
            a.push("--noconfirm".into());
        }
        a.extend(repo);
        run_pacman_raw(&a, true)?;
    }
    if !aur.is_empty() {
        install(&aur, false, noconfirm, false, false, false, false)?;
    }
    Ok(())
}

/// Split install targets into (repo, AUR): a target a configured repo can
/// satisfy goes to pacman; otherwise, if it's an AUR package, to vouch; an
/// unknown name is left to pacman to report.
fn classify_targets(targets: &[String]) -> (Vec<String>, Vec<String>) {
    let db = vouch_alpm::Db::open().ok();
    let mut repo = Vec::new();
    let mut aur = Vec::new();
    for t in targets {
        if db.as_ref().is_some_and(|d| d.repo_satisfies(t)) {
            repo.push(t.clone());
        } else if vouch_rpc::info(t).ok().flatten().is_some() {
            aur.push(t.clone());
        } else {
            repo.push(t.clone());
        }
    }
    (repo, aur)
}

/// Run `pacman` (via `sudo` unless we're root, or directly for read-only ops)
/// with the given arguments.
fn run_pacman_raw(args: &[String], sudo: bool) -> Result<()> {
    let mut cmd = if sudo {
        pacman_cmd()
    } else {
        std::process::Command::new("pacman")
    };
    cmd.args(args);
    let status = cmd.status().context("running pacman")?;
    if !status.success() {
        bail!("pacman exited with failure");
    }
    Ok(())
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
            println!(
                "{} not vouched before (new to you)",
                "review:".bright_blue().bold()
            );
        }
        Ok(ReviewStatus::Unchanged { record }) => {
            println!(
                "{} unchanged since you vouched it {}",
                "review:".bright_blue().bold(),
                human_since(record.approved_at)
            );
        }
        Ok(ReviewStatus::Changed { previous, .. }) => {
            println!(
                "{} {} changed since you vouched it {}",
                "review:".bright_blue().bold(),
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

fn build(target: &str, force: bool, yes: bool, allow_net: bool, no_sandbox: bool) -> Result<()> {
    require_sandbox(no_sandbox)?;
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
    // the approval once consent is given, and resolves the effective
    // build-network decision (flag this run, or remembered from last vouch).
    let build_network = gate_with_tofu(&store, &key, &bundle, &verdict, force, yes, allow_net)?;

    let outcome = build_one(&build_dir, build_network, no_sandbox)?;

    println!();
    println!(
        "{} {}",
        "vouch:".bright_cyan().bold(),
        "build complete".green().bold()
    );
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
        "vouch:".bright_cyan().bold(),
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
    allow_net: bool,
) -> Result<bool> {
    let files = reviewed_files(bundle);
    // Network is allowed if requested this run, or remembered from the last
    // approval of this *unchanged* recipe.
    let mut build_network = allow_net;
    match store.status(key, &files)? {
        ReviewStatus::New => {
            println!(
                "{} first time vouching this recipe (trust-on-first-use)",
                "vouch:".bright_cyan().bold()
            );
            gate(verdict, force, yes)?;
        }
        ReviewStatus::Unchanged { record } => {
            println!(
                "{} unchanged since you vouched it {} (risk was {}/100)",
                "vouch:".bright_cyan().bold(),
                human_since(record.approved_at),
                record.score_at_approval
            );
            build_network = build_network || record.build_network;
            // Even an unchanged recipe is re-checked: a newly-added rule or IoC
            // can move a previously-vouched recipe to REFUSED.
            if verdict.decision == Decision::Refused {
                gate(verdict, force, yes)?;
            }
        }
        ReviewStatus::Changed { previous, .. } => {
            println!(
                "{} {} this recipe CHANGED since you vouched it {}",
                "vouch:".bright_cyan().bold(),
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
        .approve(key, files, verdict.score, now_unix(), build_network)
        .context("recording review approval")?;
    Ok(build_network)
}

/// Announce the build phase, making reduced isolation impossible to miss.
fn announce_build(build_network: bool) {
    if build_network {
        println!(
            "{} building with {} (reduced isolation — recipe is still vetted)",
            "vouch:".bright_cyan().bold(),
            "NETWORK ACCESS".yellow().bold()
        );
    } else {
        println!(
            "{} building in a network-denied sandbox…",
            "vouch:".bright_cyan().bold()
        );
    }
}

/// Unless `no_sandbox`, fail if no working build sandbox is available — vouch
/// never silently builds unsandboxed.
fn require_sandbox(no_sandbox: bool) -> Result<()> {
    if !no_sandbox && !vouch_sandbox::available() {
        bail!(
            "secure build sandbox unavailable (bwrap missing or unprivileged user \
             namespaces disabled). Refusing to build. Pass --no-sandbox to build \
             without isolation (the recipe is still vetted)."
        );
    }
    Ok(())
}

/// Build one package, honouring the sandbox choice. With `no_sandbox` it builds
/// unconfined (an explicit opt-out, loudly announced); otherwise in the
/// network-denied sandbox.
fn build_one(
    dir: &Path,
    build_network: bool,
    no_sandbox: bool,
) -> Result<vouch_build::BuildOutcome> {
    if no_sandbox {
        println!(
            "{} building {} (recipe is still vetted, but build/install code runs unconfined)",
            "vouch:".bright_cyan().bold(),
            "WITHOUT SANDBOX".red().bold()
        );
        vouch_build::build_unsandboxed(dir)
    } else {
        announce_build(build_network);
        vouch_build::build_in_sandbox(dir, build_network)
    }
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

#[allow(clippy::too_many_arguments)]
fn install(
    targets: &[String],
    force: bool,
    yes: bool,
    dry_run: bool,
    allow_net: bool,
    rmdeps: bool,
    no_sandbox: bool,
) -> Result<()> {
    let store = ReviewStore::open_default().context("opening the review store")?;
    if !dry_run {
        require_sandbox(no_sandbox)?;
    }

    let roots: Vec<&str> = targets.iter().map(String::as_str).collect();
    let plan = vouch_resolve::resolve_many(&roots).context("resolving dependencies")?;
    print_plan(&plan);

    if dry_run {
        for name in &plan.aur_build_order {
            println!("\n{} {}", "::".bright_blue().bold(), name.bold());
            dry_run_vet(name)?;
        }
        println!(
            "\n{} dry run — nothing built or installed.",
            "vouch:".bright_cyan().bold()
        );
        print_pacman_plan(&plan);
        if rmdeps && !plan.make_only_deps.is_empty() {
            let sudo = if is_root() { "" } else { "sudo " };
            println!(
                "  {} {sudo}pacman -Rns {} (build-only deps, if unneeded)",
                "would run:".dimmed(),
                plan.make_only_deps.join(" ")
            );
        }
        return Ok(());
    }

    // One consent up front, after the full plan is on screen. Everything below
    // runs pacman via sudo.
    if !yes
        && !confirm(&format!(
            "Proceed to build & install {} AUR package(s) (runs pacman via sudo)?",
            plan.aur_build_order.len()
        ))?
    {
        bail!("cancelled by user");
    }

    // 1. Install repo dependencies up front so each sandboxed makepkg can find
    //    its declared deps (we never let makepkg fetch them itself).
    if !plan.repo_deps.is_empty() {
        let deps: Vec<&str> = plan.repo_deps.iter().map(String::as_str).collect();
        pacman_sync(&deps)?;
    }

    // 2. Build and install one dependency layer at a time. Packages within a
    //    layer are independent, so they build in parallel; the layer is then
    //    installed serially, so the next layer's makepkg checks find their AUR
    //    deps present. Every package is vetted (serially, in order) before any
    //    building starts.
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    for layer in &plan.layers {
        // Vet + gate each package serially (clean, ordered output + approval),
        // collecting the build jobs as (name, build-dir, allow-network).
        let mut jobs: Vec<(String, PathBuf, bool)> = Vec::with_capacity(layer.len());
        for name in layer {
            println!("\n{} {}", "::".bright_blue().bold(), name.bold());
            let (dest, key, bundle, verdict) = prepare_aur_build(name, force, yes)?;
            let build_network =
                gate_with_tofu(&store, &key, &bundle, &verdict, force, yes, allow_net)?;
            jobs.push((name.clone(), dest, build_network));
        }

        if no_sandbox || jobs.len() == 1 {
            // Single package, or unsandboxed builds: run them serially with
            // live output (unsandboxed builds can't be cleanly parallelized).
            for (name, dir, net) in &jobs {
                let outcome = build_one(dir, *net, no_sandbox)?;
                pacman_install_file(&outcome.packages, !plan.explicit_targets.contains(name))?;
                record_devel(name, dir);
            }
        } else {
            build_layer_parallel(&jobs, &plan.explicit_targets, parallelism)?;
        }
    }

    println!(
        "\n{} {}",
        "vouch:".bright_cyan().bold(),
        "installation complete".green().bold()
    );

    // Optionally clean up build-only dependencies that nothing needs now.
    if rmdeps {
        remove_unneeded_make_deps(&plan.make_only_deps)?;
    }
    Ok(())
}

/// Remove build-only dependencies that are now unrequired (`pacman -Rns`).
/// Best-effort: skips anything still needed and never fails the install.
fn remove_unneeded_make_deps(make_only: &[String]) -> Result<()> {
    if make_only.is_empty() {
        return Ok(());
    }
    // Re-open ALPM so it reflects everything just installed.
    let Ok(db) = vouch_alpm::Db::open() else {
        return Ok(());
    };
    let removable: Vec<&str> = make_only
        .iter()
        .filter(|n| db.is_unrequired(n))
        .map(String::as_str)
        .collect();
    if removable.is_empty() {
        return Ok(());
    }
    println!(
        "{} removing build-only dependencies: {}",
        "vouch:".bright_cyan().bold(),
        removable.join(" ").dimmed()
    );
    let status = pacman_cmd()
        .args(["-Rns", "--noconfirm"])
        .args(&removable)
        .status()
        .context("running pacman -Rns")?;
    if !status.success() {
        eprintln!(
            "{} could not remove some build-only dependencies (still in use?)",
            "warning:".yellow().bold()
        );
    }
    Ok(())
}

/// Build every job in a layer concurrently (bounded by `parallelism`), then
/// print each build's captured log and install it — in the layer's order.
fn build_layer_parallel(
    jobs: &[(String, PathBuf, bool)],
    explicit_targets: &[String],
    parallelism: usize,
) -> Result<()> {
    println!(
        "\n{} building {} packages in parallel…",
        "vouch:".bright_cyan().bold(),
        jobs.len()
    );

    for chunk in jobs.chunks(parallelism.max(1)) {
        // Each job builds in its own temp dir and only reads shared state
        // (the read-only pacman db), so concurrent builds don't conflict.
        let results: Vec<Result<(Vec<PathBuf>, String)>> = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|(_, dir, net)| {
                    scope.spawn(|| vouch_build::build_in_sandbox_captured(dir, *net))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| match h.join() {
                    Ok(res) => res.map(|(outcome, log)| (outcome.packages, log)),
                    Err(_) => Err(anyhow::anyhow!("build thread panicked")),
                })
                .collect()
        });

        // Replay logs and install in order so output stays readable.
        for ((name, dir, _), result) in chunk.iter().zip(results) {
            let (packages, log) = result.with_context(|| format!("building {name}"))?;
            print!("{log}");
            println!(
                "{} {} {}",
                "vouch:".bright_cyan().bold(),
                "built".green(),
                name.bold()
            );
            pacman_install_file(&packages, !explicit_targets.contains(name))?;
            record_devel(name, dir);
        }
    }
    Ok(())
}

/// Print the resolved plan up front so the user sees the whole blast radius.
fn print_plan(plan: &vouch_resolve::ResolvedPlan) {
    println!("{} resolution", "vouch:".bright_cyan().bold());
    println!(
        "  AUR packages to build ({}, in order): {}",
        plan.aur_build_order.len().to_string().bright_yellow(),
        plan.aur_build_order.join(" → ").bright_cyan().bold()
    );
    if plan.layers.iter().any(|l| l.len() > 1) {
        let shown = plan
            .layers
            .iter()
            .map(|l| format!("[{}]", l.join(", ")))
            .collect::<Vec<_>>()
            .join(" → ");
        println!("  parallel build layers: {}", shown.dimmed());
    }
    if !plan.repo_deps.is_empty() {
        println!(
            "  repo dependencies (installed via pacman -S): {}",
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
    if !plan.repo_deps.is_empty() {
        println!(
            "  {} {sudo}pacman -S --asdeps --needed {}",
            "would run:".dimmed(),
            plan.repo_deps.join(" ")
        );
    }
    for name in &plan.aur_build_order {
        let asdeps = if plan.explicit_targets.contains(name) {
            ""
        } else {
            "--asdeps "
        };
        println!(
            "  {} {sudo}pacman -U {asdeps}<built {name}>",
            "would run:".dimmed()
        );
    }
}

/// A `pacman` command, prefixed with `sudo` unless we're already root.
fn pacman_cmd() -> std::process::Command {
    if is_root() {
        std::process::Command::new("pacman")
    } else {
        let mut c = std::process::Command::new("sudo");
        c.arg("pacman");
        c
    }
}

/// Install repo dependencies as dependencies (`pacman -S --asdeps --needed`).
fn pacman_sync(names: &[&str]) -> Result<()> {
    println!(
        "{} installing repo dependencies: {}",
        "vouch:".bright_cyan().bold(),
        names.join(" ").dimmed()
    );
    let status = pacman_cmd()
        .args(["-S", "--asdeps", "--needed", "--noconfirm"])
        .args(names)
        .status()
        .context("running pacman -S")?;
    if !status.success() {
        bail!("pacman failed to install repo dependencies");
    }
    Ok(())
}

/// Install built `*.pkg.tar.*` files (`pacman -U`). Dependencies are installed
/// `--asdeps`; explicit targets as explicit.
fn pacman_install_file(pkgs: &[PathBuf], as_dep: bool) -> Result<()> {
    if pkgs.is_empty() {
        return Ok(());
    }
    let mut cmd = pacman_cmd();
    cmd.args(["-U", "--needed", "--noconfirm"]);
    if as_dep {
        cmd.arg("--asdeps");
    }
    cmd.args(pkgs.iter().map(|p| p.as_os_str()));
    let status = cmd.status().context("running pacman -U")?;
    if !status.success() {
        bail!("pacman failed to install the built package");
    }
    Ok(())
}

/// After installing a package, record the upstream commits it was built against
/// if its recipe has VCS sources, so a later `vouch upgrade --devel` can tell
/// when upstream moves — even for release-versioned devel packages that carry
/// no `-git` suffix. Best-effort: never fails the install.
fn record_devel(package: &str, build_dir: &Path) {
    let Ok(pkgbuild) = std::fs::read_to_string(build_dir.join("PKGBUILD")) else {
        return;
    };
    if !vouch_devel::has_vcs_sources(&pkgbuild) {
        return;
    }
    let sources = vouch_devel::resolve_current(&pkgbuild);
    if sources.is_empty() {
        return;
    }
    if let Ok(mut db) = vouch_devel::DevelDb::open_default() {
        let _ = db.record(package, sources, now_unix());
    }
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
// upgrade (-Syu for the AUR layer)
// ----------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn upgrade(
    force: bool,
    yes: bool,
    dry_run: bool,
    allow_net: bool,
    rmdeps: bool,
    devel: bool,
    no_sandbox: bool,
) -> Result<()> {
    let mut upgrades = vouch_resolve::find_upgrades().context("checking for AUR upgrades")?;
    if devel {
        println!(
            "{} checking VCS packages for new commits…",
            "vouch:".bright_cyan().bold()
        );
        let dev = vouch_resolve::find_devel_upgrades().context("checking devel upgrades")?;
        // Merge, skipping any already found by version comparison.
        for u in dev {
            if !upgrades.iter().any(|e| e.name == u.name) {
                upgrades.push(u);
            }
        }
        upgrades.sort_by(|a, b| a.name.cmp(&b.name));
    }

    if upgrades.is_empty() {
        println!(
            "{} all AUR packages are up to date",
            "vouch:".bright_cyan().bold()
        );
        return Ok(());
    }

    println!(
        "{} {} AUR upgrade(s) available:",
        "vouch:".bright_cyan().bold(),
        upgrades.len()
    );
    for u in &upgrades {
        println!(
            "  {} {} {} {}",
            u.name.bold(),
            u.installed.dimmed(),
            "→".dimmed(),
            u.available.green()
        );
    }
    println!();

    let targets: Vec<String> = upgrades.into_iter().map(|u| u.name).collect();
    install(&targets, force, yes, dry_run, allow_net, rmdeps, no_sandbox)
}

// ----------------------------------------------------------------------------
// search
// ----------------------------------------------------------------------------

fn search(query: &str) -> Result<()> {
    let mut results = vouch_rpc::search(query).context("searching the AUR")?;
    if results.is_empty() {
        println!(
            "{} no AUR packages match {query:?}",
            "vouch:".bright_cyan().bold()
        );
        return Ok(());
    }
    // Most-voted first, then by popularity.
    results.sort_by(|a, b| {
        b.num_votes.cmp(&a.num_votes).then(
            b.popularity
                .partial_cmp(&a.popularity)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    let alpm = vouch_alpm::Db::open().ok();
    const LIMIT: usize = 50;
    let total = results.len();
    for p in results.into_iter().take(LIMIT) {
        let ood = if p.out_of_date.is_some() {
            " [out-of-date]".red().to_string()
        } else {
            String::new()
        };
        let installed = alpm
            .as_ref()
            .and_then(|a| a.installed_version(&p.name))
            .map(|v| format!(" [installed: {v}]").yellow().to_string())
            .unwrap_or_default();
        println!(
            "{}/{} {}  ({}, {:.2}){}{}",
            "aur".blue(),
            p.name.bold(),
            p.version.green(),
            format!("+{}", p.num_votes).dimmed(),
            p.popularity,
            ood,
            installed
        );
        if let Some(d) = &p.description {
            println!("    {d}");
        }
    }
    if total > LIMIT {
        println!("  {} {} more results", "…".dimmed(), total - LIMIT);
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// ioc
// ----------------------------------------------------------------------------

fn ioc(import: Option<&Path>) -> Result<()> {
    if let Some(path) = import {
        let total = vouch_ioc::import_feed(path).context("importing IoC feed")?;
        let dest = vouch_ioc::user_feed_path()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        println!(
            "{} imported feed — {total} indicators now in {}",
            "vouch:".bright_cyan().bold(),
            dest.dimmed()
        );
        return Ok(());
    }

    let ind = vouch_ioc::Indicators::load_default();
    println!(
        "{} indicators of compromise loaded:",
        "vouch:".bright_cyan().bold()
    );
    println!("  bad package names: {}", ind.bad_package_names.len());
    println!("  bad maintainers:   {}", ind.bad_maintainers.len());
    println!("  bad strings:       {}", ind.bad_strings.len());
    println!("  bad sha256 hashes: {}", ind.bad_sha256.len());
    if let Some(path) = vouch_ioc::user_feed_path() {
        let state = if path.exists() {
            "loaded"
        } else {
            "not present"
        };
        println!(
            "  user feed: {} ({state})",
            path.display().to_string().dimmed()
        );
        println!(
            "  {} import community lists with: {}",
            "→".dimmed(),
            "vouch ioc --import <file.json>".dimmed()
        );
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// forget
// ----------------------------------------------------------------------------

fn forget(package: &str) -> Result<()> {
    let store = ReviewStore::open_default().context("opening the review store")?;
    let had_review = store.forget(package)?;

    // Also drop any devel-tracking so the package is treated as fresh.
    let had_devel = match vouch_devel::DevelDb::open_default() {
        Ok(mut db) => db.forget(package).unwrap_or(false),
        Err(_) => false,
    };

    if had_review || had_devel {
        println!(
            "{} forgot saved state for {package}",
            "vouch:".bright_cyan().bold()
        );
    } else {
        println!(
            "{} no saved state for {package}",
            "vouch:".bright_cyan().bold()
        );
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
        "{} {} {} {}",
        "vouch:".bright_cyan().bold(),
        "vetting".dimmed(),
        meta.name.bright_cyan().bold(),
        meta.version.green()
    );
    let maint = meta.maintainer.as_deref().unwrap_or("(orphaned)");
    println!(
        "  maintainer: {maint}   votes: {}   popularity: {:.2}",
        meta.num_votes, meta.popularity
    );
    if let Some(installed) = installed_version(&meta.name) {
        println!("  {} currently installed: {installed}", "•".dimmed());
    }
    println!();
}

/// The installed version of `name`, via libalpm (best-effort).
fn installed_version(name: &str) -> Option<String> {
    vouch_alpm::Db::open()
        .ok()
        .and_then(|db| db.installed_version(name))
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
        "vouch:".bright_cyan().bold(),
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
