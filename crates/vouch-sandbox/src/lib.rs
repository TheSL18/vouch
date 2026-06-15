//! A hardened, unprivileged build sandbox built on [bubblewrap](https://github.com/containers/bubblewrap).
//!
//! This is `vouch`'s runtime enforcement layer. The static scanner ([`vouch-security`])
//! is advisory — it can be fooled by obfuscation. The sandbox is not: even if a
//! malicious `PKGBUILD` slips a `npm install` or `curl | bash` into `build()`,
//! with the network unshared there is simply **no route off the machine** to
//! fetch the payload. That is exactly the link "Atomic Arch" depended on.
//!
//! Guarantees provided by [`Sandbox::run`] (all verified by the test suite):
//!   * **No network** by default (`--unshare-net`); only an isolated loopback exists.
//!   * **Read-only system**: `/usr` and `/etc` are bind-mounted read-only; writes
//!     outside the work directory fail.
//!   * **Writable work directory only**: the build dir is the single rw mount.
//!   * **Namespace isolation**: user/pid/ipc/uts/cgroup namespaces are unshared,
//!     a fresh session prevents terminal-injection (TIOCSTI), and the sandbox
//!     dies with its parent.
//!   * **Clean environment**: the child starts from an empty env with only an
//!     explicit allow-list.
//!
//! Security posture: if the sandbox cannot be established, callers must **refuse
//! to build** rather than silently fall back to an unsandboxed build. See
//! [`available`].

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, bail};

const BWRAP: &str = "bwrap";

/// An isolated execution environment for a single command (typically `makepkg`).
#[derive(Debug, Clone)]
pub struct Sandbox {
    /// The only read-write directory inside the sandbox.
    workdir: PathBuf,
    /// Whether the network namespace is shared with the host. Default: `false`.
    allow_network: bool,
    /// Extra paths to expose read-only (e.g. a pacman cache).
    ro_binds: Vec<PathBuf>,
    /// Environment allow-list passed into the otherwise-empty child env.
    env: Vec<(OsString, OsString)>,
}

impl Sandbox {
    /// Create a sandbox whose only writable path is `workdir`. Network is
    /// **denied** by default — the secure default.
    pub fn new(workdir: impl Into<PathBuf>) -> Self {
        Self {
            workdir: workdir.into(),
            allow_network: false,
            ro_binds: Vec::new(),
            env: default_env(),
        }
    }

    /// Allow (`true`) or deny (`false`) network access. Only the controlled
    /// source-download phase should ever enable this — never `build()`.
    pub fn allow_network(mut self, yes: bool) -> Self {
        self.allow_network = yes;
        self
    }

    /// Expose an additional host path read-only inside the sandbox.
    pub fn ro_bind(mut self, path: impl Into<PathBuf>) -> Self {
        self.ro_binds.push(path.into());
        self
    }

    /// Add an environment variable to the child's clean environment.
    pub fn env(mut self, key: impl Into<OsString>, val: impl Into<OsString>) -> Self {
        self.env.push((key.into(), val.into()));
        self
    }

    /// Build the `bwrap` invocation for `program args...` without running it.
    /// Exposed so callers can customize stdio or inspect the command.
    pub fn command<I, S>(&self, program: &str, args: I) -> Result<Command>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let workdir = self.workdir.canonicalize().with_context(|| {
            format!("work directory does not exist: {}", self.workdir.display())
        })?;
        if !workdir.is_absolute() {
            bail!("work directory must be absolute: {}", workdir.display());
        }

        let mut cmd = Command::new(BWRAP);
        // A usr-merged read-only root.
        cmd.arg("--ro-bind").arg("/usr").arg("/usr");
        cmd.arg("--symlink").arg("usr/bin").arg("/bin");
        cmd.arg("--symlink").arg("usr/bin").arg("/sbin");
        cmd.arg("--symlink").arg("usr/lib").arg("/lib");
        cmd.arg("--symlink").arg("usr/lib").arg("/lib64");
        // System config (makepkg.conf, pacman, ca-certificates, ld.so.conf).
        cmd.arg("--ro-bind").arg("/etc").arg("/etc");
        // Read-only pacman database so makepkg's packaging checks can resolve
        // libraries/deps. Read-only means the build can never mutate it.
        cmd.arg("--ro-bind-try")
            .arg("/var/lib/pacman")
            .arg("/var/lib/pacman");
        // Kernel/dev surfaces, plus an ephemeral /tmp.
        cmd.arg("--proc").arg("/proc");
        cmd.arg("--dev").arg("/dev");
        cmd.arg("--tmpfs").arg("/tmp");

        for ro in &self.ro_binds {
            // `--ro-bind-try` so an optional path that's missing isn't fatal.
            cmd.arg("--ro-bind-try").arg(ro).arg(ro);
        }

        // The single writable mount, and we start the command there.
        cmd.arg("--bind").arg(&workdir).arg(&workdir);
        cmd.arg("--chdir").arg(&workdir);

        // Isolation: unshare everything, then re-share the network only if asked.
        cmd.arg("--unshare-user");
        cmd.arg("--unshare-ipc");
        cmd.arg("--unshare-pid");
        cmd.arg("--unshare-uts");
        cmd.arg("--unshare-cgroup-try");
        if !self.allow_network {
            cmd.arg("--unshare-net");
        }
        cmd.arg("--die-with-parent");
        cmd.arg("--new-session");

        // Clean environment: bwrap clears it, then we set our allow-list.
        cmd.arg("--clearenv");
        for (k, v) in &self.env {
            cmd.arg("--setenv").arg(k).arg(v);
        }
        // HOME points at the writable workdir so tools don't try to touch the
        // real home (which isn't mounted anyway).
        cmd.arg("--setenv").arg("HOME").arg(&workdir);

        cmd.arg("--").arg(program);
        for a in args {
            cmd.arg(a);
        }

        // We manage the host-side env ourselves; don't leak it past bwrap.
        cmd.env_clear();
        Ok(cmd)
    }

    /// Run `program args...` in the sandbox, inheriting stdio, and return its
    /// exit status.
    pub fn run<I, S>(&self, program: &str, args: I) -> Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = self.command(program, args)?;
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        cmd.status()
            .with_context(|| format!("failed to launch sandbox via {BWRAP}"))
    }
}

/// The minimal environment every sandboxed command starts with.
fn default_env() -> Vec<(OsString, OsString)> {
    vec![
        ("PATH".into(), "/usr/bin".into()),
        ("LANG".into(), "C.UTF-8".into()),
        (
            "TERM".into(),
            std::env::var_os("TERM").unwrap_or_else(|| "xterm".into()),
        ),
    ]
}

/// Whether a working sandbox can be established on this host. Runs `/usr/bin/true`
/// inside a real (network-denied) sandbox; returns `false` if `bwrap` is missing
/// or unprivileged user namespaces are unavailable.
///
/// Callers should treat `false` as "do not build" — never as "build unsandboxed".
pub fn available() -> bool {
    let probe = Sandbox::new(std::env::temp_dir());
    match probe.command("/usr/bin/true", std::iter::empty::<&OsStr>()) {
        Ok(mut cmd) => cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        Err(_) => false,
    }
}
