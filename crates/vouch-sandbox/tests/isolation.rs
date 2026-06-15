//! Integration tests that assert the sandbox's security properties against the
//! real kernel. They are skipped (not failed) on hosts without unprivileged
//! user namespaces, so CI without that capability stays green.

use std::fs;
use std::path::Path;
use std::process::id;

use vouch_sandbox::{Sandbox, available};

/// Make a unique, real work directory for a test.
fn workdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vouch-sbx-{}-{tag}", id()));
    fs::create_dir_all(&dir).expect("create workdir");
    dir
}

#[test]
fn workdir_writable_but_system_is_not() {
    if !available() {
        eprintln!("skipping: unprivileged user namespaces unavailable");
        return;
    }
    let dir = workdir("fs");

    // The work directory is the one writable mount.
    let status = Sandbox::new(&dir)
        .run("/usr/bin/sh", ["-c", "touch \"$HOME/marker\""])
        .expect("run");
    assert!(
        status.success(),
        "writing inside the workdir should succeed"
    );
    assert!(
        dir.join("marker").exists(),
        "marker must appear on the host"
    );

    // /etc is read-only: writing there must fail.
    let status = Sandbox::new(&dir)
        .run("/usr/bin/sh", ["-c", "touch /etc/vouch-should-not-exist"])
        .expect("run");
    assert!(
        !status.success(),
        "/etc must be read-only inside the sandbox"
    );
    assert!(
        !Path::new("/etc/vouch-should-not-exist").exists(),
        "nothing must have been written to the host /etc"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn network_is_denied_by_default() {
    if !available() {
        eprintln!("skipping: unprivileged user namespaces unavailable");
        return;
    }
    if !Path::new("/usr/bin/curl").exists() {
        eprintln!("skipping: curl not present to exercise the network");
        return;
    }
    let dir = workdir("net-deny");

    let status = Sandbox::new(&dir)
        .run(
            "/usr/bin/curl",
            ["--max-time", "5", "-sS", "https://archlinux.org"],
        )
        .expect("run");
    assert!(
        !status.success(),
        "the default sandbox must have no network route off the host"
    );

    fs::remove_dir_all(&dir).ok();
}
