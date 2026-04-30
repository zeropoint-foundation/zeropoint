//! Build script — stamps the git commit hash into the binary.
//!
//! Available at runtime via `env!("ZP_GIT_HASH")`.
//! `zp --version` and `zp doctor` use this to detect stale binaries.

use std::process::Command;

fn main() {
    // Short git hash
    let hash = git(&["rev-parse", "--short", "HEAD"]);
    println!("cargo:rustc-env=ZP_GIT_HASH={}", hash);

    // Dirty flag
    let dirty = git(&["status", "--porcelain"]);
    let dirty_flag = if dirty.is_empty() { "" } else { "-dirty" };
    println!("cargo:rustc-env=ZP_GIT_DIRTY={}", dirty_flag);

    // Re-run if HEAD changes (new commits)
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads/");
}

fn git(args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
        .trim()
        .to_string()
}
