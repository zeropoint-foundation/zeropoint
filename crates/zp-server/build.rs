//! Build script — tells cargo to recompile when asset files change,
//! and embeds the git commit hash so we can always verify which binary
//! is running.

fn main() {
    // ── Git commit stamp ─────────────────────────────────────────────
    // Embeds ZP_BUILD_COMMIT so the server can print it on startup.
    // This is the ONLY reliable way to know what code is running.
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ZP_BUILD_COMMIT={}", commit);

    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if dirty {
        println!("cargo:rustc-env=ZP_BUILD_DIRTY=+dirty");
    } else {
        println!("cargo:rustc-env=ZP_BUILD_DIRTY=");
    }

    // Rebuild when HEAD changes (new commits)
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/");

    // ── Asset watching ───────────────────────────────────────────────
    println!("cargo:rerun-if-changed=assets/");

    let assets = [
        "assets/dashboard.html",
        "assets/onboard.html",
        "assets/onboard.css",
        "assets/onboard.js",
        "assets/speak.html",
        "assets/ecosystem.html",
        "assets/tts.js",
        "assets/providers-default.toml",
    ];

    for asset in &assets {
        println!("cargo:rerun-if-changed={}", asset);
    }
}
