//! Build script — tells cargo to recompile when asset files change.
//!
//! Without this, `include_str!("../assets/dashboard.html")` and friends
//! are only re-evaluated when a `.rs` file changes.  This build script
//! watches the assets directory so HTML/CSS/JS edits trigger recompilation.

fn main() {
    // Watch the entire assets directory for changes
    println!("cargo:rerun-if-changed=assets/");

    // Also watch individual files that are included via include_str!()
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
