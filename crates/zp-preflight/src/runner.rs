//! Orchestrates all preflight checks and produces a report.

use crate::checks;
use crate::platform::Platform;
use crate::report::{CheckResult, PreflightReport};
use std::time::Instant;

/// Run all pre-flight checks against the detected platform.
pub fn run_all() -> PreflightReport {
    let start = Instant::now();
    let plat = Platform::detect();

    let checks: Vec<CheckResult> = vec![
        // ── Rust toolchain ──
        checks::check_rust_toolchain(&plat),
        checks::check_wasm_target(&plat),
        // ── System libraries (core) ──
        checks::check_pkg_config_tool(&plat),
        checks::check_libssl(&plat),
        // ── System libraries (feature-gated) ──
        checks::check_libdbus(&plat),
        checks::check_libusb(&plat),
        // ── System resources ──
        checks::check_disk_space(&plat),
        checks::check_port(&plat),
        // ── Network ──
        checks::check_network_crates_io(&plat),
        checks::check_network_github(&plat),
        // ── OS capabilities ──
        checks::check_keychain_capability(&plat),
        // ── Optional tools ──
        checks::check_docker(&plat),
    ];

    PreflightReport::build(plat, checks, start.elapsed())
}

/// Run checks for a binary-only install (no Rust toolchain needed).
pub fn run_binary_install() -> PreflightReport {
    let start = Instant::now();
    let plat = Platform::detect();

    let checks: Vec<CheckResult> = vec![
        checks::check_disk_space(&plat),
        checks::check_port(&plat),
        checks::check_network_github(&plat),
        checks::check_keychain_capability(&plat),
        checks::check_docker(&plat),
    ];

    PreflightReport::build(plat, checks, start.elapsed())
}
