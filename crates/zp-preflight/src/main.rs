//! ZeroPoint Pre-flight Diagnostic Tool
//!
//! Run this *before* installing ZeroPoint to verify your system is ready.
//!
//! ```
//! $ zp-preflight            # full check (source build)
//! $ zp-preflight --binary   # binary-install check (no Rust needed)
//! $ zp-preflight --json     # machine-readable output
//! ```

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use zp_preflight::report::{PreflightReport, Status};
use zp_preflight::runner;

#[derive(Parser)]
#[command(
    name = "zp-preflight",
    about = "Check system readiness for ZeroPoint installation",
    version
)]
struct Cli {
    /// Output results as JSON (also saved to ~/ZeroPoint/preflight-report.json)
    #[arg(long)]
    json: bool,

    /// Only check requirements for binary (pre-built) installation.
    /// Skips Rust toolchain and system library checks.
    #[arg(long)]
    binary: bool,

    /// Custom port to check instead of default (17770)
    #[arg(long)]
    port: Option<u16>,

    /// Skip saving report to ~/ZeroPoint/
    #[arg(long)]
    no_save: bool,
}

fn main() {
    let cli = Cli::parse();

    let report = if cli.binary {
        runner::run_binary_install()
    } else {
        runner::run_all()
    };

    if cli.json {
        print_json(&report);
    } else {
        print_human(&report);
    }

    // Save report for installer consumption
    if !cli.no_save {
        save_report(&report);
    }

    // Exit code: 0 if ready, 1 if any failures
    if !report.summary.ready {
        std::process::exit(1);
    }
}

fn print_human(report: &PreflightReport) {
    println!();
    println!("  ZeroPoint Pre-flight Check");
    println!("  ─────────────────────────────────────────");
    println!(
        "  Platform: {} ({:?} {:?})",
        report.platform.os_version, report.platform.os, report.platform.arch
    );
    println!();

    for check in &report.checks {
        let icon = match check.status {
            Status::Pass => "\x1b[32m✓\x1b[0m",
            Status::Fail => "\x1b[31m✗\x1b[0m",
            Status::Warn => "\x1b[33m⚠\x1b[0m",
            Status::Skip => "\x1b[90m─\x1b[0m",
        };
        println!("  {icon} {}: {}", check.label, check.detail);
        if !check.fix.is_empty() && (check.is_fail() || check.is_warn()) {
            println!("    → Fix: {}", check.fix);
        }
    }

    println!();
    println!("  ─────────────────────────────────────────");
    println!(
        "  {} passed, {} failed, {} warnings, {} skipped ({} ms)",
        report.summary.passed,
        report.summary.failed,
        report.summary.warnings,
        report.summary.skipped,
        report.elapsed_ms,
    );

    if report.summary.ready {
        println!("  \x1b[32m✓ System is ready for ZeroPoint installation.\x1b[0m");
    } else {
        println!("  \x1b[31m✗ Fix the failures above before installing.\x1b[0m");
    }
    println!();
}

fn print_json(report: &PreflightReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("Failed to serialize report: {e}");
            std::process::exit(2);
        }
    }
}

fn save_report(report: &PreflightReport) {
    let dir = zp_home();
    if fs::create_dir_all(&dir).is_err() {
        return; // Silently skip if we can't create the directory
    }
    let path = dir.join("preflight-report.json");
    if let Ok(json) = serde_json::to_string_pretty(report) {
        let _ = fs::write(&path, json);
    }
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Resolve the ZP home directory. **Mirror of [`zp_core::paths::home`]**
/// (Seam 19) — kept local instead of depending on `zp-core` because
/// `zp-preflight` is deliberately minimal-deps for fast-compile (see
/// the Cargo.toml comment "Kept minimal on purpose").
///
/// If the resolution rule in `zp_core::paths::home` ever changes, this
/// function MUST be updated to match. The two stay in sync by hand.
fn zp_home() -> PathBuf {
    if let Ok(h) = std::env::var("ZP_HOME") {
        return PathBuf::from(h);
    }
    home_dir().join("ZeroPoint")
}
