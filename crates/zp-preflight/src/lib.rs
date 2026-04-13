//! ZeroPoint Pre-flight Diagnostic System
//!
//! Inspects the target system and produces a clear pass/fail report for every
//! dependency ZeroPoint needs. Designed to run *before* installation, on a
//! system that may have none of the Rust toolchain or system libraries installed.
//!
//! # Design principles
//!
//! 1. **Zero heavy dependencies.** We shell out to system tools (`pkg-config`,
//!    `rustc`, `rustup`, `docker`, etc.) rather than linking native crates.
//! 2. **Actionable output.** Every failing check includes the *exact* command
//!    an operator should run to fix it, for their detected OS and package manager.
//! 3. **JSON-exportable.** The full report serialises to
//!    `~/.zeropoint/preflight-report.json` for consumption by the installer.

pub mod checks;
pub mod platform;
pub mod report;
pub mod runner;
