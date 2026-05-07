//! Discipline: Cloudflare-specific Rust types must stop at the
//! `zp-cloudflare` adapter crate.
//!
//! # Why (Stack-Cloudflare reference integration)
//!
//! The ZP × Cloudflare reference integration
//! (`docs/STACK-CLOUDFLARE-2026-05.md`) defines a hexagonal layout:
//!
//! - **Ports** (in `crates/zp-*`) — pure ZeroPoint traits and types.
//!   Cloudflare-agnostic.
//! - **Adapters** (in `crates/zp-cloudflare/`) — implement ZP port
//!   traits using Cloudflare primitives. The *only* place
//!   Cloudflare-specific types are allowed.
//! - **Cloudflare primitives** — accessed exclusively through
//!   adapters.
//!
//! The first of three boundary rules: *no Cloudflare types upstream
//! of the adapter*. This pin enforces that rule mechanically. Without
//! it, Cloudflare types could leak into `zp-server`, `zp-mesh`, or
//! any other ZP crate; the adapter boundary would erode; ZP would
//! quietly become Cloudflare-coupled. With it, every attempt to
//! introduce a Cloudflare import outside the allowlisted crate fails
//! the build — visibly, immediately, with a structured rationale.
//!
//! # Pattern
//!
//! Forbids the standard Rust import patterns for the Cloudflare
//! ecosystem:
//!
//! - `use worker::...` — the Cloudflare Workers Rust SDK.
//! - `use cloudflare::...` and `use cloudflare_*::...` — the
//!   Cloudflare API client crates (e.g. `cloudflare`,
//!   `cloudflare_api`).
//! - `use cf_workers_*::...` — generated/proc-macro adapter
//!   crates that follow the `cf_workers_*` naming convention.
//! - `extern crate worker` and friends — the older Rust 2015-style
//!   import for the same crates.
//!
//! # Allowlist
//!
//! `crates/zp-cloudflare/` — the canonical adapter crate. This is
//! the *only* location where Cloudflare imports are legal. All
//! `worker::`, `cloudflare::`, `cf_workers_*::` imports must live
//! here.
//!
//! Future expansion: if a `crates/zp-cloudflare-mock/` or similar
//! adapter test crate is added, it should also be allowlisted.

use zp_discipline::Discipline;

#[test]
fn cloudflare_types_must_stop_at_the_adapter_crate() {
    Discipline::new("no_cloudflare_imports_in_zp_crates")
        .cite_invariant("Stack-Cloudflare reference integration: port/adapter boundary")
        .rationale(
            "Cloudflare-specific Rust types must live only in the \
             zp-cloudflare adapter crate. Importing them from any \
             other zp-* crate erodes the port/adapter boundary and \
             couples ZeroPoint to Cloudflare structurally. Define \
             a port trait in the appropriate zp-* crate; implement \
             the adapter in zp-cloudflare; route Cloudflare-side \
             types through the adapter only.",
        )
        // Cloudflare Workers Rust SDK.
        .forbid_pattern(r"\buse\s+worker(::|;)")
        .forbid_pattern(r"\bextern\s+crate\s+worker\b")
        // Cloudflare API client (and *_api / *-api variants).
        .forbid_pattern(r"\buse\s+cloudflare(::|_|;)")
        .forbid_pattern(r"\bextern\s+crate\s+cloudflare\b")
        // Generated proc-macro / binding crates that follow the
        // cf_workers_* naming convention.
        .forbid_pattern(r"\buse\s+cf_workers")
        .forbid_pattern(r"\bextern\s+crate\s+cf_workers")
        // The canonical adapter crate is the one allowed home.
        .allow_path("crates/zp-cloudflare/")
        // Comments may legitimately mention `use worker::...` or
        // similar when explaining the boundary (rationale strings,
        // doc comments, the forbidden-form examples in this file).
        .skip_lines_containing("//")
        // Lines declaring forbidden patterns aren't violations of
        // those patterns. The framework's own pin file mentions
        // each forbidden form via `forbid_pattern(...)`.
        .skip_lines_containing("forbid_pattern")
        .assert();
}
