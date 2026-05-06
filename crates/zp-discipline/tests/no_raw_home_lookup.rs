//! Discipline: raw home-directory lookups MUST go through the
//! `zp_core::paths` carrier.
//!
//! # Why (Seam 19)
//!
//! Two distinct concepts share the same call surface in ad-hoc Rust
//! code: `dirs::home_dir()` and `std::env::var("HOME")` can mean either
//! "the ZP data root" (`~/ZeroPoint/`) or "the user's home" (`~`). The
//! carrier disambiguates them:
//!
//! - `zp_core::paths::home()` — ZP data root (honors `ZP_HOME`)
//! - `zp_core::paths::user_home()` — user's actual home
//! - `zp_core::paths::user_home_or(fallback)` — user home with fallback
//! - `zp_core::paths::redact_user_home(s)` — replace home with `~`
//!
//! Every site that hand-rolls these via `dirs` or raw env lookups
//! re-introduces the ambiguity. The pin enforces that callers opt in
//! to one carrier function, making intent explicit.
//!
//! # Allowlist
//!
//! Three locations are permitted to look up `HOME` directly:
//!
//! 1. **`crates/zp-core/src/paths.rs`** — the carrier itself.
//! 2. **`crates/zp-preflight/`** — deliberately minimal-deps for
//!    fast-compile (see its Cargo.toml header). Maintains a documented
//!    mirror of `paths::home()` with a comment cross-reference.
//! 3. **`crates/zp-config/`** — same constraint as zp-preflight; also
//!    a documented mirror.
//!
//! A future structural improvement is to extract `paths` into a
//! micro-crate that zp-preflight and zp-config can depend on without
//! pulling in zp-core's transitive deps. Until then, the mirrors are
//! the documented exception.
//!
//! # Skip-line markers
//!
//! Lines containing `// HOME-OK:` are exempted. The marker is for test
//! isolation code that must save/restore the real `HOME` while
//! redirecting it to a tempdir — a legitimate use that the carrier
//! cannot abstract away. The marker forces an explicit annotation, so
//! any future use is at least visible to a reviewer.

use zp_discipline::Discipline;

#[test]
fn raw_home_lookups_must_go_through_paths_carrier() {
    Discipline::new("no_raw_home_lookup")
        .cite_invariant("Seam 19 (path resolution carrier)")
        .rationale(
            "Raw home-dir lookups collapse two distinct intents (ZP data \
             root vs user home) into one ambiguous call surface. Route \
             through zp_core::paths::home or zp_core::paths::user_home \
             so intent is explicit at every site.",
        )
        // External crates that expose home_dir functions.
        .forbid_pattern(r"\bdirs::home_dir\s*\(")
        .forbid_pattern(r"\bdirectories::home_dir\s*\(")
        // Raw HOME / USERPROFILE env lookups (both var and var_os forms).
        .forbid_pattern(r#"std::env::var\s*\(\s*"HOME""#)
        .forbid_pattern(r#"std::env::var_os\s*\(\s*"HOME""#)
        .forbid_pattern(r#"std::env::var\s*\(\s*"USERPROFILE""#)
        .forbid_pattern(r#"std::env::var_os\s*\(\s*"USERPROFILE""#)
        // Lines declaring forbidden patterns aren't violations of those
        // patterns. The framework's own pin file mentions each forbidden
        // form via `forbid_pattern(...)` — those declarations are the
        // mechanism that catches violations elsewhere, not violations.
        .skip_lines_containing("forbid_pattern")
        // The carrier itself.
        .allow_path("crates/zp-core/src/paths.rs")
        // Documented mirror crates (Cargo.toml header explains the
        // minimal-deps constraint; each function carries a cross-
        // reference comment to zp_core::paths).
        .allow_path("crates/zp-preflight/")
        .allow_path("crates/zp-config/")
        // Skip comments — the rationale and module-level prose
        // legitimately mention the forbidden forms.
        .skip_lines_containing("//")
        // Test isolation marker. Lines containing `HOME-OK` are
        // intentional uses (save/restore around tempdir redirection).
        // The marker forces an explicit annotation so any future use
        // is visible to a reviewer.
        .skip_lines_containing("HOME-OK")
        .assert();
}
