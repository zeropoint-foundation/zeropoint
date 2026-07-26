//! Discipline: runtime file resolution MUST NOT depend on build-time
//! paths.
//!
//! # Why (C7 — loaded, not versioned)
//!
//! `env!("CARGO_MANIFEST_DIR")` expands at *compile* time to the
//! absolute path of the crate directory **on the machine that ran the
//! build**. Embedding it in a path the binary resolves at *run* time
//! produces a substrate that reads its own data from wherever it
//! happened to be compiled.
//!
//! This is not a portability nicety. It breaks three ways:
//!
//! 1. **A released binary looks for a path that does not exist.** Ship
//!    `zp serve` to ARTEMIS, or to any Sovereign-Form build, and the
//!    baked path points at the builder's source tree. The read fails.
//! 2. **The failure is silent.** The observed instance
//!    (`crates/zp-server/src/regent.rs`, dossier corpus) logs at `warn`
//!    and returns an empty corpus, after which `corpus.dossiers`
//!    is empty, routing falls through to `route_from_config`, and the
//!    substrate makes every routing decision from config defaults while
//!    reporting nothing wrong.
//! 3. **The fallback is dead code.** That site's
//!    `.unwrap_or_else(|| data_path.join("models"))` only fires when
//!    `.parent().parent()` returns `None`, which cannot happen for a
//!    valid `CARGO_MANIFEST_DIR`. The intended fallback never runs.
//!
//! Runtime data paths resolve through `zp_core::paths` (ZP data root,
//! honours `ZP_HOME`) or through operator configuration. Compile-time
//! *content* embedding via `include_str!` is unaffected and remains the
//! correct tool — it captures the bytes at build time rather than a
//! path to be resolved later.
//!
//! Violates *identity is a key, not a location* (P2): the substrate's
//! evidence base should be found by configured identity, not by the
//! filesystem coordinates of a build host.
//!
//! # Skip-line marker
//!
//! Lines containing `// BUILD-PATH-TIEOFF:` are exempted. The marker
//! must carry a reason and a reopen condition at the site, per
//! `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md` Stage 1t. A tie-off is a
//! legitimate permanent state; an *undeclared* one is the defect. The
//! marker turns "this site is knowingly exempt" into something a reader
//! and a grep can both find.
//!
//! # Allowlist
//!
//! - **`crates/zp-discipline/src/`** — the pin framework itself walks
//!   up from its own manifest dir to find the workspace root. Pins only
//!   ever execute under `cargo test` from the source tree, so build-time
//!   and run-time paths are the same path by construction. This is the
//!   one place where the assumption holds.
//!
//! Test code under `tests/` is out of scope for the same reason and is
//! excluded by `restrict_to_paths` rather than by allowlist.
//!
//! # First finding
//!
//! `crates/zp-server/src/regent.rs` — the model dossier corpus, found
//! 2026-07-26 while establishing that `models/` had never been tracked
//! in git. Tracking the dossiers was necessary and not sufficient: the
//! binary still resolves them by build-host path.
//!
//! # Scope
//!
//! This is the first slice of C7 per
//! `docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md` §7 P0, not the
//! whole condition. It catches build-time path leakage. It does not yet
//! check that every runtime-opened path is tracked in git or declared
//! operator-local — there are 102 file-open sites across `crates/*/src/`
//! and most resolve dynamically from config, which needs the P1
//! enumeration rather than a pattern match.

use zp_discipline::Discipline;

#[test]
fn runtime_paths_must_not_come_from_build_time_env() {
    Discipline::new("no_build_time_paths_at_runtime")
        .cite_invariant("P2 (identity is a key, not a location) — C7 loaded-not-versioned")
        .rationale(
            "env!(\"CARGO_MANIFEST_DIR\") expands to the build host's \
             absolute path. Resolving runtime data through it makes the \
             substrate read its evidence base from wherever it was \
             compiled — which fails silently on any other machine, and \
             degrades routing to config defaults with only a warn-level \
             log. Resolve runtime paths through zp_core::paths or \
             operator configuration; use include_str! when the intent is \
             to embed content at build time.",
        )
        // Only the runtime crates. Test targets legitimately locate
        // fixtures relative to their own manifest.
        .restrict_to_paths(&["crates/"])
        .forbid_pattern(r#"env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)"#)
        // The pin framework locates the workspace root this way and only
        // ever runs from the source tree. See module docs.
        .allow_path("crates/zp-discipline/src/")
        // Integration and unit test trees.
        .allow_path("/tests/")
        .allow_path("/benches/")
        // Doc comments legitimately name the forbidden form — this file
        // is the reference for it.
        .skip_lines_containing("//!")
        .skip_lines_containing("///")
        // The declaration below is the mechanism, not a violation.
        .skip_lines_containing("forbid_pattern")
        // Declared tie-offs. See module docs — the marker must carry a
        // reason and a reopen condition at the site.
        .skip_lines_containing("BUILD-PATH-TIEOFF")
        .assert();
}
