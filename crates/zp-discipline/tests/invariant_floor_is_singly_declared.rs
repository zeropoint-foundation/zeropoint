//! Discipline pin: the Regent's invariant floor is declared exactly once.
//!
//! The floor lives in `crates/zp-regent/src/onboarding/floor.rs`. Its four
//! capabilities (per REGENT-ONBOARDING-CEREMONY-2026-09 §3) are the
//! substrate's KEEL-mandated ground floor -- what a Regent has *by default*,
//! non-refusable. A second declaration site would either drift silently
//! from the first, or become a rival authority the substrate has no way to
//! resolve between.
//!
//! # What this pin scans for
//!
//! Three of the four floor capability strings -- `read:own-scope`,
//! `emit:cognitive`, and `propose:via-p9` -- are colon-namespaced tokens
//! that carry no meaning outside this context. The pin scans for their
//! literal appearance under `crates/**/*.rs` and confirms they occur only
//! in the allowlisted paths: the declaration file and this pin's own
//! source.
//!
//! The fourth capability, `respond`, is deliberately *not* scanned -- the
//! word is generic enough that it appears in prose (doc comments, error
//! messages, prompt files) throughout the codebase. Declaring it as a
//! literal would produce noise the pin cannot reliably filter. The other
//! three are sufficient: any second declaration of the floor as a *set*
//! would contain them.
//!
//! # What a violation looks like
//!
//! Any second appearance of one of the three colon-namespaced tokens as
//! a Rust string literal anywhere under `crates/**/*.rs` outside the two
//! allowlisted paths. The scan is line-oriented and skips comments so a
//! doc comment or reference is not counted.

use zp_discipline::Discipline;

#[test]
fn invariant_floor_read_own_scope_is_singly_declared() {
    Discipline::new("invariant_floor_is_singly_declared:read_own_scope")
        .cite_invariant(
            "Regent invariant floor -- declared exactly once per \
             REGENT-ONBOARDING-CEREMONY-2026-09 §3",
        )
        .rationale(
            "The Regent's four floor capabilities are the substrate's \
             KEEL-mandated ground floor. A second declaration is either \
             silent drift from the first or a rival authority. The floor's \
             single declaration site is crates/zp-regent/src/onboarding/\
             floor.rs.",
        )
        .forbid_pattern(r#""read:own-scope""#)
        .allow_path("crates/zp-regent/src/onboarding/floor.rs")
        .allow_path("crates/zp-discipline/tests/invariant_floor_is_singly_declared.rs")
        .skip_lines_containing("//")
        .skip_lines_containing("forbid_pattern")
        .assert();
}

#[test]
fn invariant_floor_emit_cognitive_is_singly_declared() {
    Discipline::new("invariant_floor_is_singly_declared:emit_cognitive")
        .cite_invariant(
            "Regent invariant floor -- declared exactly once per \
             REGENT-ONBOARDING-CEREMONY-2026-09 §3",
        )
        .rationale(
            "See invariant_floor_read_own_scope_is_singly_declared above.",
        )
        .forbid_pattern(r#""emit:cognitive""#)
        .allow_path("crates/zp-regent/src/onboarding/floor.rs")
        .allow_path("crates/zp-discipline/tests/invariant_floor_is_singly_declared.rs")
        .skip_lines_containing("//")
        .skip_lines_containing("forbid_pattern")
        .assert();
}

#[test]
fn invariant_floor_propose_via_p9_is_singly_declared() {
    Discipline::new("invariant_floor_is_singly_declared:propose_via_p9")
        .cite_invariant(
            "Regent invariant floor -- declared exactly once per \
             REGENT-ONBOARDING-CEREMONY-2026-09 §3",
        )
        .rationale(
            "See invariant_floor_read_own_scope_is_singly_declared above.",
        )
        .forbid_pattern(r#""propose:via-p9""#)
        .allow_path("crates/zp-regent/src/onboarding/floor.rs")
        .allow_path("crates/zp-discipline/tests/invariant_floor_is_singly_declared.rs")
        .skip_lines_containing("//")
        .skip_lines_containing("forbid_pattern")
        .assert();
}
