//! Discipline: `serde_json/preserve_order` MUST NOT be enabled.
//!
//! # Why
//!
//! ZP-canonical-v1 (Seam 17) depends on `serde_json::Map` being backed by
//! `BTreeMap` — keys serialize in lexicographic order, which is what makes
//! the canonical form deterministic across calls and across implementations.
//! The `preserve_order` feature on `serde_json` switches the backing to
//! `IndexMap` (insertion order). The canonical form would silently change.
//! Every signed structure in the workspace would shift hash, and the audit
//! chain would break across the cut.
//!
//! This is the kind of risk that's invisible at code review and visible
//! only when receipts stop verifying. Pinning it here means: any PR that
//! enables `serde_json/preserve_order` (deliberately or accidentally,
//! e.g. by enabling a feature on a dep that itself enables it) fails the
//! build with a citation.
//!
//! There's already a runtime pin (`canonical::tests::preserve_order_not_enabled`
//! in `zp-receipt`) that confirms the property holds at test time. This
//! discipline is the source-level companion: the property can't be
//! enabled at the Cargo manifest layer either.

use zp_discipline::Discipline;

#[test]
fn no_serde_json_preserve_order_feature() {
    Discipline::new("no_serde_json_preserve_order_feature")
        .cite_invariant("Seam 17 (ZP-canonical-v1 determinism)")
        .rationale(
            "preserve_order switches serde_json::Map from BTreeMap to IndexMap, \
             silently breaking the canonical form every signed structure depends on.",
        )
        .scan_extensions(&["toml"])
        // Match the feature being enabled — `preserve_order` listed under
        // serde_json's features. The feature name is unique enough that
        // matching it anywhere in a Cargo.toml is a strong signal.
        .forbid_pattern(r#""preserve_order""#)
        .forbid_pattern(r#"preserve_order\s*="#)
        .skip_lines_containing("//")
        .skip_lines_containing("#")
        .assert();
}
