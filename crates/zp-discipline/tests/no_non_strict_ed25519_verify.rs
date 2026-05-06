//! Discipline: Ed25519 signature verification MUST go through `verify_strict`.
//!
//! # Why (Seam 5 / CRIT-4)
//!
//! `ed25519_dalek::VerifyingKey::verify` is signature-malleable — for a
//! given (key, message, signature) it accepts a small set of valid
//! distinct signature byte sequences. Two attacker-controlled receipts
//! could verify under the same hash. The malleability primitive is
//! defeated by `verify_strict`, which rejects every form except the
//! canonical one.
//!
//! Phase 1.C swept five sites from `verify` to `verify_strict` (zp-verify
//! chain S1 rule, zp-receipt::Signer::verify_receipt, zp-server::
//! attestations, zp-mesh::runtime, zp-mesh::discovery). The Tier 1 verify
//! helper (`zp_core::verify_signature`, defined in `zp-receipt::verify`)
//! is the single canonical verify primitive. This discipline pins both:
//! no `verifying_key.verify(` (non-strict form) anywhere, period.
//!
//! # Pattern
//!
//! Matches `verifying_key.verify(` — the most common form Phase 1.C
//! swept. Doesn't catch creative variable names like `vk.verify(`; that
//! gap is acknowledged. The discipline catches the obvious case loudly,
//! and a sweep of the broader pattern is task #30 in the Tier 1 plan.

use zp_discipline::Discipline;

#[test]
fn no_non_strict_verify_on_named_verifying_key() {
    Discipline::new("no_non_strict_ed25519_verify")
        .cite_invariant("Seam 5 (verifier symmetry) / CRIT-4 (signature malleability)")
        .rationale(
            "verifying_key.verify(...) is signature-malleable; verify_strict \
             is the only sanctioned primitive. Direct calls outside the \
             zp_core::verify::verify_signature helper are forbidden.",
        )
        // Match `verifying_key.verify(` (non-strict). The word boundary
        // before `(` ensures `verify_strict(` doesn't match — `_` is a
        // word character, so `\bverify\b` won't span into `verify_strict`.
        .forbid_pattern(r"verifying_key\.verify\b\s*\(")
        // Doc comments and module-level rationale comments may legitimately
        // mention the forbidden form when explaining why it's forbidden.
        .skip_lines_containing("//")
        // Lines that mention `verify_strict` alongside the non-strict
        // form are almost always explaining the rule (rationale strings,
        // doc-comment continuations, error messages naming the correct
        // primitive). Skipping them avoids the framework catching its
        // own documentation as a violation.
        .skip_lines_containing("verify_strict")
        .assert();
}
