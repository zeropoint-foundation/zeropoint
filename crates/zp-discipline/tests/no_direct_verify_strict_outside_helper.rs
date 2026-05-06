//! Discipline: `verify_strict(` MUST only appear inside the canonical
//! verify primitive at `zp-receipt/src/verify.rs`.
//!
//! # Why (Seam 5, tightened)
//!
//! The companion `no_non_strict_ed25519_verify` discipline forbids the
//! malleable `verify(` form everywhere. This one closes the second half
//! of the loop: even the strict form must not appear at call sites —
//! every signature check in the workspace routes through
//! `zp_receipt::verify::verify_signature` (raw bytes) or
//! `zp_receipt::verify::verify_signed` (any `Signable`).
//!
//! Why bother pinning the strict form? Three reasons:
//!
//! 1. **Single carrier for observability.** When verification fails in
//!    production we want one place to add tracing, one place to count
//!    `signature_failures`, one place to enforce key-length checks. If
//!    callers re-implement the strict form by hand, those properties
//!    drift across the workspace.
//!
//! 2. **Single carrier for error semantics.** `verify_signature` returns
//!    a typed `VerifyError` (InvalidPublicKey / InvalidSignature /
//!    Mismatch). Hand-rolled call sites collapse all three into
//!    `is_ok()` and lose the distinction. Some callers want to surface
//!    "bad public key bytes" as a hard error; others want to treat it
//!    the same as "signature didn't verify." The helper makes the
//!    distinction explicit; ad-hoc call sites bury it.
//!
//! 3. **Composes with `Signable`.** `verify_signed<T: Signable>` re-
//!    derives the canonical preimage from the signed object — there is
//!    no path by which a verifier could compute a *different* preimage
//!    from the same value. Hand-rolled `verify_strict` calls bypass
//!    this and re-introduce the canonical-bytes drift Seam 17 was
//!    meant to close.
//!
//! # Pattern
//!
//! Matches `verify_strict(` (with optional whitespace before the paren).
//! The companion non-strict pin uses `verifying_key.verify\b\s*\(` to
//! avoid spanning into `verify_strict`; this pin matches the strict
//! form directly. The only legitimate occurrence is inside the helper
//! itself — see the `allow_path` allowlist below.

use zp_discipline::Discipline;

#[test]
fn verify_strict_must_only_appear_in_the_helper() {
    Discipline::new("no_direct_verify_strict_outside_helper")
        .cite_invariant("Seam 5 (single verify primitive)")
        .rationale(
            "Every Ed25519 signature check routes through \
             zp_receipt::verify::verify_signature. Direct verify_strict \
             calls re-introduce the canonical-bytes / error-semantics / \
             observability drift the helper was created to eliminate.",
        )
        .forbid_pattern(r"verify_strict\s*\(")
        // The helper itself legitimately calls `verify_strict` — that's
        // the one place the strict form is allowed to appear.
        .allow_path("crates/zp-receipt/src/verify.rs")
        // Comments may mention the forbidden form when explaining the
        // discipline (rationale strings, doc comments, error messages
        // naming the correct primitive). Skipping comment lines avoids
        // catching the framework's own discussion of the rule.
        .skip_lines_containing("//")
        .assert();
}
