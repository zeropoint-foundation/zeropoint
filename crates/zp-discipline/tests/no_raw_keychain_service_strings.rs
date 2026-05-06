//! Discipline: keyring `Entry::new` MUST go through the namespace functions.
//!
//! # Why (Seam 11)
//!
//! `cfg!(test)` is per-crate at compile time. When `zp-keys` is built as
//! a regular dependency for an external test crate, `cfg!(test)` inside
//! `zp-keys` evaluates to `false` and any code that used the literal
//! `"zeropoint-genesis"` would reach the *production* keychain entry,
//! not the `*-test` namespace.
//!
//! The fix landed in May 2026 was to convert the namespace constants to
//! functions (`genesis_keychain_service()`, `genesis_keychain_account()`,
//! and friends) that consult both `cfg!(test)` AND the
//! `ZP_KEYCHAIN_TEST_NAMESPACE` env var. This discipline pins the rule:
//! any `keyring::Entry::new(...)` call inside zp-keys' source must go
//! through one of those functions — never with literal namespace strings.
//!
//! The literal strings `"zeropoint-genesis"` and `"zeropoint-operator"`
//! still appear legitimately in:
//!
//! - The namespace-resolution functions themselves (the only place they
//!   should be *defined*).
//! - Certificate subject names in `zp-keys/src/certificate.rs`. These
//!   are subject *labels*, not keychain service identifiers, and never
//!   reach `keyring::Entry::new`.
//! - Doc comments and human-facing error messages that mention the
//!   service names by name.
//! - CLI error messages that tell the user how to clean up entries.

use zp_discipline::Discipline;

#[test]
fn no_literal_keychain_service_in_entry_new() {
    Discipline::new("no_literal_keychain_service_in_entry_new")
        .cite_invariant("Seam 11 (test/production identity isolation)")
        .rationale(
            "keyring::Entry::new must use the namespace functions \
             (genesis_keychain_service / operator_keychain_service / \
             genesis_keychain_account / operator_keychain_account) \
             so cfg!(test) AND ZP_KEYCHAIN_TEST_NAMESPACE both gate \
             the namespace.",
        )
        // Entry::new called with a string literal that contains a known
        // production keychain service name. This catches the "someone
        // wrote keyring::Entry::new(\"zeropoint-genesis\", ...)" mistake
        // directly. Doesn't catch creative misspellings, but the
        // discipline's job is to catch the obvious case loudly.
        .forbid_pattern(r#"Entry::new\s*\(\s*"zeropoint-(genesis|operator)"#)
        .skip_lines_containing("//")
        .assert();
}
