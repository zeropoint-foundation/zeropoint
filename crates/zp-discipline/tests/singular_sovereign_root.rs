//! Discipline: exactly one sovereign root per process, reached by one loader.
//!
//! # The rule
//!
//! Genesis is the only sovereign root. Every other secret is either derived
//! from it in memory (vault master key, audit signer seed, agent certificate
//! material) or stored in the vault and decrypted with the in-memory vault
//! master key. There is no third category — no secret sitting in the OS
//! credential store independently, behind its own biometric gate.
//!
//! The canonical loader is `zp_keys::sovereignty::load_sovereign_root()`,
//! wrapping a process-scoped `OnceLock`: one sovereignty ceremony per process
//! lifetime, everything else a cache hit.
//!
//! Full argument in `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md`; the rule table
//! this file mechanises is `docs/DISCIPLINE-PINS.md` §singular_sovereign_root.
//!
//! # Why it is mechanised here — 2026-08-05
//!
//! The rule shipped 2026-05-14 with unit tests for the provider parser (they
//! live at `zp-keys/src/sovereignty/mod.rs:991`) and an *enforcement scan*
//! written as a block of `rg` invocations with the note *"CI integration: add
//! as a step in the pre-merge check."* That step was never added, so for eleven
//! weeks the nine forbidden-pattern rules were enforced by a human remembering
//! to run shell commands. `SINGULAR-SOVEREIGN-ROOT-2026-05.md` §179 still lists
//! the work as pending; `DISCIPLINE-PINS.md:33-38` records the confusion this
//! produced, having concluded from the presence of the parser tests that the
//! enforcement half was "done elsewhere." It was not.
//!
//! The scan also drifted from the code while nobody was running it — see the
//! exemption notes below, each of which records a site the documented table
//! does not anticipate.
//!
//! # What this does not catch
//!
//! These pins enforce *one root*, not *one ceremony per operator action*. A
//! command that routes correctly through `load_sovereign_root()` but has no
//! business unlocking anything — a read-only HTTP call over the session token,
//! say — satisfies every pattern here while still charging the operator a
//! hardware touch. That failure mode recurred on 2026-08-05 in `zp correction`
//! and is handled structurally by `is_session_token_only` in `zp-cli`, not by a
//! pattern scan; it is not expressible as "this regex must not appear."

use zp_discipline::Discipline;

/// The pins' own crate is exempt from every rule in this file.
///
/// Not a loophole: a discipline pin must name the pattern it forbids, so its
/// source necessarily contains that pattern. Without this the rationale strings
/// below would flag themselves and the file could never go green. `zp-discipline`
/// holds the scanner and the pins and no production code, so nothing can hide
/// here. The alternative — contorting every pattern so it cannot match its own
/// spelling — is how `no_raw_keychain_service_strings` is written, and it makes
/// the patterns harder to read than the rule they encode.
const DISCIPLINE_CRATE: &str = "crates/zp-discipline/";

/// Credential-store primitives stay inside `zp-keys`.
///
/// This is the singular-sovereign-root boundary drawn at crate granularity: any
/// other crate reaching the OS credential store directly is, by construction, a
/// second root with its own gate. Within `zp-keys` the narrower per-file rules
/// below apply.
#[test]
fn no_credential_store_access_outside_zp_keys() {
    Discipline::new("no_credential_store_access_outside_zp_keys")
        .cite_invariant("P2 (identity is a key, not a location) / singular sovereign root")
        .rationale(
            "Credential-store reads and writes belong to zp-keys. A second \
             crate holding its own credential-store entry is a second sovereign \
             root: another gate, another prompt, and an audit signer loadable \
             independently of Genesis — which weakens the chain's claim that \
             the operator signed.",
        )
        .forbid_pattern(r"\.get_password\s*\(")
        .forbid_pattern(r"\.set_password\s*\(")
        // Fully qualified deliberately: a bare `Entry::new` collides with
        // `UnsealedEntry::new`, which appears in ten-plus call sites across
        // zp-cli and zp-server and has nothing to do with the credential store.
        .forbid_pattern(r"keyring::Entry::new\s*\(")
        .allow_path("crates/zp-keys/")
        .allow_path(DISCIPLINE_CRATE)
        .skip_lines_containing("//")
        .assert();
}

/// macOS Keychain FFI stays in the Touch ID provider.
#[test]
fn no_security_framework_ffi_outside_touchid_provider() {
    Discipline::new("no_security_framework_ffi_outside_touchid_provider")
        .cite_invariant("singular sovereign root (one credential-store owner)")
        .rationale(
            "SecItemAdd / SecItemCopyMatching / SecItemDelete are the raw \
             Keychain surface. One module owns them so that access-control \
             flags, the os_enforced determination, and the once-per-process \
             read discipline all have exactly one place to be correct.",
        )
        .forbid_pattern(r"\bSecItemAdd\b")
        .forbid_pattern(r"\bSecItemCopyMatching\b")
        .forbid_pattern(r"\bSecItemDelete\b")
        .allow_path("crates/zp-keys/src/sovereignty/touchid.rs")
        .allow_path(DISCIPLINE_CRATE)
        .skip_lines_containing("//")
        .assert();
}

/// Biometric subprocesses stay in their own provider modules.
#[test]
fn no_biometric_subprocess_outside_its_provider() {
    Discipline::new("no_biometric_subprocess_outside_its_provider")
        .cite_invariant("singular sovereign root (one provider per gate)")
        .rationale(
            "`bioutil` belongs to the Touch ID provider and `fprintd-verify` to \
             the fingerprint provider. Shelling out to either from anywhere else \
             is a biometric gate the sovereignty layer does not know it has.",
        )
        // Matched at the spawn site rather than on the bare name, so a doc
        // comment or error message mentioning either tool is not a violation.
        // Verified 2026-08-05 against all four real call sites: touchid.rs
        // :217, :243, :338 and fingerprint.rs:159.
        .forbid_pattern(r#"Command::new\s*\(\s*"bioutil""#)
        .forbid_pattern(r#"Command::new\s*\(\s*"fprintd-verify""#)
        .allow_path("crates/zp-keys/src/sovereignty/touchid.rs")
        .allow_path("crates/zp-keys/src/sovereignty/fingerprint.rs")
        .allow_path(DISCIPLINE_CRATE)
        .skip_lines_containing("//")
        .assert();
}

/// `provider.load_secret()` is reached through the cached loader.
///
/// This is the load-bearing pin of the set. `load_sovereign_root()` exists so
/// that one ceremony serves a whole process; a direct `load_secret()` call
/// sidesteps the `OnceLock` and charges the operator a second confirmation.
///
/// # Exemptions, and what each one is
///
/// - `sovereignty/mod.rs` — the canonical loader itself, inside
///   `load_sovereign_root_uncached`. The one legitimate call site.
///
/// - `zp-server/src/onboard/genesis.rs` — sovereignty-mode graduation reads the
///   secret from the *outgoing* provider in order to re-enrol it under the
///   incoming one. Necessarily outside the cache: the cached value belongs to
///   the provider being replaced, and the ceremony's whole purpose is to move
///   between two of them. Legitimate by design, not drift.
///
/// - `sovereignty/hardware/mod.rs` — tests asserting the error path when no
///   device is present.
///
/// - `zp-keys/src/biometric.rs` — **unresolved.** `load_genesis_biometric()`
///   and `save_genesis_biometric()` are compatibility wrappers calling the
///   providers directly, bypassing the `OnceLock`. As of 2026-08-05 nothing in
///   the workspace calls either one — but they are `pub`, and `keyring.rs:623`
///   and `:598` tell the reader to use them ("For biometric mode on Linux, call
///   `biometric::load_genesis_biometric()` instead"). A documented bypass with
///   no callers is worse than dead code: the next person to need biometric
///   loading will follow the doc comment into it and get a second ceremony with
///   nothing to warn them. This exemption is a placeholder for a decision —
///   delete both functions and repoint the two doc comments at
///   `load_sovereign_root()`, then drop this line — not a blessing.
#[test]
fn no_direct_load_secret_outside_canonical_loader() {
    Discipline::new("no_direct_load_secret_outside_canonical_loader")
        .cite_invariant("singular sovereign root (one ceremony per process)")
        .rationale(
            "load_sovereign_root() wraps a process-scoped OnceLock so one \
             sovereignty ceremony serves the whole process. Calling \
             provider.load_secret() directly sidesteps the cache and charges \
             the operator another physical confirmation — the exact drift that \
             produced 5-9 Touch ID prompts for one `zp configure exec` in \
             2026-05.",
        )
        .forbid_pattern(r"\.load_secret\s*\(")
        .allow_path("crates/zp-keys/src/sovereignty/mod.rs")
        .allow_path("crates/zp-keys/src/sovereignty/hardware/mod.rs")
        .allow_path("crates/zp-server/src/onboard/genesis.rs")
        // Pending deletion — see the exemption notes above.
        .allow_path("crates/zp-keys/src/biometric.rs")
        .allow_path(DISCIPLINE_CRATE)
        .skip_lines_containing("//")
        .assert();
}
