//! End-to-end exercise of the credential vault through the production seam.
//!
//! # Why this exists
//!
//! `zp-trust/src/vault.rs` carries thirty unit tests — save/load roundtrip,
//! wrong-key-fails-decrypt, tier isolation, atomic save, ref cycles. The crypto
//! and the file format are well covered, and every one of those tests
//! constructs a master key directly (`[0x42u8; 32]`).
//!
//! None of them exercise the substrate's *use* of the vault: deriving the key
//! the way production derives it, storing at the path production stores at,
//! and reading it back across a process boundary. That distinction stopped
//! being academic on 2026-08-06, when `~/ZeroPoint/vault.json` was found not to
//! exist on a substrate that had been running for months. The vault was
//! complete and correct; nothing had ever written to it. A startup race meant
//! `spawn_regent` read the vault master key before a background thread had
//! resolved it, so the one code path that would have populated the vault took
//! its silent fallback on every boot.
//!
//! The unit tests could not have caught that, and no test should be expected
//! to catch a wiring defect in a crate it does not import. But the shape
//! recurred five times in one session — a component built, tested, and
//! unreachable on the path it sat on — and the cheapest guard against it is a
//! test that walks the seam rather than the unit.
//!
//! # What this covers that the unit tests do not
//!
//! 1. **Derivation is deterministic.** `derive_vault_key` is a keyed blake3 of
//!    the sovereign root. If it ever changed, every stored secret would become
//!    permanently unreadable with no error at write time. Nothing pinned it.
//! 2. **`save()` is what creates the file.** `load_or_create` synthesises an
//!    empty vault in memory and writes nothing — which is exactly why an absent
//!    `vault.json` looked identical to a healthy empty one.
//! 3. **The plaintext is not on disk.** The nearest existing test
//!    (`test_vault_encryption_isolation`) asserts only that two entries have
//!    different nonces. The property an operator cares about — that the secret
//!    they stored is not sitting in the file — was untested.
//! 4. **The secret survives a process boundary**, loaded fresh from disk rather
//!    than read back out of the same in-memory instance.
//! 5. **A different sovereign root cannot read it**, derived rather than
//!    hand-constructed, so the derivation is part of the isolation claim.
//!
//! # What this deliberately does not cover
//!
//! The real key comes from `load_sovereign_root`, which needs Genesis and, on
//! this substrate, a Trezor touch. That cannot run unattended, so the sovereign
//! root here is a fixed byte array standing in for it. Everything downstream of
//! the root is the production path; the root itself is not. Verifying the real
//! unlock remains an operator-attended step.

use zp_keys::derive_vault_key;
use zp_trust::vault::VaultTier;
use zp_trust::CredentialVault;

/// The path `spawn_regent` migrates the operator's inference credential to.
/// Hard-coded here on purpose: if production changes it, this test should be
/// the thing that notices.
const PRODUCTION_KEY_PATH: &str = "system/regent/inference/api_key";

/// Shaped like a real credential so a substring scan of the vault file is a
/// meaningful check rather than a search for something too short to matter.
const SECRET: &[u8] = b"sk-abacus-TESTONLY-4f3a91c2e8b7d60514a2";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn vault_round_trips_a_secret_through_the_production_seam() {
    // Stands in for the sovereign root. Production derives this from Genesis
    // via `load_sovereign_root`; everything after this line is the real path.
    let sovereign_root = [0x5Au8; 32];

    // (1) Derivation must be stable. A change here silently orphans every
    // secret ever stored — the write succeeds, the read fails forever.
    let key = derive_vault_key(&sovereign_root);
    let key_again = derive_vault_key(&sovereign_root);
    assert_eq!(
        *key, *key_again,
        "vault key derivation must be deterministic — an unstable derivation \
         makes every previously stored secret unreadable with no error at \
         write time"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_path = tmp.path().join("vault.json");

    // (2) `load_or_create` on a missing file must not create the file. This is
    // the behaviour that made an absent vault indistinguishable from an empty
    // one in the officer sweep.
    {
        let vault = CredentialVault::load_or_create(&key, &vault_path)
            .expect("load_or_create on a missing path");
        assert!(
            vault.list().is_empty(),
            "a freshly created vault must be empty"
        );
    }
    assert!(
        !vault_path.exists(),
        "load_or_create must not write to disk — only save() creates the file. \
         If this ever changes, an absent vault and an empty vault stop being \
         distinguishable at the filesystem, which is how the 2026-08-06 \
         investigation lost half a day"
    );

    // Store and persist, as `spawn_regent`'s migration does.
    {
        let mut vault = CredentialVault::load_or_create(&key, &vault_path).expect("load_or_create");
        vault
            .store_tiered(PRODUCTION_KEY_PATH, SECRET, VaultTier::System)
            .expect("store_tiered");
        vault.save(&vault_path).expect("save");
    }

    assert!(vault_path.exists(), "save() must create the vault file");

    // (3) The secret must not be readable from the file.
    let on_disk = std::fs::read(&vault_path).expect("read vault file");
    assert!(
        !contains(&on_disk, SECRET),
        "plaintext secret found in the vault file — encryption at rest is not \
         in effect"
    );
    assert!(!on_disk.is_empty(), "vault file exists but is empty");

    // (4) Survives a process boundary: fresh instance, loaded from disk.
    {
        let vault = CredentialVault::load_or_create(&key, &vault_path).expect("reload from disk");
        let retrieved = vault
            .retrieve(PRODUCTION_KEY_PATH)
            .expect("retrieve after reload");
        assert_eq!(retrieved, SECRET, "secret did not survive save/load");
        assert_eq!(
            vault.list(),
            vec![PRODUCTION_KEY_PATH.to_string()],
            "list() must report the stored key name"
        );
    }

    // (5) A different sovereign root must not decrypt it. Derived, not
    // hand-built, so the derivation is part of the isolation claim.
    {
        let other_key = derive_vault_key(&[0xA5u8; 32]);
        assert_ne!(*other_key, *key, "distinct roots must derive distinct keys");

        // Loading may succeed — the envelope is readable — but the value must
        // not decrypt.
        if let Ok(vault) = CredentialVault::load_or_create(&other_key, &vault_path) {
            assert!(
                vault.retrieve(PRODUCTION_KEY_PATH).is_err(),
                "a vault opened with a different derived key must not yield \
                 the secret"
            );
        }
    }
}

/// `list()` must report key *names* and never leak values.
///
/// Officers hold a `VaultKeyLister` under the R1 privilege invariant — names
/// only, never secret material — and the forthcoming `zp vault list` verb will
/// rely on the same property. Worth pinning before anything is built on it.
#[test]
fn vault_list_exposes_names_not_values() {
    let key = derive_vault_key(&[0x11u8; 32]);
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_path = tmp.path().join("vault.json");

    let mut vault = CredentialVault::load_or_create(&key, &vault_path).expect("create");
    vault
        .store_tiered(PRODUCTION_KEY_PATH, SECRET, VaultTier::System)
        .expect("store");

    let names = vault.list();
    assert_eq!(names, vec![PRODUCTION_KEY_PATH.to_string()]);

    let rendered = names.join(" ");
    let secret_str = String::from_utf8_lossy(SECRET);
    assert!(
        !rendered.contains(secret_str.as_ref()),
        "list() leaked secret material into a key name listing"
    );
}
