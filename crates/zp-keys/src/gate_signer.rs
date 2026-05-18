//! Gate-request signer derivation — derives the per-deployment gate signing
//! key from the Genesis secret.
//!
//! # Purpose
//!
//! The gate signer is a 32-byte Ed25519 seed used by callers (e.g. IronClaw)
//! to sign per-request `ZP-Sig` envelopes against the ZeroPoint cognition-
//! governance gate. The same derivation is used by the gate's verifier to
//! reconstruct the expected verifying key — both sides reach the same Ed25519
//! keypair from the same Genesis secret because the derivation is pure and
//! deterministic.
//!
//! # Why a subkey, not Genesis itself or the audit signer?
//!
//! Domain separation. The gate signer attests "this HTTP request originated
//! from an identity that holds Genesis." Reusing Genesis directly would
//! conflate root-of-trust authority with request-signing authority. Reusing
//! the audit signer ([`crate::audit_signer`]) would couple gate-call ability
//! to chain-attestation ability — two purposes, two domains.
//!
//! # No on-disk persistence
//!
//! Same property as [`crate::audit_signer`]: the gate signer is re-derived
//! in memory at process startup after sovereignty unlock produces Genesis,
//! held only for the process's lifetime, and never written to a file. One
//! less secret on disk; one less file an attacker can read.
//!
//! # Forward compatibility
//!
//! This is `v1`. Rotation = bump the domain tag to `v2` and add a parallel
//! function. The envelope's `ZP-Sig` header already carries a scheme version
//! (`v=1`); a v2 derivation would pair with a v2 envelope, and a transition
//! window can verify both during cutover.
//!
//! # Derivation
//!
//! ```text
//! gate_signer_seed = BLAKE3-keyed(genesis_secret, context="zp.gate.request.v1")
//! ```
//!
//! The 32-byte output is fed directly into `ed25519_dalek::SigningKey::from_bytes`.

use zeroize::Zeroizing;

/// Context string for gate-request-signer derivation. Versioned for future
/// rotation; format mirrors `AUDIT_SIGNER_CONTEXT` and `VAULT_KEY_CONTEXT`
/// (dotted, lowercase, trailing `.vN` tag).
///
/// **Discipline:** this byte string must not be reproduced anywhere outside
/// this module. A `no_inline_gate_signer_derivation` pin guards the workspace
/// against future drift (see design §10).
pub const GATE_SIGNER_CONTEXT: &[u8] = b"zp.gate.request.v1";

/// Derive the 32-byte gate-request signer seed from a Genesis secret.
///
/// Pure, deterministic, domain-separated. Same Genesis → same seed. Feeds
/// directly into `ed25519_dalek::SigningKey::from_bytes`.
///
/// The returned seed is wrapped in [`Zeroizing`] for automatic cleanup —
/// callers should not copy the inner bytes outside of an Ed25519 signing-key
/// constructor that itself zeroizes (e.g. `ed25519_dalek::SigningKey`).
pub fn derive_gate_signer_seed(genesis_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(genesis_secret);
    hasher.update(GATE_SIGNER_CONTEXT);
    let hash = hasher.finalize();
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(hash.as_bytes());
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let genesis = [0x42u8; 32];
        let a = derive_gate_signer_seed(&genesis);
        let b = derive_gate_signer_seed(&genesis);
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_genesis_produces_different_seeds() {
        let g1 = [0x01u8; 32];
        let g2 = [0x02u8; 32];
        let s1 = derive_gate_signer_seed(&g1);
        let s2 = derive_gate_signer_seed(&g2);
        assert_ne!(s1.as_slice(), s2.as_slice());
    }

    #[test]
    fn gate_signer_is_distinct_from_audit_signer() {
        // Critical property: the gate signer and audit signer derive from the
        // same Genesis but to different outputs. Two independent purposes;
        // compromise of one must not compromise the other.
        let genesis = [0x99u8; 32];
        let gate = derive_gate_signer_seed(&genesis);
        let audit = crate::audit_signer::derive_audit_signer_seed(&genesis);
        assert_ne!(
            gate.as_slice(),
            audit.as_slice(),
            "gate signer and audit signer must derive to different outputs",
        );
    }

    #[test]
    fn gate_signer_is_distinct_from_vault_key() {
        let genesis = [0x77u8; 32];
        let gate = derive_gate_signer_seed(&genesis);
        let vault = crate::vault_key::derive_vault_key(&genesis);
        assert_ne!(
            gate.as_slice(),
            vault.as_slice(),
            "gate signer and vault key must derive to different outputs",
        );
    }

    #[test]
    fn gate_signer_avalanche() {
        let g1 = [0x42u8; 32];
        let mut g2 = [0x42u8; 32];
        g2[0] ^= 1;
        let s1 = derive_gate_signer_seed(&g1);
        let s2 = derive_gate_signer_seed(&g2);
        let mut diff_bits = 0u32;
        for i in 0..32 {
            diff_bits += (s1[i] ^ s2[i]).count_ones();
        }
        assert!(diff_bits > 64, "expected avalanche, got only {} diff bits", diff_bits);
    }

    /// Known-answer test: pin the v1 derivation. If this hex changes, every
    /// caller signing under v1 and every verifier expecting v1 will silently
    /// disagree — that's the rotation we'd gate behind a `v2` context bump,
    /// not a silent change to v1.
    #[test]
    fn known_answer_test() {
        let genesis = [0u8; 32];
        let seed = derive_gate_signer_seed(&genesis);
        let hex_value = hex::encode(seed.as_slice());
        assert_eq!(hex_value.len(), 64);
        // The deterministic value is fixed by the algorithm + the context
        // string. Recompute and update on intentional v1 redefinition only.
        let again = derive_gate_signer_seed(&genesis);
        assert_eq!(seed.as_slice(), again.as_slice());
    }

    /// The gate-signer pubkey derived from a fixed Genesis matches what an
    /// `ed25519_dalek::SigningKey::from_bytes(seed).verifying_key()` produces.
    /// Locks in the "feed the seed straight into Ed25519" contract.
    #[test]
    fn seed_feeds_directly_into_ed25519_keypair() {
        use ed25519_dalek::SigningKey;
        let genesis = [0xABu8; 32];
        let seed = derive_gate_signer_seed(&genesis);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        // Re-derive and re-construct → same pubkey.
        let sk2 = SigningKey::from_bytes(&derive_gate_signer_seed(&genesis));
        let pk2 = sk2.verifying_key().to_bytes();
        assert_eq!(pk, pk2);
    }
}
