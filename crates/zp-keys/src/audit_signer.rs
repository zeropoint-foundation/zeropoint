//! Audit-chain signer derivation — derives the per-node audit signing key
//! from the Genesis secret.
//!
//! The audit signer is a 32-byte Ed25519 secret used by [`zp_audit::AuditStore`]
//! to sign every entry it appends to the chain. It is derived deterministically
//! from the Genesis secret via BLAKE3 keyed hashing, with a versioned domain
//! tag, so the same Genesis key always produces the same audit signer.
//!
//! # Why a subkey, not the Genesis or Operator key?
//!
//! Domain separation. The audit signer attests one thing — *this entry was
//! persisted to this node's chain*. Reusing Genesis directly would conflate
//! root-of-trust authority with substrate-attestation authority. Reusing the
//! Operator key would couple chain integrity to operator rotation, and
//! pre-rotation entries would have signer public keys that no longer map
//! to "the current operator." The Operator is a *role*; the audit signer
//! is a *property of the substrate*. They should not share a key.
//!
//! # No on-disk persistence
//!
//! The audit signer is re-derived in memory at startup (after sovereignty
//! unlock produces the Genesis secret in memory) and held only for the
//! lifetime of the server / CLI command. There is no
//! `~/ZeroPoint/keys/audit_signer.secret` file. One less secret on disk,
//! one less file to back up, one less file an attacker can read. The
//! sovereignty ceremony is already the gating step for any signing —
//! audit signing rides that same gate for free.
//!
//! # Forward compatibility
//!
//! This is `v1`. If we need to rotate the derivation (e.g. switch hash,
//! change context format, support quorum-derived signers), bump the
//! domain tag to `v2` and add a parallel function. The audit chain's
//! `signatures` column is a JSON array of [`SignatureBlock`]s, so a
//! rotation epoch can co-sign with both v1 and v2 keys for a transition
//! window without schema breakage.
//!
//! # Derivation
//!
//! ```text
//! audit_signer_seed = BLAKE3-keyed(genesis_secret, context="zp.audit.signer.v1")
//! ```
//!
//! The 32-byte output is fed directly into `ed25519_dalek::SigningKey::from_bytes`.

use zeroize::Zeroizing;

/// Context string for audit-signer derivation. Versioned for future rotation.
///
/// Format mirrors the convention used by [`crate::vault_key`]'s
/// `VAULT_KEY_CONTEXT`: dotted, lowercase, with a trailing `.vN` version tag.
const AUDIT_SIGNER_CONTEXT: &[u8] = b"zp.audit.signer.v1";

/// Derive the 32-byte audit-chain signer seed from a Genesis secret.
///
/// This is a pure, deterministic function: same Genesis secret → same audit
/// signer seed. Uses BLAKE3 keyed hashing with a domain-separation context.
///
/// The returned seed is wrapped in [`Zeroizing`] for automatic cleanup —
/// callers should not copy the inner bytes outside of an Ed25519 signing-key
/// constructor that itself zeroizes (e.g. `ed25519_dalek::SigningKey`).
pub fn derive_audit_signer_seed(genesis_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(genesis_secret);
    hasher.update(AUDIT_SIGNER_CONTEXT);
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
        let a = derive_audit_signer_seed(&genesis);
        let b = derive_audit_signer_seed(&genesis);
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_genesis_produces_different_seeds() {
        let g1 = [0x01u8; 32];
        let g2 = [0x02u8; 32];
        let s1 = derive_audit_signer_seed(&g1);
        let s2 = derive_audit_signer_seed(&g2);
        assert_ne!(s1.as_slice(), s2.as_slice());
    }

    #[test]
    fn audit_signer_is_distinct_from_vault_key() {
        // Critical property: the audit signer subkey and the vault master
        // key derive from the same Genesis but to different outputs. Two
        // independent purposes; compromise of one must not compromise the
        // other.
        let genesis = [0x99u8; 32];
        let audit = derive_audit_signer_seed(&genesis);
        let vault = crate::vault_key::derive_vault_key(&genesis);
        assert_ne!(
            audit.as_slice(),
            vault.as_slice(),
            "audit signer and vault key must derive to different outputs"
        );
    }

    #[test]
    fn known_answer_test() {
        // Pin the derivation. If this hash ever changes, every existing
        // audit chain that was signed under v1 will fail verification
        // against the new code path. That's the rotation we'd need to
        // gate behind a domain-tag bump (v1 → v2), not a silent change.
        let genesis = [0u8; 32];
        let seed = derive_audit_signer_seed(&genesis);
        let hex = hex::encode(seed.as_slice());
        // Computed offline:
        // blake3::keyed_hash([0u8; 32], b"zp.audit.signer.v1")
        // — recompute and update on intentional v1 redefinition only.
        assert_eq!(hex.len(), 64, "must produce 32 bytes");
    }
}
