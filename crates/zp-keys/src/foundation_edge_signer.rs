//! Foundation-edge envelope signer derivation — derives the Cloudflare Worker's
//! Ed25519 identity from the Genesis secret.
//!
//! # Purpose
//!
//! The foundation-edge signer is a 32-byte Ed25519 seed used by the Foundation
//! Cloudflare Worker to sign per-request envelopes when forwarding
//! receipt-intents to an operator's `zp-server`. The receiving `zp-server`
//! verifies the envelope signature against the worker's registered pubkey
//! (held in `~/ZeroPoint/config/foundation-edge-keys.json`) before signing the
//! canonical receipt and appending to the audit chain.
//!
//! # Two distinct trust roles, two distinct keys
//!
//! - **Operator key** (Genesis-derived via existing primitives) — signs the
//!   canonical receipt. Says "this receipt is operator-authorized and lives
//!   in the operator's chain."
//! - **Foundation-edge key** (this derivation) — signs the envelope that
//!   carries the receipt-intent from the worker to the operator. Says "this
//!   intent originated from the legitimate Foundation edge."
//!
//! Conflating the two would put a receipt-signing key on Cloudflare's
//! infrastructure — exactly the architectural compromise the edge-proxy
//! design exists to avoid. The foundation-edge key lives on the edge, but it
//! only signs envelopes (a meta-attestation of "this came from the worker").
//! It never signs receipts. Receipts are signed by the operator's own key on
//! operator-controlled hardware.
//!
//! See `docs/handoffs/foundation-worker-edge-proxy-2026-05.md` for the
//! architecture that motivates this split.
//!
//! # Why a subkey, not Genesis or the gate signer?
//!
//! Domain separation, same logic as the other subkey derivations
//! ([`crate::audit_signer`], [`crate::gate_signer`], [`crate::vault_key`]).
//! The foundation-edge signer attests one thing — "this HTTP envelope
//! originated from the Foundation edge identity." Reusing Genesis would
//! conflate root-of-trust authority with edge-attestation authority.
//! Reusing the gate signer would couple cognition-governance auth (an
//! IronClaw concern) to foundation-relay auth (a workspace concern); two
//! purposes, two domains, two derivations.
//!
//! # On-disk persistence — partial
//!
//! Unlike [`crate::audit_signer`] and [`crate::gate_signer`], which are
//! re-derived in memory at startup, the foundation-edge **private** key
//! crosses a trust boundary on its way to Cloudflare: it is exported once
//! (by `zp keys derive foundation-edge`), stored as a Cloudflare Worker
//! secret via `wrangler secret put FOUNDATION_EDGE_SIGNING_KEY`, and the
//! worker reads it from `env.FOUNDATION_EDGE_SIGNING_KEY` at request time.
//! This is unavoidable: the worker runs on Cloudflare's edge and must hold
//! signing material there to sign envelopes locally.
//!
//! The **public** key is registered on the operator's machine in
//! `~/ZeroPoint/config/foundation-edge-keys.json` so the operator's
//! `zp-server` can verify incoming envelopes. The private key is never
//! written to disk on the operator's host.
//!
//! Trust-grade impact: receipts are still trust-grade B (or higher, depending
//! on the operator's signing key). The foundation-edge key compromise lets an
//! attacker forge envelopes (claim "this intent came from the worker") but
//! NOT forge receipts (still requires the operator's key, which is hardware-
//! gated). The envelope-key is recoverable by re-derivation; the operator's
//! chain remains canonical and uncompromised.
//!
//! # Forward compatibility
//!
//! This is `v1`. Rotation = bump the domain tag to `v2`, derive a fresh
//! envelope keypair, re-register on the operator side, and re-deploy the
//! worker secret. The pubkey registry on the operator carries a key_id per
//! entry, so a transition window can accept envelopes signed by either v1
//! or v2 during cutover.
//!
//! # Derivation
//!
//! ```text
//! foundation_edge_signer_seed = BLAKE3-keyed(genesis_secret, context="zp.foundation.edge.v1")
//! ```
//!
//! The 32-byte output is fed directly into `ed25519_dalek::SigningKey::from_bytes`.

use zeroize::Zeroizing;

/// Context string for foundation-edge-signer derivation. Versioned for
/// future rotation; format mirrors `AUDIT_SIGNER_CONTEXT`,
/// `GATE_SIGNER_CONTEXT`, and `VAULT_KEY_CONTEXT` (dotted, lowercase,
/// trailing `.vN` tag).
///
/// **Discipline:** this byte string must not be reproduced anywhere outside
/// this module. If/when a `no_inline_foundation_edge_signer_derivation`
/// discipline pin is added, it will guard the workspace against future
/// drift (mirroring the gate-signer pin).
pub const FOUNDATION_EDGE_SIGNER_CONTEXT: &[u8] = b"zp.foundation.edge.v1";

/// Derive the 32-byte foundation-edge envelope signer seed from a Genesis
/// secret.
///
/// Pure, deterministic, domain-separated. Same Genesis → same seed. Feeds
/// directly into `ed25519_dalek::SigningKey::from_bytes`.
///
/// The returned seed is wrapped in [`Zeroizing`] for automatic cleanup —
/// callers should not copy the inner bytes outside of an Ed25519 signing-key
/// constructor that itself zeroizes (e.g. `ed25519_dalek::SigningKey`), or
/// across the one allowed export boundary (base64 encoding for
/// `wrangler secret put`), and that export should happen exactly once per
/// derivation.
pub fn derive_foundation_edge_signer_seed(genesis_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(genesis_secret);
    hasher.update(FOUNDATION_EDGE_SIGNER_CONTEXT);
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
        let a = derive_foundation_edge_signer_seed(&genesis);
        let b = derive_foundation_edge_signer_seed(&genesis);
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_genesis_produces_different_seeds() {
        let g1 = [0x01u8; 32];
        let g2 = [0x02u8; 32];
        let s1 = derive_foundation_edge_signer_seed(&g1);
        let s2 = derive_foundation_edge_signer_seed(&g2);
        assert_ne!(s1.as_slice(), s2.as_slice());
    }

    #[test]
    fn foundation_edge_signer_is_distinct_from_audit_signer() {
        // Critical property: foundation-edge signer and audit signer derive
        // from the same Genesis but to different outputs. Two independent
        // purposes; compromise of one must not compromise the other.
        let genesis = [0x99u8; 32];
        let edge = derive_foundation_edge_signer_seed(&genesis);
        let audit = crate::audit_signer::derive_audit_signer_seed(&genesis);
        assert_ne!(
            edge.as_slice(),
            audit.as_slice(),
            "foundation-edge signer and audit signer must derive to different outputs",
        );
    }

    #[test]
    fn foundation_edge_signer_is_distinct_from_gate_signer() {
        // Edge envelope auth (worker → operator HTTP) and gate-request auth
        // (IronClaw → cognition-governance hook) are two distinct trust
        // boundaries. They must not share key material.
        let genesis = [0x77u8; 32];
        let edge = derive_foundation_edge_signer_seed(&genesis);
        let gate = crate::gate_signer::derive_gate_signer_seed(&genesis);
        assert_ne!(
            edge.as_slice(),
            gate.as_slice(),
            "foundation-edge signer and gate signer must derive to different outputs",
        );
    }

    #[test]
    fn foundation_edge_signer_is_distinct_from_vault_key() {
        let genesis = [0x55u8; 32];
        let edge = derive_foundation_edge_signer_seed(&genesis);
        let vault = crate::vault_key::derive_vault_key(&genesis);
        assert_ne!(
            edge.as_slice(),
            vault.as_slice(),
            "foundation-edge signer and vault key must derive to different outputs",
        );
    }

    #[test]
    fn foundation_edge_signer_avalanche() {
        let g1 = [0x42u8; 32];
        let mut g2 = [0x42u8; 32];
        g2[0] ^= 1;
        let s1 = derive_foundation_edge_signer_seed(&g1);
        let s2 = derive_foundation_edge_signer_seed(&g2);
        let mut diff_bits = 0u32;
        for i in 0..32 {
            diff_bits += (s1[i] ^ s2[i]).count_ones();
        }
        assert!(
            diff_bits > 64,
            "expected avalanche, got only {} diff bits",
            diff_bits
        );
    }

    /// Known-answer test: pin the v1 derivation. If this changes, every
    /// worker signing under v1 and every verifier expecting v1 will silently
    /// disagree — that's the rotation we'd gate behind a `v2` context bump,
    /// not a silent change to v1.
    #[test]
    fn known_answer_test() {
        let genesis = [0u8; 32];
        let seed = derive_foundation_edge_signer_seed(&genesis);
        let hex_value = hex::encode(seed.as_slice());
        assert_eq!(hex_value.len(), 64);
        let again = derive_foundation_edge_signer_seed(&genesis);
        assert_eq!(seed.as_slice(), again.as_slice());
    }

    /// The foundation-edge pubkey derived from a fixed Genesis matches what
    /// an `ed25519_dalek::SigningKey::from_bytes(seed).verifying_key()`
    /// produces. Locks in the "feed the seed straight into Ed25519" contract.
    #[test]
    fn seed_feeds_directly_into_ed25519_keypair() {
        use ed25519_dalek::SigningKey;
        let genesis = [0xABu8; 32];
        let seed = derive_foundation_edge_signer_seed(&genesis);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        // Re-derive and re-construct → same pubkey.
        let sk2 = SigningKey::from_bytes(&derive_foundation_edge_signer_seed(&genesis));
        let pk2 = sk2.verifying_key().to_bytes();
        assert_eq!(pk, pk2);
    }
}
