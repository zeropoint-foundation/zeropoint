//! Design decision 3 — deferred. **Do not build this into v1.**
//!
//! Per `docs/design/IDENTITY-HOSTING-ADAPTER-2026-09.md` §3: v1 CIMD
//! documents ship with `jwks` absent (PKCE + authorization code needs no
//! token-endpoint credential at all). This file exists so that the *shape*
//! of the eventual `client_auth_key` derivation — needed only if a
//! concrete external authorization server requires `private_key_jwt` — is
//! decided now, at zero cost, rather than re-litigated later.
//!
//! The derivation below is written to the exact pattern of
//! `crates/zp-keys/src/gate_signer.rs`, `audit_signer.rs`, and
//! `foundation_edge_signer.rs`: `blake3::Hasher::new_keyed(genesis_secret)`
//! keyed-hashed over a versioned, domain-separated context string, wrapped
//! in `Zeroizing`, never persisted. Reusing any of those three existing
//! keys for CIMD's JWKS was rejected in §3 for the same domain-separation
//! reason those three modules give each other: this key sits behind the
//! single most externally-reachable surface any ZP key would ever have
//! (published to the open internet by construction), so it must be able to
//! be compromised without forging a gate request, a chain receipt, or a
//! Foundation-relay envelope.
//!
//! **This file's real home, once built, is `crates/zp-keys/src/cimd_signer.rs`**
//! — a fourth sibling beside the three named above, with a `pub use` added
//! to `zp-keys/src/lib.rs`. It is not created there in this pass, for the
//! same reason this whole crate isn't registered as a workspace member yet:
//! `zp-keys/src/lib.rs` is a shared file, and this design session should
//! not be editing files two other parallel sessions might also be touching
//! this same run. Migrate this file's contents verbatim when the day comes.

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// Context string for `client_auth_key` derivation. Versioned per the same
/// rotation convention `GATE_SIGNER_CONTEXT` documents: *"Rotation = bump
/// the domain tag to v2 and add a parallel function."*
///
/// Reserved here so the tag is picked once, by this design pass, rather
/// than improvised by whichever future session actually builds this.
pub const CLIENT_AUTH_KEY_CONTEXT: &[u8] = b"zp.cimd.client_auth.v1";

/// Derive the 32-byte `client_auth_key` seed from a Genesis secret. Pure,
/// deterministic, domain-separated — same Genesis, same seed, every time.
///
/// Mirrors `zp_keys::gate_signer::derive_gate_signer_seed` exactly, modulo
/// the context string. **Not called from anywhere in this scaffold** — see
/// the module doc comment for why it should stay unused until a concrete AS
/// forces the question.
pub fn derive_client_auth_key_seed(genesis_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(genesis_secret);
    hasher.update(CLIENT_AUTH_KEY_CONTEXT);
    let hash = hasher.finalize();
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(hash.as_bytes());
    seed
}

/// Convenience: seed → signing key, for the day this is wired into a real
/// JWKS entry (see `document.rs`'s [`crate::document::Jwk`]).
pub fn client_auth_signing_key(genesis_secret: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&derive_client_auth_key_seed(genesis_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let genesis = [0x42u8; 32];
        let a = derive_client_auth_key_seed(&genesis);
        let b = derive_client_auth_key_seed(&genesis);
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_genesis_gives_different_seed() {
        let s1 = derive_client_auth_key_seed(&[1u8; 32]);
        let s2 = derive_client_auth_key_seed(&[2u8; 32]);
        assert_ne!(s1.as_slice(), s2.as_slice());
    }

    /// Domain separation from the sibling derivations: same Genesis must
    /// not produce the same seed as `derive_gate_signer_seed` would (this
    /// test can't import that function without depending on `zp-keys`, so
    /// it pins the property indirectly — same input, different context
    /// string, must not collide with the well-known gate-signer context by
    /// construction).
    #[test]
    fn context_tag_is_distinct_from_gate_signer_context() {
        assert_ne!(CLIENT_AUTH_KEY_CONTEXT, b"zp.gate.request.v1" as &[u8]);
        assert_ne!(CLIENT_AUTH_KEY_CONTEXT, b"zp.foundation.edge.v1" as &[u8]);
    }
}
