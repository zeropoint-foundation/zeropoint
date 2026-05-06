//! The [`Signable`] trait — single carrier for hash-then-sign discipline.
//!
//! # The wire (Seam 20)
//!
//! Every structure in ZeroPoint that gets signed implements [`Signable`]. The
//! trait gives one method, [`Signable::canonical_preimage`], that returns the
//! deterministic bytes over which a signature is computed — the preimage. A
//! default [`Signable::canonical_hash`] wraps BLAKE3 over the preimage.
//!
//! The discipline:
//!
//! 1. The preimage MUST exclude any signature fields the object carries
//!    (otherwise the hash depends on the signature, which depends on the
//!    hash — circular).
//! 2. The preimage MUST be deterministic across calls and across
//!    implementations. Goes through [`crate::canonical`] (Seam 17) so
//!    every preimage in the workspace is byte-identical to every other
//!    canonical-form construction.
//! 3. The preimage MUST NOT include `content_hash` if the object carries
//!    one (same reason: circular).
//!
//! # Why a trait, not a free function
//!
//! Each signed type's preimage shape is type-specific (Receipt excludes
//! `content_hash`/`signature`/`signer_public_key`; CapabilityGrant
//! excludes `signature` only; AuditEntry's preimage is built externally
//! from the unsealed view). A single free function would have to either
//! handle every type's exclusions (dispatch hell) or operate on a Value
//! preimage the caller pre-built (which is what `canonical_hash(&Value)`
//! already does — that's the value-level wire). The trait lets each
//! type own the rule that says "for me, the preimage looks like this."
//!
//! # Composition with verification (Seam 5)
//!
//! When the [`zp_crypto::verify_signature`] helper lands (Seam 5), it
//! takes `&impl Signable` plus a public key and signature, and runs
//! `verify_strict` against `value.canonical_hash()`. That gives the
//! workspace one verify primitive — the entry point through which
//! every signature check passes. Per-call-site `verify_strict(...).is_ok()`
//! invocations are then forbidden by lint.

use serde::Serialize;

/// A structure whose canonical form can be signed.
///
/// Implementations MUST exclude any signature fields from the preimage.
/// The preimage MUST be deterministic — same logical value, same bytes.
pub trait Signable {
    /// Canonical preimage bytes for this object. The bytes signed by a
    /// signer and the bytes verified against by a verifier. Both sides
    /// call this method.
    ///
    /// # Failure
    ///
    /// Default impls that go through `serde_json` may fail if the
    /// type's `Serialize` impl errors. Domain implementations that
    /// hand-build the preimage typically can't fail (they construct
    /// from known fields) — they should panic on `unreachable!()`
    /// rather than mask the error.
    fn canonical_preimage(&self) -> Vec<u8>;

    /// BLAKE3 hash of [`Signable::canonical_preimage`]. Default impl
    /// is correct for every type; types should not override unless
    /// they have a specific reason (e.g. tag-prefixed hashing for
    /// domain separation).
    fn canonical_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_preimage()).as_bytes()
    }

    /// Hex-encoded form of [`Signable::canonical_hash`]. Convenience for
    /// display, logging, and string comparison; does not change what
    /// gets signed.
    fn canonical_hash_hex(&self) -> String {
        blake3::hash(&self.canonical_preimage()).to_hex().to_string()
    }
}

/// Build a default [`Signable`] impl for any `T: Serialize` whose entire
/// canonical JSON form (with no exclusions) IS the preimage.
///
/// Use sparingly — most signed types in ZeroPoint have signature fields
/// that must be excluded from the preimage, which means the
/// `Serialize`-everything default isn't safe. This helper exists for
/// internal types (announce capabilities, transcripts, etc.) whose
/// `Serialize` impl already excludes signing-related fields by virtue of
/// their structure.
///
/// # Pitfalls
///
/// If the type later gains a `signature` field and its `Serialize` impl
/// includes it, this default will start producing a circular hash. The
/// type-level discipline: when adding a signature field, switch from
/// the default to a hand-rolled `canonical_preimage` that excludes the
/// new field.
pub fn signable_from_serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    crate::canonical::canonical_bytes_of(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    /// A test type that hand-rolls its preimage (excludes `signature`).
    #[derive(Serialize)]
    struct TestSignable {
        id: String,
        payload: u32,
        #[serde(skip)]
        signature: Option<Vec<u8>>,
    }

    impl Signable for TestSignable {
        fn canonical_preimage(&self) -> Vec<u8> {
            crate::canonical::canonical_bytes_of(self)
                .expect("TestSignable serialization cannot fail")
        }
    }

    #[test]
    fn canonical_hash_excludes_skipped_signature() {
        let a = TestSignable {
            id: "x".into(),
            payload: 42,
            signature: None,
        };
        let b = TestSignable {
            id: "x".into(),
            payload: 42,
            signature: Some(b"deadbeef".to_vec()),
        };
        // Same logical value (different signature) → same preimage,
        // same hash. This is the discipline: signature can't change the
        // hash because the hash is *what gets signed*.
        assert_eq!(a.canonical_hash(), b.canonical_hash());
        assert_eq!(a.canonical_hash_hex(), b.canonical_hash_hex());
    }

    #[test]
    fn canonical_hash_changes_with_payload() {
        let a = TestSignable {
            id: "x".into(),
            payload: 1,
            signature: None,
        };
        let b = TestSignable {
            id: "x".into(),
            payload: 2,
            signature: None,
        };
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn hash_is_32_bytes_blake3() {
        let s = TestSignable {
            id: "x".into(),
            payload: 0,
            signature: None,
        };
        let h = s.canonical_hash();
        assert_eq!(h.len(), 32);
        // Same as direct BLAKE3 over the preimage.
        let direct = *blake3::hash(&s.canonical_preimage()).as_bytes();
        assert_eq!(h, direct);
    }

    #[test]
    fn hex_form_matches_byte_form() {
        let s = TestSignable {
            id: "x".into(),
            payload: 7,
            signature: None,
        };
        let bytes = s.canonical_hash();
        let hex = s.canonical_hash_hex();
        assert_eq!(hex, blake3::Hash::from_bytes(bytes).to_hex().to_string());
    }
}
