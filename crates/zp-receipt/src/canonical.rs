//! Canonical JSON serialization for deterministic hashing and signing.
//!
//! # The wire (Seam 17)
//!
//! Every place in ZeroPoint that produces a hash or signature over JSON
//! data goes through this module. The architectural commitment: there is
//! one canonical form, defined once, used everywhere. Per-domain hand-
//! rolled preimages are forbidden because they're how subtle inconsistencies
//! creep in (one site sorts keys, another doesn't; one site escapes
//! Unicode one way, another differently; etc.).
//!
//! # The scheme — "ZP-canonical-v1"
//!
//! `canonical_bytes` produces deterministic output because:
//!
//! 1. `serde_json::json!({...})` and `serde_json::to_value(&T)` create a
//!    `serde_json::Map` backed by `BTreeMap<String, Value>` — keys are
//!    always serialized in lexicographic order.
//! 2. `serde_json::to_vec(&Value)` walks the BTreeMap in key order.
//! 3. The `preserve_order` feature of `serde_json` is NOT enabled in this
//!    workspace (which would switch to `IndexMap` and break determinism).
//!    The pinned test `preserve_order_not_enabled` fails the build if it
//!    ever gets enabled.
//!
//! This is a *workspace-internal* canonical form, not RFC 8785 (JCS). It
//! is sufficient for ZeroPoint's signing because every consumer of a hash
//! produced here is also a member of this workspace. If interop with
//! another implementation is ever needed, JCS would land as v2 with
//! versioned dispatch — never as a silent change to v1, which would
//! invalidate every existing hash on disk.
//!
//! # When to use which API
//!
//! - You have a `&serde_json::Value`: use [`canonical_bytes`],
//!   [`canonical_string`], or [`canonical_hash`].
//! - You have a typed struct that implements `Serialize`: use
//!   [`canonical_bytes_of`] or [`canonical_hash_of`]. They serialize via
//!   `serde_json::to_value` first, which is the conversion most callers
//!   were doing manually.
//!
//! # Discipline
//!
//! Never hash raw struct serialization — always go through one of these
//! functions. Code that calls `serde_json::to_vec(&my_struct)` followed
//! by `blake3::hash(...)` is bypassing the canonical form's guarantee
//! and is wrong even if it happens to produce the same bytes today.

use serde::Serialize;

/// Serialize a [`serde_json::Value`] to deterministic canonical bytes.
///
/// For `Value::Object` (created by `serde_json::json!{}` or
/// `serde_json::to_value`), keys are emitted in lexicographic order
/// because `serde_json::Map` is `BTreeMap`-backed.
///
/// # Panics
///
/// Panics if serialization fails, which should never happen for a
/// well-formed `serde_json::Value` (it has no non-serializable values).
pub fn canonical_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("canonical JSON serialization cannot fail for Value")
}

/// Serialize a [`serde_json::Value`] to a deterministic canonical string.
pub fn canonical_string(value: &serde_json::Value) -> String {
    serde_json::to_string(value).expect("canonical JSON serialization cannot fail for Value")
}

/// Compute the BLAKE3 hash (hex-encoded) of the canonical serialization.
pub fn canonical_hash(value: &serde_json::Value) -> String {
    let bytes = canonical_bytes(value);
    blake3::hash(&bytes).to_hex().to_string()
}

/// Compute the BLAKE3 hash (raw 32 bytes) of the canonical serialization.
///
/// Use this when you need the raw hash bytes for further signing or
/// hashing (e.g. as the message input to Ed25519). For display or
/// storage, prefer [`canonical_hash`] which returns the hex form.
pub fn canonical_hash_bytes(value: &serde_json::Value) -> [u8; 32] {
    let bytes = canonical_bytes(value);
    *blake3::hash(&bytes).as_bytes()
}

/// Serialize any [`Serialize`] type to deterministic canonical bytes.
///
/// Internally goes through `serde_json::to_value` first so the BTreeMap-
/// backed `Map` produces lexicographic key order regardless of how the
/// type's fields were declared. This is the API most callers want — if
/// you have a typed struct, you should not have to construct a
/// `serde_json::Value` yourself.
///
/// # Errors
///
/// Returns the underlying serde error if the type can't be serialized
/// (e.g. a `Map` with non-string keys, or a custom `Serialize` impl that
/// errors).
pub fn canonical_bytes_of<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    Ok(canonical_bytes(&v))
}

/// Compute the BLAKE3 hash (hex-encoded) of any [`Serialize`] type's
/// canonical form.
pub fn canonical_hash_of<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = canonical_bytes_of(value)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Compute the BLAKE3 hash (raw 32 bytes) of any [`Serialize`] type's
/// canonical form. Companion to [`canonical_hash_of`].
pub fn canonical_hash_bytes_of<T: Serialize>(value: &T) -> Result<[u8; 32], serde_json::Error> {
    let bytes = canonical_bytes_of(value)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn key_ordering_is_alphabetical() {
        // serde_json::json!{} uses BTreeMap — keys must be sorted.
        let value = serde_json::json!({
            "zebra": 1,
            "alpha": 2,
            "middle": 3,
        });

        let s = canonical_string(&value);

        let alpha = s.find("\"alpha\"").unwrap();
        let middle = s.find("\"middle\"").unwrap();
        let zebra = s.find("\"zebra\"").unwrap();
        assert!(alpha < middle && middle < zebra);
    }

    #[test]
    fn determinism_across_calls() {
        let value = serde_json::json!({"id": "rcpt-001", "version": "1.0"});
        assert_eq!(canonical_bytes(&value), canonical_bytes(&value));
    }

    #[test]
    fn determinism_across_construction_order() {
        let v1 = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let v2 = serde_json::json!({"c": 3, "a": 1, "b": 2});
        assert_eq!(canonical_bytes(&v1), canonical_bytes(&v2));
    }

    #[test]
    fn nested_objects_are_sorted() {
        let v = serde_json::json!({
            "outer_z": {"inner_b": 2, "inner_a": 1},
            "outer_a": "first",
        });
        let s = canonical_string(&v);
        assert!(s.find("\"outer_a\"").unwrap() < s.find("\"outer_z\"").unwrap());
        assert!(s.find("\"inner_a\"").unwrap() < s.find("\"inner_b\"").unwrap());
    }

    #[test]
    fn null_and_missing_fields_differ() {
        let with_null = serde_json::json!({"a": 1, "b": null});
        let without = serde_json::json!({"a": 1});
        assert_ne!(canonical_bytes(&with_null), canonical_bytes(&without));
    }

    /// Pin test: verify that the `preserve_order` feature is not enabled.
    ///
    /// If someone adds `serde_json/preserve_order` to a workspace dep,
    /// this test fails because `serde_json::Map` would switch to
    /// `IndexMap` (insertion order) instead of `BTreeMap` (sorted order),
    /// and every signed structure in the substrate would silently change
    /// its hash.
    #[test]
    fn preserve_order_not_enabled() {
        let v1 = serde_json::json!({"z": 1, "a": 2});
        let v2 = serde_json::json!({"a": 2, "z": 1});
        assert_eq!(
            canonical_bytes(&v1),
            canonical_bytes(&v2),
            "serde_json preserve_order feature must NOT be enabled"
        );
    }

    // ── Generic Serialize overloads ──────────────────────────────────

    #[derive(Serialize, Deserialize)]
    struct ExampleStruct {
        // Field declaration order is deliberately non-alphabetical to
        // prove the canonical form sorts regardless.
        zebra: u32,
        alpha: String,
        middle: bool,
    }

    #[test]
    fn struct_overload_sorts_keys_lexicographically() {
        let s = ExampleStruct {
            zebra: 1,
            alpha: "hello".to_string(),
            middle: true,
        };
        let bytes = canonical_bytes_of(&s).unwrap();
        let out = std::str::from_utf8(&bytes).unwrap();
        assert!(out.find("\"alpha\"").unwrap() < out.find("\"middle\"").unwrap());
        assert!(out.find("\"middle\"").unwrap() < out.find("\"zebra\"").unwrap());
    }

    #[test]
    fn struct_and_value_paths_agree() {
        // The same logical document, built two different ways, must
        // produce identical bytes. This is the discipline guarantee:
        // call sites that have a struct can use `_of` and call sites
        // that have a Value can use the plain helpers, and they round-
        // trip the same hash.
        let s = ExampleStruct {
            zebra: 1,
            alpha: "hello".to_string(),
            middle: true,
        };
        let v = serde_json::json!({
            "zebra": 1,
            "alpha": "hello",
            "middle": true,
        });
        assert_eq!(canonical_bytes_of(&s).unwrap(), canonical_bytes(&v));
        assert_eq!(canonical_hash_of(&s).unwrap(), canonical_hash(&v));
    }

    #[test]
    fn hash_bytes_matches_hash_hex() {
        let v = serde_json::json!({"a": 1});
        let raw = canonical_hash_bytes(&v);
        let hex = canonical_hash(&v);
        assert_eq!(hex, blake3::Hash::from_bytes(raw).to_hex().to_string());
        assert_eq!(hex.len(), 64);
    }
}
