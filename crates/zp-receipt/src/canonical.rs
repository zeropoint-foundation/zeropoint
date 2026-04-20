//! Canonical serialization for deterministic signing.
//!
//! Phase 2.8 (P2-5): Ensures that structurally identical values always
//! produce the same byte sequence, regardless of field declaration order
//! or serializer implementation details.
//!
//! ## Guarantee
//!
//! `canonical_bytes(value)` produces deterministic output because:
//!
//! 1. `serde_json::json!({})` creates a `serde_json::Map` backed by
//!    `BTreeMap<String, Value>` (keys are always sorted).
//! 2. `serde_json::to_vec()` serializes `BTreeMap` in key order.
//! 3. The `preserve_order` feature of `serde_json` is NOT enabled in
//!    this workspace (which would switch to `IndexMap` and break
//!    determinism).
//!
//! This module provides a single canonical serialization function and
//! tests that pin the determinism guarantee.
//!
//! ## When to use
//!
//! Use `canonical_bytes()` before any BLAKE3 hash or Ed25519 signature
//! computation. Never hash raw struct serialization — always go through
//! the canonical form.

/// Serialize a `serde_json::Value` to deterministic canonical bytes.
///
/// For `Value::Object` (created by `serde_json::json!{}`), keys are
/// sorted alphabetically because `serde_json::Map` is `BTreeMap`-backed.
///
/// # Panics
///
/// Panics if serialization fails, which should never happen for a
/// well-formed `serde_json::Value`.
pub fn canonical_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("canonical JSON serialization cannot fail for Value")
}

/// Serialize a `serde_json::Value` to a deterministic canonical string.
pub fn canonical_string(value: &serde_json::Value) -> String {
    serde_json::to_string(value).expect("canonical JSON serialization cannot fail for Value")
}

/// Compute the BLAKE3 hash of the canonical serialization of a value.
pub fn canonical_hash(value: &serde_json::Value) -> String {
    let bytes = canonical_bytes(value);
    blake3::hash(&bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_ordering_is_alphabetical() {
        // serde_json::json!{} uses BTreeMap — keys must be sorted
        let value = serde_json::json!({
            "zebra": 1,
            "alpha": 2,
            "middle": 3,
        });

        let bytes = canonical_bytes(&value);
        let output = String::from_utf8(bytes).unwrap();

        // Keys must appear in alphabetical order
        let alpha_pos = output.find("\"alpha\"").unwrap();
        let middle_pos = output.find("\"middle\"").unwrap();
        let zebra_pos = output.find("\"zebra\"").unwrap();

        assert!(alpha_pos < middle_pos, "alpha must come before middle");
        assert!(middle_pos < zebra_pos, "middle must come before zebra");
    }

    #[test]
    fn test_determinism_across_calls() {
        let value = serde_json::json!({
            "id": "rcpt-001",
            "version": "1.0",
            "status": "success",
            "created_at": "2026-04-19T00:00:00.000Z",
        });

        let bytes1 = canonical_bytes(&value);
        let bytes2 = canonical_bytes(&value);
        assert_eq!(bytes1, bytes2, "canonical_bytes must be deterministic");
    }

    #[test]
    fn test_determinism_across_construction_order() {
        // Build the same object with fields specified in different orders.
        // serde_json::json!{} sorts by key regardless of declaration order.
        let v1 = serde_json::json!({
            "a": 1,
            "b": 2,
            "c": 3,
        });

        let v2 = serde_json::json!({
            "c": 3,
            "a": 1,
            "b": 2,
        });

        assert_eq!(
            canonical_bytes(&v1),
            canonical_bytes(&v2),
            "field declaration order must not affect canonical bytes"
        );
    }

    #[test]
    fn test_nested_objects_are_sorted() {
        let value = serde_json::json!({
            "outer_z": {
                "inner_b": 2,
                "inner_a": 1,
            },
            "outer_a": "first",
        });

        let output = canonical_string(&value);

        // Outer keys sorted
        let outer_a_pos = output.find("\"outer_a\"").unwrap();
        let outer_z_pos = output.find("\"outer_z\"").unwrap();
        assert!(outer_a_pos < outer_z_pos);

        // Inner keys sorted
        let inner_a_pos = output.find("\"inner_a\"").unwrap();
        let inner_b_pos = output.find("\"inner_b\"").unwrap();
        assert!(inner_a_pos < inner_b_pos);
    }

    #[test]
    fn test_canonical_hash_is_deterministic() {
        let value = serde_json::json!({
            "receipt_type": "Execution",
            "id": "rcpt-test",
            "status": "Success",
        });

        let hash1 = canonical_hash(&value);
        let hash2 = canonical_hash(&value);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // BLAKE3 hex output
    }

    #[test]
    fn test_null_and_missing_fields_differ() {
        let with_null = serde_json::json!({
            "a": 1,
            "b": null,
        });

        let without = serde_json::json!({
            "a": 1,
        });

        // These must produce different canonical bytes — null is not the same
        // as absent.
        assert_ne!(canonical_bytes(&with_null), canonical_bytes(&without));
    }

    /// Pin test: verify that the `preserve_order` feature is not enabled.
    ///
    /// If someone enables `preserve_order` on `serde_json`, this test will
    /// fail because field declaration order will suddenly matter.
    #[test]
    fn test_preserve_order_not_enabled() {
        // If preserve_order were enabled, these two objects would produce
        // different byte sequences because serde_json::Map would use
        // IndexMap (insertion order) instead of BTreeMap (sorted order).
        let v1 = serde_json::json!({ "z": 1, "a": 2 });
        let v2 = serde_json::json!({ "a": 2, "z": 1 });

        assert_eq!(
            canonical_bytes(&v1),
            canonical_bytes(&v2),
            "serde_json preserve_order feature must NOT be enabled — \
             canonical serialization requires BTreeMap-backed Map"
        );
    }
}
