//! Content-addressed object identity.
//!
//! Per CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md §Section 4.
//!
//! Object IDs are deterministic content-addressed hashes derived from
//! the receipt(s) that produced the object plus an object-class discriminator.
//! Given identical chain input and identical config, rebuild produces
//! identical IDs — the load-bearing property that enables the rebuild-diff
//! test and stable operator references across ontology rebuilds.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 16-byte content-addressed object identifier.
///
/// First 16 bytes of the sha256 of the ID derivation input. Trades some
/// collision resistance for compact storage; 16 bytes = 128 bits, sufficient
/// for the ontology object cardinalities the substrate will realistically
/// encounter (millions of objects per operator lifetime).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(pub [u8; 16]);

impl ObjectId {
    /// Derive an ObjectId from raw hash input.
    ///
    /// Callers should use one of the typed derivation functions below rather
    /// than calling this directly — the typed functions ensure consistent
    /// derivation across ontology object classes.
    pub fn from_hash_input(input: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let full = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&full[..16]);
        ObjectId(bytes)
    }

    /// Hex representation for display / receipt-event-string embedding.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse hex representation back to ObjectId.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 16 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(ObjectId(arr))
    }

    /// Raw bytes (for SQLite BLOB storage).
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Derive a Trajectory ID from the first receipt in the trajectory plus
/// the boundary signals that triggered its creation.
///
/// Deterministic given the same inputs — rebuild produces identical IDs.
///
/// `boundary_signals_json` must be canonical JSON of the S1-S5 scores.
/// Callers are responsible for ensuring canonical form (sorted keys,
/// consistent float precision) — helper `canonicalize_boundary_signals`
/// provided in `boundary` module.
pub fn derive_trajectory_id(first_receipt_hash: &str, boundary_signals_json: &str) -> ObjectId {
    let mut input = Vec::with_capacity(64 + first_receipt_hash.len() + boundary_signals_json.len());
    input.extend_from_slice(b"trajectory:");
    input.extend_from_slice(first_receipt_hash.as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(boundary_signals_json.as_bytes());
    ObjectId::from_hash_input(&input)
}

/// Derive a Decision / Insight / Artifact / Friction ID from the originating
/// receipt and a class-specific discriminator.
///
/// The discriminator distinguishes multiple objects derivable from the same
/// receipt (e.g., a governance-request receipt could produce a Decision AND
/// an Insight — the discriminator tells them apart).
pub fn derive_object_id(
    object_type: ObjectType,
    originating_receipt_hash: &str,
    discriminator: &str,
) -> ObjectId {
    let type_prefix = object_type.as_str();
    let mut input = Vec::with_capacity(
        32 + type_prefix.len() + originating_receipt_hash.len() + discriminator.len(),
    );
    input.extend_from_slice(type_prefix.as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(originating_receipt_hash.as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(discriminator.as_bytes());
    ObjectId::from_hash_input(&input)
}

/// Derive a Relationship ID from source, target, and relationship kind.
///
/// Deterministic — the same (source, target, kind) triple never produces
/// two Relationship rows.
pub fn derive_relationship_id(
    source_type: ObjectType,
    source_id: &ObjectId,
    target_type: ObjectType,
    target_id: &ObjectId,
    kind: &str,
) -> ObjectId {
    let mut input = Vec::with_capacity(80 + kind.len());
    input.extend_from_slice(b"rel:");
    input.extend_from_slice(source_type.as_str().as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(source_id.as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(target_type.as_str().as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(target_id.as_bytes());
    input.extend_from_slice(b":");
    input.extend_from_slice(kind.as_bytes());
    ObjectId::from_hash_input(&input)
}

/// Object type discriminator for ID derivation and storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    Trajectory,
    Decision,
    Insight,
    Artifact,
    Friction,
}

impl ObjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Trajectory => "trajectory",
            ObjectType::Decision => "decision",
            ObjectType::Insight => "insight",
            ObjectType::Artifact => "artifact",
            ObjectType::Friction => "friction",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trajectory_id_is_deterministic() {
        let receipt = "abc123def456";
        let signals = r#"{"conversation":0.3,"time_gap":0.2}"#;

        let id1 = derive_trajectory_id(receipt, signals);
        let id2 = derive_trajectory_id(receipt, signals);
        assert_eq!(id1, id2);
    }

    #[test]
    fn trajectory_id_changes_with_different_receipt() {
        let signals = r#"{"conversation":0.3}"#;
        let id1 = derive_trajectory_id("aaa", signals);
        let id2 = derive_trajectory_id("bbb", signals);
        assert_ne!(id1, id2);
    }

    #[test]
    fn trajectory_id_changes_with_different_signals() {
        let receipt = "abc";
        let id1 = derive_trajectory_id(receipt, r#"{"a":0.1}"#);
        let id2 = derive_trajectory_id(receipt, r#"{"a":0.2}"#);
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_types_distinct_for_same_receipt() {
        let receipt = "same-receipt";
        let discriminator = "same";
        let dec = derive_object_id(ObjectType::Decision, receipt, discriminator);
        let ins = derive_object_id(ObjectType::Insight, receipt, discriminator);
        let art = derive_object_id(ObjectType::Artifact, receipt, discriminator);
        let fri = derive_object_id(ObjectType::Friction, receipt, discriminator);
        // All four must be distinct — type prefix in derivation input separates them.
        let mut ids = vec![dec, ins, art, fri];
        ids.sort_by_key(|id| id.0);
        ids.dedup();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn relationship_id_deterministic_on_triple() {
        let src = ObjectId::from_hash_input(b"source");
        let tgt = ObjectId::from_hash_input(b"target");
        let r1 = derive_relationship_id(
            ObjectType::Trajectory,
            &src,
            ObjectType::Decision,
            &tgt,
            "contains",
        );
        let r2 = derive_relationship_id(
            ObjectType::Trajectory,
            &src,
            ObjectType::Decision,
            &tgt,
            "contains",
        );
        assert_eq!(r1, r2);
    }

    #[test]
    fn relationship_id_directional() {
        let a = ObjectId::from_hash_input(b"a");
        let b = ObjectId::from_hash_input(b"b");
        let ab = derive_relationship_id(
            ObjectType::Trajectory,
            &a,
            ObjectType::Decision,
            &b,
            "contains",
        );
        let ba = derive_relationship_id(
            ObjectType::Decision,
            &b,
            ObjectType::Trajectory,
            &a,
            "contains",
        );
        // Directional — reversing source/target must produce a different ID.
        assert_ne!(ab, ba);
    }

    #[test]
    fn hex_roundtrip() {
        let id = derive_trajectory_id("xyz", r#"{"a":0.5}"#);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32); // 16 bytes -> 32 hex chars
        let restored = ObjectId::from_hex(&hex).expect("parse");
        assert_eq!(id, restored);
    }

    #[test]
    fn hex_invalid_length_rejected() {
        // 30 hex chars = 15 bytes, wrong length
        assert!(ObjectId::from_hex("abcdef0123456789abcdef01234567").is_err());
    }

    #[test]
    fn object_type_string_form_stable() {
        // Lock in the string form used in ID derivation — changing these
        // would break every existing chain's ID stability.
        assert_eq!(ObjectType::Trajectory.as_str(), "trajectory");
        assert_eq!(ObjectType::Decision.as_str(), "decision");
        assert_eq!(ObjectType::Insight.as_str(), "insight");
        assert_eq!(ObjectType::Artifact.as_str(), "artifact");
        assert_eq!(ObjectType::Friction.as_str(), "friction");
    }
}
