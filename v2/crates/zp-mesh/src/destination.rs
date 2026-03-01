//! Mesh destinations — the routing primitive.
//!
//! A destination is a routable endpoint on the mesh, identified by a
//! 128-bit hash derived from the owner's public key. Destinations can be:
//!
//! - **Single**: Point-to-point, asymmetrically encrypted (one identity)
//! - **Group**: Symmetrically encrypted for multiple recipients
//! - **Plain**: Unencrypted broadcast (used for discovery)
//! - **Link**: Established encrypted channel (session-keyed)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::PUBLIC_KEY_SIZE;

/// 128-bit destination hash — the mesh address.
///
/// Derived from SHA-256 of the destination's name material and public key,
/// truncated to 16 bytes. This is the primary routing primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DestinationHash(pub [u8; 16]);

impl DestinationHash {
    /// Create from raw 16-byte hash.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Create from a combined 64-byte public key (identity-based destination).
    pub fn from_public_key(combined_key: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(combined_key);
        let full = hasher.finalize();
        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&full[..16]);
        Self(truncated)
    }

    /// Create from app name + aspects + public key (Reticulum-style).
    ///
    /// ```text
    /// hash = SHA256(app_name + "." + aspect1 + "." + aspect2 + ... + public_key_hash)[0:16]
    /// ```
    pub fn from_name_and_key(
        app_name: &str,
        aspects: &[&str],
        combined_key: &[u8; PUBLIC_KEY_SIZE],
    ) -> Self {
        let mut hasher = Sha256::new();

        // Build name material
        hasher.update(app_name.as_bytes());
        for aspect in aspects {
            hasher.update(b".");
            hasher.update(aspect.as_bytes());
        }

        // Hash of the public key
        let key_hash = Sha256::digest(combined_key);
        hasher.update(key_hash);

        let full = hasher.finalize();
        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&full[..16]);
        Self(truncated)
    }

    /// Hex string representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, crate::error::MeshError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| crate::error::MeshError::InvalidPacket(e.to_string()))?;
        if bytes.len() != 16 {
            return Err(crate::error::MeshError::InvalidPacket(format!(
                "destination hash must be 16 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Display for DestinationHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>", self.to_hex())
    }
}

/// Type of destination — determines encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DestinationType {
    /// Point-to-point encrypted with elliptic curve (identity-keyed).
    Single = 0b00,
    /// Symmetrically encrypted for multiple recipients (shared key).
    Group = 0b01,
    /// Unencrypted broadcast.
    Plain = 0b10,
    /// Established encrypted channel (session-keyed link).
    Link = 0b11,
}

impl DestinationType {
    /// Parse from the 2-bit field in the packet header.
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0b00 => Some(Self::Single),
            0b01 => Some(Self::Group),
            0b10 => Some(Self::Plain),
            0b11 => Some(Self::Link),
            _ => None,
        }
    }

    /// Encode as 2-bit field.
    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// A named destination on the mesh.
///
/// Combines the hash (for routing) with metadata about the destination
/// type and the application/aspect naming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    /// The 128-bit routing hash.
    pub hash: DestinationHash,

    /// Destination type (single, group, plain, link).
    pub destination_type: DestinationType,

    /// Application name (e.g., "zeropoint").
    pub app_name: String,

    /// Aspects (e.g., ["agent", "receipts"]).
    pub aspects: Vec<String>,
}

impl Destination {
    /// Create a new single-identity destination for a ZeroPoint agent.
    pub fn agent(combined_key: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        let hash =
            DestinationHash::from_name_and_key("zeropoint", &["agent", "receipts"], combined_key);
        Self {
            hash,
            destination_type: DestinationType::Single,
            app_name: "zeropoint".into(),
            aspects: vec!["agent".into(), "receipts".into()],
        }
    }

    /// Create a plain broadcast destination for discovery.
    pub fn discovery() -> Self {
        // Discovery uses a well-known hash (no public key component)
        let mut hasher = Sha256::new();
        hasher.update(b"zeropoint.discovery.announce");
        let full = hasher.finalize();
        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&full[..16]);

        Self {
            hash: DestinationHash(truncated),
            destination_type: DestinationType::Plain,
            app_name: "zeropoint".into(),
            aspects: vec!["discovery".into(), "announce".into()],
        }
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{} {}",
            self.app_name,
            self.aspects.join("."),
            self.hash,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MeshIdentity;

    #[test]
    fn test_destination_hash_from_public_key() {
        let id = MeshIdentity::generate();
        let hash = DestinationHash::from_public_key(&id.combined_public_key());
        assert_eq!(hash.0, id.destination_hash());
    }

    #[test]
    fn test_destination_hash_hex_roundtrip() {
        let id = MeshIdentity::generate();
        let hash = DestinationHash::from_public_key(&id.combined_public_key());
        let hex_str = hash.to_hex();
        let parsed = DestinationHash::from_hex(&hex_str).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_destination_type_bits_roundtrip() {
        for dt in [
            DestinationType::Single,
            DestinationType::Group,
            DestinationType::Plain,
            DestinationType::Link,
        ] {
            let bits = dt.to_bits();
            assert_eq!(DestinationType::from_bits(bits), Some(dt));
        }
    }

    #[test]
    fn test_named_destination_deterministic() {
        let id = MeshIdentity::generate();
        let key = id.combined_public_key();

        let h1 = DestinationHash::from_name_and_key("zeropoint", &["agent", "receipts"], &key);
        let h2 = DestinationHash::from_name_and_key("zeropoint", &["agent", "receipts"], &key);
        assert_eq!(h1, h2);

        // Different name → different hash
        let h3 = DestinationHash::from_name_and_key("other", &["agent", "receipts"], &key);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_agent_destination() {
        let id = MeshIdentity::generate();
        let dest = Destination::agent(&id.combined_public_key());
        assert_eq!(dest.destination_type, DestinationType::Single);
        assert_eq!(dest.app_name, "zeropoint");
    }

    #[test]
    fn test_discovery_destination() {
        let d1 = Destination::discovery();
        let d2 = Destination::discovery();
        assert_eq!(d1.hash, d2.hash); // Well-known hash
        assert_eq!(d1.destination_type, DestinationType::Plain);
    }
}
