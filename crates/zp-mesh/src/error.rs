//! Error types for mesh transport operations.

use thiserror::Error;

/// Errors that can occur during mesh transport operations.
#[derive(Error, Debug)]
pub enum MeshError {
    // === Identity & Crypto ===
    /// The provided key material is invalid.
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Key exchange failed.
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// Encryption or decryption failed.
    #[error("Cipher error: {0}")]
    CipherError(String),

    // === Packet ===
    /// Packet is malformed or truncated.
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Packet exceeds the interface MTU.
    #[error("Packet exceeds MTU ({size} > {mtu})")]
    PacketTooLarge { size: usize, mtu: usize },

    /// Hop count exceeded.
    #[error("Hop limit exceeded (max {max})")]
    HopLimitExceeded { max: u8 },

    // === Link ===
    /// Link establishment failed.
    #[error("Link failed: {0}")]
    LinkFailed(String),

    /// Link is not in the expected state.
    #[error("Link state error: expected {expected}, got {actual}")]
    LinkStateError { expected: String, actual: String },

    /// Link has timed out.
    #[error("Link timed out after {elapsed_ms}ms")]
    LinkTimeout { elapsed_ms: u64 },

    // === Peer ===
    /// Peer not found in peer registry.
    #[error("Peer not found: {0}")]
    NoPeer(String),

    // === Destination ===
    /// Destination not found in routing table.
    #[error("Destination not found: {0}")]
    DestinationNotFound(String),

    /// No path to destination.
    #[error("No path to destination: {0}")]
    NoPath(String),

    // === Transport ===
    /// Interface error.
    #[error("Interface error: {0}")]
    InterfaceError(String),

    /// No interfaces configured.
    #[error("No interfaces configured")]
    NoInterfaces,

    // === Serialization ===
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Receipt doesn't fit in mesh MTU.
    #[error("Receipt too large for mesh transport ({size} bytes, max {max})")]
    ReceiptTooLarge { size: usize, max: usize },

    // === General ===
    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for MeshError {
    fn from(e: serde_json::Error) -> Self {
        MeshError::Serialization(e.to_string())
    }
}

/// Result type for mesh operations.
pub type MeshResult<T> = Result<T, MeshError>;
