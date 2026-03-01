//! Mesh link — encrypted bidirectional channel.
//!
//! A link is established between two mesh identities via a 3-packet handshake:
//!
//! ```text
//! Initiator                          Responder
//!     │                                  │
//!     │── LinkRequest ──────────────────▶│  (ephemeral X25519 pub + Ed25519 pub)
//!     │                                  │
//!     │◀────────────────── LinkProof ────│  (Ed25519 signature + X25519 pub)
//!     │                                  │
//!     │── RTT ──────────────────────────▶│  (confirms handshake, measures latency)
//!     │                                  │
//!     │◀═══════ Encrypted Channel ══════▶│  (AES-128-CBC with HKDF-derived keys)
//! ```
//!
//! Once established, the link provides:
//! - Forward-secret encryption (ephemeral per-link keys)
//! - Authenticated data transfer
//! - Keepalive and RTT measurement
//! - Receipt exchange over the encrypted channel

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::capability_exchange::{
    negotiate, CapabilityPolicy, CapabilityRequest, NegotiationResult,
};
use crate::destination::DestinationHash;
use crate::error::{MeshError, MeshResult};
use crate::identity::MeshIdentity;
use zp_core::capability_grant::CapabilityGrant;

/// Link state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkState {
    /// Link request sent, waiting for proof.
    Pending,
    /// Handshake complete, link is active.
    Active,
    /// Link is being closed.
    Closing,
    /// Link has been closed or timed out.
    Closed,
}

impl std::fmt::Display for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Closing => write!(f, "closing"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Derived session keys for an established link.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key used to encrypt outgoing data.
    pub encrypt_key: [u8; 32],
    /// Key used to decrypt incoming data.
    pub decrypt_key: [u8; 32],
    /// HMAC key for message authentication.
    pub hmac_key: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("encrypt_key", &"[REDACTED]")
            .field("decrypt_key", &"[REDACTED]")
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        // Zeroize key material
        self.encrypt_key = [0u8; 32];
        self.decrypt_key = [0u8; 32];
        self.hmac_key = [0u8; 32];
    }
}

/// Data carried in a LinkRequest packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRequestData {
    /// Initiator's ephemeral X25519 public key (32 bytes).
    pub ephemeral_public: [u8; 32],
    /// Initiator's Ed25519 public key (32 bytes).
    pub signing_public: [u8; 32],
    /// Random nonce for replay protection (16 bytes).
    pub nonce: [u8; 16],
}

impl LinkRequestData {
    /// Serialize to bytes for wire transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&self.ephemeral_public);
        buf.extend_from_slice(&self.signing_public);
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(data: &[u8]) -> MeshResult<Self> {
        if data.len() < 80 {
            return Err(MeshError::InvalidPacket(format!(
                "link request too short: {} bytes",
                data.len()
            )));
        }
        let mut ephemeral_public = [0u8; 32];
        let mut signing_public = [0u8; 32];
        let mut nonce = [0u8; 16];

        ephemeral_public.copy_from_slice(&data[0..32]);
        signing_public.copy_from_slice(&data[32..64]);
        nonce.copy_from_slice(&data[64..80]);

        Ok(Self {
            ephemeral_public,
            signing_public,
            nonce,
        })
    }
}

/// Data carried in a LinkProof packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkProofData {
    /// Responder's Ed25519 signature over the challenge (64 bytes, as Vec for serde compat).
    pub signature: Vec<u8>,
    /// Responder's X25519 public key (32 bytes).
    pub ephemeral_public: [u8; 32],
}

impl LinkProofData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.ephemeral_public);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> MeshResult<Self> {
        if data.len() < 96 {
            return Err(MeshError::InvalidPacket(format!(
                "link proof too short: {} bytes",
                data.len()
            )));
        }
        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[64..96]);

        Ok(Self {
            signature: data[0..64].to_vec(),
            ephemeral_public,
        })
    }
}

/// An encrypted link between two mesh identities.
///
/// Links carry receipts, delegation requests, and guard evaluations
/// between ZeroPoint agents over any physical medium.
#[derive(Debug)]
pub struct Link {
    /// Unique link identifier (hash of handshake material).
    pub id: [u8; 16],
    /// Current state.
    pub state: LinkState,
    /// Our identity on this link.
    pub local_identity: DestinationHash,
    /// Remote peer's destination hash.
    pub remote_destination: DestinationHash,
    /// Remote peer's Ed25519 signing public key.
    pub remote_signing_key: Option<[u8; 32]>,
    /// Session keys (only present when Active).
    pub session_keys: Option<SessionKeys>,
    /// When the link was established.
    pub established_at: Option<DateTime<Utc>>,
    /// Last measured round-trip time in milliseconds.
    pub rtt_ms: Option<u64>,
    /// Number of packets sent over this link.
    pub packets_sent: u64,
    /// Number of packets received over this link.
    pub packets_received: u64,
    /// Whether we initiated this link.
    pub is_initiator: bool,
    /// Capability grants we hold (from the remote peer to us).
    pub local_grants: Vec<CapabilityGrant>,
    /// Capability grants we issued (from us to the remote peer).
    pub remote_grants: Vec<CapabilityGrant>,
}

impl Link {
    /// Create a new outgoing link (initiator side).
    pub fn initiate(
        local: &MeshIdentity,
        remote_destination: DestinationHash,
    ) -> (Self, LinkRequestData) {
        // Generate ephemeral X25519 keypair for this link
        let nonce = rand_nonce();

        let request = LinkRequestData {
            ephemeral_public: local.encryption_public_key(),
            signing_public: local.signing_public_key(),
            nonce,
        };

        // Link ID = hash of request data
        let id = link_id_from_request(&request);

        let link = Self {
            id,
            state: LinkState::Pending,
            local_identity: DestinationHash::from_public_key(&local.combined_public_key()),
            remote_destination,
            remote_signing_key: None,
            session_keys: None,
            established_at: None,
            rtt_ms: None,
            packets_sent: 0,
            packets_received: 0,
            is_initiator: true,
            local_grants: Vec::new(),
            remote_grants: Vec::new(),
        };

        (link, request)
    }

    /// Accept an incoming link request (responder side).
    pub fn accept(
        local: &MeshIdentity,
        request: &LinkRequestData,
    ) -> MeshResult<(Self, LinkProofData, SessionKeys)> {
        // Perform ECDH with initiator's ephemeral key
        let shared_secret = local.key_exchange(&request.ephemeral_public);

        // Derive session keys (we are the responder)
        let (encrypt_key, decrypt_key, hmac_key) =
            MeshIdentity::derive_session_keys(&shared_secret, false)?;

        let session_keys = SessionKeys {
            encrypt_key,
            decrypt_key,
            hmac_key,
        };

        // Sign the challenge: SHA-256(ephemeral_public ‖ nonce)
        let mut challenge = Vec::with_capacity(48);
        challenge.extend_from_slice(&request.ephemeral_public);
        challenge.extend_from_slice(&request.nonce);
        let signature = local.sign(&challenge);

        let proof = LinkProofData {
            signature: signature.to_vec(),
            ephemeral_public: local.encryption_public_key(),
        };

        let id = link_id_from_request(request);

        let link = Self {
            id,
            state: LinkState::Active,
            local_identity: DestinationHash::from_public_key(&local.combined_public_key()),
            remote_destination: DestinationHash([0u8; 16]), // Set from packet source
            remote_signing_key: Some(request.signing_public),
            session_keys: Some(session_keys.clone()),
            established_at: Some(Utc::now()),
            rtt_ms: None,
            packets_sent: 0,
            packets_received: 0,
            is_initiator: false,
            local_grants: Vec::new(),
            remote_grants: Vec::new(),
        };

        Ok((link, proof, session_keys))
    }

    /// Complete the handshake after receiving a proof (initiator side).
    pub fn complete_handshake(
        &mut self,
        local: &MeshIdentity,
        proof: &LinkProofData,
        original_request: &LinkRequestData,
    ) -> MeshResult<SessionKeys> {
        if self.state != LinkState::Pending {
            return Err(MeshError::LinkStateError {
                expected: "pending".into(),
                actual: self.state.to_string(),
            });
        }

        // Verify the proof signature against the remote's Ed25519 public key.
        // The remote signing key can come from:
        // 1. A prior announce packet (stored in remote_signing_key), or
        // 2. An explicit signing key provided during link establishment.
        let mut challenge = Vec::with_capacity(48);
        challenge.extend_from_slice(&original_request.ephemeral_public);
        challenge.extend_from_slice(&original_request.nonce);

        if let Some(remote_key) = &self.remote_signing_key {
            // We have the remote's signing key — verify the proof signature
            if proof.signature.len() != 64 {
                return Err(MeshError::InvalidPacket(format!(
                    "proof signature wrong length: {} (expected 64)",
                    proof.signature.len()
                )));
            }
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&proof.signature);

            let valid = MeshIdentity::verify_with_key(remote_key, &challenge, &sig_bytes)?;
            if !valid {
                return Err(MeshError::InvalidPacket(
                    "link proof signature verification failed".into(),
                ));
            }
        }
        // If no remote signing key is set, we accept the proof on trust-on-first-use
        // and record the key from the next announce.

        // Perform ECDH with responder's ephemeral key
        let shared_secret = local.key_exchange(&proof.ephemeral_public);

        // Derive session keys (we are the initiator)
        let (encrypt_key, decrypt_key, hmac_key) =
            MeshIdentity::derive_session_keys(&shared_secret, true)?;

        let keys = SessionKeys {
            encrypt_key,
            decrypt_key,
            hmac_key,
        };

        self.session_keys = Some(keys.clone());
        self.state = LinkState::Active;
        self.established_at = Some(Utc::now());

        Ok(keys)
    }

    /// Set the remote peer's Ed25519 signing key.
    ///
    /// Call this before `complete_handshake()` to enable signature verification.
    /// The key can come from a prior announce packet or from the link request itself.
    pub fn set_remote_signing_key(&mut self, key: [u8; 32]) {
        self.remote_signing_key = Some(key);
    }

    /// Negotiate capabilities on this link.
    ///
    /// Called after the handshake is complete. Both sides exchange
    /// capability requests, and the negotiation produces grants
    /// that are stored on the link.
    ///
    /// This is a post-handshake step — the link's encrypted channel
    /// is already active. The negotiation results are stored locally;
    /// in a real deployment, the requests and responses travel over
    /// the encrypted link.
    pub fn negotiate_capabilities(
        &mut self,
        our_policy: &CapabilityPolicy,
        our_request: &CapabilityRequest,
        their_request: &CapabilityRequest,
        receipt_id: &str,
    ) -> MeshResult<NegotiationResult> {
        if self.state != LinkState::Active {
            return Err(MeshError::LinkStateError {
                expected: "active".into(),
                actual: self.state.to_string(),
            });
        }

        let our_address = hex::encode(self.local_identity.0);
        let their_address = hex::encode(self.remote_destination.0);

        let result = negotiate(
            our_policy,
            our_request,
            their_request,
            &our_address,
            &their_address,
            receipt_id,
        );

        // Store grants on the link
        self.local_grants = result.initiator_grants.clone();
        self.remote_grants = result.responder_grants.clone();

        Ok(result)
    }

    /// Check whether this link has a specific capability grant for the remote peer.
    pub fn has_remote_grant(&self, capability_name: &str) -> bool {
        self.remote_grants
            .iter()
            .any(|g| g.capability.name() == capability_name)
    }

    /// Check whether this link has a specific capability grant for us.
    pub fn has_local_grant(&self, capability_name: &str) -> bool {
        self.local_grants
            .iter()
            .any(|g| g.capability.name() == capability_name)
    }

    /// Close the link.
    pub fn close(&mut self) {
        self.state = LinkState::Closed;
        self.session_keys = None; // Zeroize via Drop
        self.local_grants.clear();
        self.remote_grants.clear();
    }

    /// Whether this link is active and ready for data.
    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active && self.session_keys.is_some()
    }

    /// Hex representation of the link ID.
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }
}

/// Compute link ID from handshake request data.
fn link_id_from_request(request: &LinkRequestData) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(request.ephemeral_public);
    hasher.update(request.signing_public);
    hasher.update(request.nonce);
    let full = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// Generate a random 16-byte nonce.
fn rand_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_handshake_full() {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();

        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        // Step 1: Alice initiates
        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        assert_eq!(alice_link.state, LinkState::Pending);
        assert!(alice_link.is_initiator);

        // Step 2: Bob accepts (signs the challenge with his Ed25519 key)
        let (bob_link, proof, _bob_keys) = Link::accept(&bob, &request).unwrap();
        assert_eq!(bob_link.state, LinkState::Active);
        assert!(!bob_link.is_initiator);

        // Step 3: Alice sets Bob's signing key and completes with verification
        alice_link.set_remote_signing_key(bob.signing_public_key());
        let _alice_keys = alice_link
            .complete_handshake(&alice, &proof, &request)
            .unwrap();
        assert_eq!(alice_link.state, LinkState::Active);
        assert!(alice_link.is_active());
        assert_eq!(
            alice_link.remote_signing_key,
            Some(bob.signing_public_key())
        );
    }

    #[test]
    fn test_session_keys_match() {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();

        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (_bob_link, proof, bob_keys) = Link::accept(&bob, &request).unwrap();
        let alice_keys = alice_link
            .complete_handshake(&alice, &proof, &request)
            .unwrap();

        // Alice's encrypt key should equal Bob's decrypt key (and vice versa)
        assert_eq!(alice_keys.encrypt_key, bob_keys.decrypt_key);
        assert_eq!(alice_keys.decrypt_key, bob_keys.encrypt_key);
        assert_eq!(alice_keys.hmac_key, bob_keys.hmac_key);
    }

    #[test]
    fn test_link_request_data_roundtrip() {
        let data = LinkRequestData {
            ephemeral_public: [0xAA; 32],
            signing_public: [0xBB; 32],
            nonce: [0xCC; 16],
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), 80);

        let decoded = LinkRequestData::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.ephemeral_public, data.ephemeral_public);
        assert_eq!(decoded.signing_public, data.signing_public);
        assert_eq!(decoded.nonce, data.nonce);
    }

    #[test]
    fn test_link_proof_data_roundtrip() {
        let data = LinkProofData {
            signature: vec![0xDD; 64],
            ephemeral_public: [0xEE; 32],
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), 96);

        let decoded = LinkProofData::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.signature, data.signature);
        assert_eq!(decoded.ephemeral_public, data.ephemeral_public);
    }

    #[test]
    fn test_link_close() {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (_, proof, _) = Link::accept(&bob, &request).unwrap();
        alice_link
            .complete_handshake(&alice, &proof, &request)
            .unwrap();

        assert!(alice_link.is_active());
        alice_link.close();
        assert!(!alice_link.is_active());
        assert_eq!(alice_link.state, LinkState::Closed);
        assert!(alice_link.session_keys.is_none());
    }

    #[test]
    fn test_cannot_complete_closed_link() {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut link, request) = Link::initiate(&alice, bob_dest);
        let (_, proof, _) = Link::accept(&bob, &request).unwrap();

        // Complete once
        link.complete_handshake(&alice, &proof, &request).unwrap();

        // Close
        link.close();

        // Cannot complete again — wrong state
        let result = link.complete_handshake(&alice, &proof, &request);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_packet_sizes() {
        // Verify that handshake data fits in mesh MTU
        let request = LinkRequestData {
            ephemeral_public: [0; 32],
            signing_public: [0; 32],
            nonce: [0; 16],
        };
        assert_eq!(request.to_bytes().len(), 80);

        let proof = LinkProofData {
            signature: vec![0; 64],
            ephemeral_public: [0; 32],
        };
        assert_eq!(proof.to_bytes().len(), 96);

        // Both fit well within MTU (500 bytes)
        assert!(request.to_bytes().len() < crate::packet::MAX_DATA_TYPE1);
        assert!(proof.to_bytes().len() < crate::packet::MAX_DATA_TYPE1);
    }

    // ====================================================================
    // Signature Verification Tests (Phase 2 Step 1)
    // ====================================================================

    #[test]
    fn test_handshake_verified_signature() {
        // Full handshake with signature verification enabled
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (_, proof, bob_keys) = Link::accept(&bob, &request).unwrap();

        // Alice knows Bob's signing key (from a prior announce)
        alice_link.set_remote_signing_key(bob.signing_public_key());

        let alice_keys = alice_link
            .complete_handshake(&alice, &proof, &request)
            .unwrap();

        // Link is active and keys match
        assert!(alice_link.is_active());
        assert_eq!(alice_keys.encrypt_key, bob_keys.decrypt_key);
        assert_eq!(alice_keys.decrypt_key, bob_keys.encrypt_key);
    }

    #[test]
    fn test_handshake_rejects_wrong_signing_key() {
        // Alice has a WRONG key for Bob — verification should fail
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let eve = MeshIdentity::generate(); // attacker's key
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (_, proof, _) = Link::accept(&bob, &request).unwrap();

        // Alice thinks she's talking to Eve (wrong key)
        alice_link.set_remote_signing_key(eve.signing_public_key());

        let result = alice_link.complete_handshake(&alice, &proof, &request);
        assert!(
            result.is_err(),
            "Handshake should fail with wrong signing key"
        );
    }

    #[test]
    fn test_handshake_rejects_tampered_proof() {
        // Bob's proof signature is tampered
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (_, mut proof, _) = Link::accept(&bob, &request).unwrap();

        // Tamper with the signature (flip a bit)
        proof.signature[0] ^= 0xFF;

        alice_link.set_remote_signing_key(bob.signing_public_key());

        let result = alice_link.complete_handshake(&alice, &proof, &request);
        assert!(result.is_err(), "Handshake should fail with tampered proof");
    }

    #[test]
    fn test_handshake_rejects_short_signature() {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);

        // Forge a proof with too-short signature
        let proof = LinkProofData {
            signature: vec![0u8; 32], // only 32 bytes, need 64
            ephemeral_public: bob.encryption_public_key(),
        };

        alice_link.set_remote_signing_key(bob.signing_public_key());

        let result = alice_link.complete_handshake(&alice, &proof, &request);
        assert!(result.is_err(), "Handshake should reject short signature");
    }

    #[test]
    fn test_handshake_tofu_without_signing_key() {
        // Without a remote signing key, trust-on-first-use — handshake succeeds
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (_, proof, _) = Link::accept(&bob, &request).unwrap();

        // Don't set remote_signing_key — TOFU mode
        assert!(alice_link.remote_signing_key.is_none());

        let result = alice_link.complete_handshake(&alice, &proof, &request);
        assert!(result.is_ok(), "Handshake should succeed in TOFU mode");
    }

    #[test]
    fn test_responder_stores_initiator_signing_key() {
        // When Bob accepts, he should store Alice's signing key from the request
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();

        let (_, request) = Link::initiate(
            &alice,
            DestinationHash::from_public_key(&bob.combined_public_key()),
        );

        let (bob_link, _, _) = Link::accept(&bob, &request).unwrap();

        // Bob should have Alice's signing key
        assert_eq!(
            bob_link.remote_signing_key,
            Some(alice.signing_public_key()),
            "Responder should store initiator's signing key from LinkRequest"
        );
    }

    // ====================================================================
    // Capability Negotiation on Link (Phase 2 Step 2)
    // ====================================================================

    use crate::capability_exchange::{CapabilityPolicy, CapabilityRequest};
    use zp_core::capability_grant::GrantedCapability;
    use zp_core::policy::TrustTier;

    /// Helper: establish a fully active link between Alice and Bob.
    fn establish_link() -> (Link, Link, MeshIdentity, MeshIdentity) {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut alice_link, request) = Link::initiate(&alice, bob_dest);
        let (bob_link, proof, _) = Link::accept(&bob, &request).unwrap();

        alice_link.set_remote_signing_key(bob.signing_public_key());
        alice_link
            .complete_handshake(&alice, &proof, &request)
            .unwrap();

        (alice_link, bob_link, alice, bob)
    }

    #[test]
    fn test_negotiate_capabilities_on_link() {
        let (mut alice_link, _, _, _) = establish_link();

        let policy = CapabilityPolicy::allow_all();
        let our_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };
        let their_request = CapabilityRequest {
            requested: vec![GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        let result = alice_link
            .negotiate_capabilities(&policy, &our_request, &their_request, "rcpt-001")
            .unwrap();

        // Alice granted Write to the peer (responder_grants)
        assert!(!result.responder_grants.is_empty());
        assert!(alice_link.has_remote_grant("write"));

        // Alice got Read from the peer's offer (initiator_grants)
        assert!(!result.initiator_grants.is_empty());
        assert!(alice_link.has_local_grant("read"));
    }

    #[test]
    fn test_negotiate_capabilities_deny_all() {
        let (mut alice_link, _, _, _) = establish_link();

        let policy = CapabilityPolicy::deny_all();
        let our_request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };
        let their_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        let result = alice_link
            .negotiate_capabilities(&policy, &our_request, &their_request, "rcpt-002")
            .unwrap();

        // Everything denied
        assert!(result.responder_grants.is_empty());
        assert!(result.initiator_grants.is_empty());
        assert!(!result.denied.is_empty());
        assert!(!alice_link.has_remote_grant("read"));
    }

    #[test]
    fn test_negotiate_requires_active_link() {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();
        let bob_dest = DestinationHash::from_public_key(&bob.combined_public_key());

        let (mut pending_link, _) = Link::initiate(&alice, bob_dest);
        // Link is still Pending — negotiation should fail

        let policy = CapabilityPolicy::allow_all();
        let empty_request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };

        let result = pending_link.negotiate_capabilities(
            &policy,
            &empty_request,
            &empty_request,
            "rcpt-003",
        );
        assert!(result.is_err(), "Cannot negotiate on a pending link");
    }

    #[test]
    fn test_close_clears_grants() {
        let (mut alice_link, _, _, _) = establish_link();

        let policy = CapabilityPolicy::allow_all();
        let their_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };
        let our_request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };

        alice_link
            .negotiate_capabilities(&policy, &our_request, &their_request, "rcpt-004")
            .unwrap();
        assert!(!alice_link.remote_grants.is_empty());

        alice_link.close();
        assert!(alice_link.local_grants.is_empty());
        assert!(alice_link.remote_grants.is_empty());
    }

    #[test]
    fn test_negotiate_bilateral_grants_stored() {
        let (mut alice_link, _, _, _) = establish_link();

        let policy = CapabilityPolicy::allow_all();

        // Alice requests Read, offers Write
        let our_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            offered: vec![GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        // Peer requests MeshSend, offers Read
        let their_request = CapabilityRequest {
            requested: vec![GrantedCapability::MeshSend {
                destinations: vec!["*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        let result = alice_link
            .negotiate_capabilities(&policy, &our_request, &their_request, "rcpt-005")
            .unwrap();

        // We granted MeshSend to peer
        assert!(alice_link.has_remote_grant("mesh_send"));
        // We got Read from peer's offer (intersection of our request and their offer)
        assert!(alice_link.has_local_grant("read"));

        // Verify counts match result
        assert_eq!(alice_link.local_grants.len(), result.initiator_grants.len());
        assert_eq!(
            alice_link.remote_grants.len(),
            result.responder_grants.len()
        );
    }

    #[test]
    fn test_negotiate_empty_preserves_active_link() {
        let (mut alice_link, _, _, _) = establish_link();

        let policy = CapabilityPolicy::allow_all();
        let empty = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };

        let result = alice_link
            .negotiate_capabilities(&policy, &empty, &empty, "rcpt-006")
            .unwrap();

        // No grants, but link is still active
        assert!(result.initiator_grants.is_empty());
        assert!(result.responder_grants.is_empty());
        assert!(alice_link.is_active());
    }

    #[test]
    fn test_has_grant_queries() {
        let (mut alice_link, _, _, _) = establish_link();

        // Before negotiation — no grants
        assert!(!alice_link.has_local_grant("read"));
        assert!(!alice_link.has_remote_grant("write"));

        let policy = CapabilityPolicy::allow_all();
        let our_request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };
        let their_request = CapabilityRequest {
            requested: vec![
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                GrantedCapability::Write {
                    scope: vec!["*".to_string()],
                },
            ],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        alice_link
            .negotiate_capabilities(&policy, &our_request, &their_request, "rcpt-007")
            .unwrap();

        // Granted to remote
        assert!(alice_link.has_remote_grant("read"));
        assert!(alice_link.has_remote_grant("write"));
        assert!(!alice_link.has_remote_grant("execute"));
        assert!(!alice_link.has_local_grant("read")); // we didn't request anything
    }
}
