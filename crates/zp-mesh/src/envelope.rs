//! Mesh envelope — receipt-in-mesh carrier.
//!
//! Wraps a ZeroPoint receipt for transmission over mesh links.
//! The primary challenge: a full JSON receipt can be 2-4 KB,
//! but mesh packets have a 465-byte data payload limit.
//!
//! ## Strategy
//!
//! 1. **CompactReceipt**: A stripped-down binary encoding of the essential
//!    receipt fields, using msgpack instead of JSON. Typically 150-300 bytes.
//!    Suitable for single-packet transmission over LoRa.
//!
//! 2. **MeshEnvelope**: The outer wrapper that adds routing metadata,
//!    sequence numbering (for multi-packet resources), and a signature.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{MeshError, MeshResult};

/// Maximum size for a compact receipt to fit in a single mesh packet.
/// Allows room for envelope overhead (signature, routing, sequence).
pub const MAX_COMPACT_RECEIPT_SIZE: usize = 380;

/// Compact binary representation of a ZeroPoint receipt.
///
/// Strips optional fields and uses msgpack encoding to produce a
/// representation that fits in a single mesh packet (~150-300 bytes
/// typical, well under the 465-byte limit).
///
/// The full receipt can be reconstructed later by merging with
/// cached metadata (executor details, timing, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactReceipt {
    /// Receipt ID (e.g., "rcpt-a1b2c3...")
    pub id: String,
    /// Receipt type: "execution", "intent", "approval", etc.
    pub rt: String,
    /// Status: "success", "failed", "denied", etc.
    pub st: String,
    /// Trust grade: "A", "B", "C", "D"
    pub tg: String,
    /// Content hash (Blake3, hex)
    pub ch: String,
    /// Created at (Unix timestamp seconds)
    pub ts: i64,
    /// Parent receipt ID (if chained)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
    /// Policy decision: "allow", "deny", "escalate"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pd: Option<String>,
    /// Policy rationale (short)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ra: Option<String>,
    /// Ed25519 signature over the content hash (hex)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sg: Option<String>,
    /// Extension data (compact JSON, for domain-specific fields)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ex: Option<serde_json::Value>,
}

impl CompactReceipt {
    /// Compress a full receipt into compact form.
    pub fn from_receipt(receipt: &zp_receipt::Receipt) -> Self {
        let tg = match receipt.trust_grade {
            zp_receipt::TrustGrade::A => "A",
            zp_receipt::TrustGrade::B => "B",
            zp_receipt::TrustGrade::C => "C",
            zp_receipt::TrustGrade::D => "D",
        };

        let rt = format!("{}", receipt.receipt_type);

        let st = match receipt.status {
            zp_receipt::Status::Success => "success",
            zp_receipt::Status::Partial => "partial",
            zp_receipt::Status::Failed => "failed",
            zp_receipt::Status::Denied => "denied",
            zp_receipt::Status::Timeout => "timeout",
            zp_receipt::Status::Pending => "pending",
        };

        let (pd, ra) = receipt
            .policy
            .as_ref()
            .map(|p| {
                let decision = match p.decision {
                    zp_receipt::Decision::Allow => "allow",
                    zp_receipt::Decision::Deny => "deny",
                    zp_receipt::Decision::Escalate => "escalate",
                    zp_receipt::Decision::AuditOnly => "audit",
                };
                (Some(decision.to_string()), p.rationale.clone())
            })
            .unwrap_or((None, None));

        Self {
            id: receipt.id.clone(),
            rt: rt.to_string(),
            st: st.to_string(),
            tg: tg.to_string(),
            ch: receipt.content_hash.clone(),
            ts: receipt.created_at.timestamp(),
            pr: receipt.parent_receipt_id.clone(),
            pd,
            ra,
            sg: receipt.signature.clone(),
            ex: receipt.extensions.as_ref().map(|e| serde_json::json!(e)),
        }
    }

    /// Encode to msgpack bytes for wire transmission.
    /// Uses named (map) encoding so optional fields can be omitted safely.
    pub fn to_msgpack(&self) -> MeshResult<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    /// Decode from msgpack bytes.
    pub fn from_msgpack(data: &[u8]) -> MeshResult<Self> {
        rmp_serde::from_slice(data).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    /// Check if this compact receipt fits in a single mesh packet.
    pub fn fits_single_packet(&self) -> MeshResult<bool> {
        let encoded = self.to_msgpack()?;
        Ok(encoded.len() <= MAX_COMPACT_RECEIPT_SIZE)
    }

    /// Sweep 6 (RFC §3.2) — verify the ed25519 signature in `sg` over the
    /// content hash `ch` using the supplied verifying key.
    ///
    /// Returns:
    /// * `Ok(SignatureStatus::Valid)`     — `sg` present, signature checks.
    /// * `Ok(SignatureStatus::Unsigned)`  — `sg` is `None`.
    /// * `Err(MeshError::Serialization)`  — `sg` is present but malformed
    ///   (not hex, wrong length) or verification failed.
    ///
    /// The signed preimage is exactly the bytes of the hex `ch` string.
    /// This matches the producer contract: peers sign `ch.as_bytes()` with
    /// their ed25519 signing key at receipt-compaction time.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> MeshResult<SignatureStatus> {
        use ed25519_dalek::{Signature, Verifier};

        let Some(sig_hex) = self.sg.as_deref() else {
            return Ok(SignatureStatus::Unsigned);
        };

        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| MeshError::Serialization(format!("signature hex: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(MeshError::Serialization(format!(
                "signature length: expected 64, got {}",
                sig_bytes.len()
            )));
        }
        let mut fixed = [0u8; 64];
        fixed.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&fixed);

        key.verify(self.ch.as_bytes(), &sig)
            .map(|()| SignatureStatus::Valid)
            .map_err(|e| MeshError::Serialization(format!("signature verify: {e}")))
    }

    /// Sign this compact receipt's content hash with the supplied signing
    /// key, populating `self.sg`. Used by senders and by Sweep 6 tests.
    pub fn sign_content_hash(&mut self, signing: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let sig = signing.sign(self.ch.as_bytes());
        self.sg = Some(hex::encode(sig.to_bytes()));
    }
}

/// Result of verifying a `CompactReceipt` signature against a peer key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// `sg` field was present and verified against the supplied key.
    Valid,
    /// `sg` field was absent; nothing to verify.
    Unsigned,
}

/// Compact wire representation of a capability delegation grant.
///
/// Uses short field names and strips non-essential fields to fit within
/// the 465-byte mesh packet MTU when wrapped in a MeshEnvelope.
/// Similar strategy to CompactReceipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactDelegation {
    /// Grant ID (e.g., "grant-...")
    pub id: String,
    /// Capability type: "r"=Read, "w"=Write, "x"=Execute, "a"=Admin, "c"=Composite
    pub ct: String,
    /// Scope strings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sc: Vec<String>,
    /// Tools (Execute only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tl: Vec<String>,
    /// Grantor
    pub gr: String,
    /// Grantee
    pub ge: String,
    /// Trust tier (as u8)
    pub tt: u8,
    /// Created at (Unix timestamp)
    pub ts: i64,
    /// Receipt ID
    pub ri: String,
    /// Parent grant ID (if delegated)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pi: Option<String>,
    /// Delegation depth
    #[serde(default)]
    pub dd: u8,
    /// Max delegation depth
    #[serde(default = "default_max_del_depth")]
    pub md: u8,
    /// Expiry (Unix timestamp, if set)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ex: Option<i64>,
}

fn default_max_del_depth() -> u8 {
    3
}

impl CompactDelegation {
    /// Compress a full CapabilityGrant into compact wire form.
    pub fn from_grant(grant: &zp_core::CapabilityGrant) -> Self {
        let (ct, sc, tl) = match &grant.capability {
            zp_core::GrantedCapability::Read { scope } => ("r".to_string(), scope.clone(), vec![]),
            zp_core::GrantedCapability::Write { scope } => ("w".to_string(), scope.clone(), vec![]),
            zp_core::GrantedCapability::Execute { languages } => {
                ("x".to_string(), languages.clone(), vec![])
            }
            zp_core::GrantedCapability::CredentialAccess { credential_refs } => {
                ("cr".to_string(), credential_refs.clone(), vec![])
            }
            zp_core::GrantedCapability::ApiCall { endpoints } => {
                ("ac".to_string(), endpoints.clone(), vec![])
            }
            zp_core::GrantedCapability::ConfigChange { settings } => {
                ("cc".to_string(), settings.clone(), vec![])
            }
            zp_core::GrantedCapability::MeshSend { destinations } => {
                ("ms".to_string(), destinations.clone(), vec![])
            }
            zp_core::GrantedCapability::Custom { name, parameters } => (
                "cu".to_string(),
                vec![name.clone()],
                vec![parameters.to_string()],
            ),
        };

        let tt = match grant.trust_tier {
            zp_core::policy::TrustTier::Tier0 => 0,
            zp_core::policy::TrustTier::Tier1 => 1,
            zp_core::policy::TrustTier::Tier2 => 2,
        };

        Self {
            id: grant.id.clone(),
            ct,
            sc,
            tl,
            gr: grant.grantor.clone(),
            ge: grant.grantee.clone(),
            tt,
            ts: grant.created_at.timestamp(),
            ri: grant.receipt_id.clone(),
            pi: grant.parent_grant_id.clone(),
            dd: grant.delegation_depth,
            md: grant.max_delegation_depth,
            ex: grant.expires_at.map(|dt| dt.timestamp()),
        }
    }

    /// Reconstruct a CapabilityGrant from compact form.
    ///
    /// Note: constraints and signature are not preserved in compact form.
    pub fn to_grant(&self) -> zp_core::CapabilityGrant {
        use chrono::{DateTime, Utc};

        let capability = match self.ct.as_str() {
            "r" => zp_core::GrantedCapability::Read {
                scope: self.sc.clone(),
            },
            "w" => zp_core::GrantedCapability::Write {
                scope: self.sc.clone(),
            },
            "x" => zp_core::GrantedCapability::Execute {
                languages: self.sc.clone(),
            },
            "cr" => zp_core::GrantedCapability::CredentialAccess {
                credential_refs: self.sc.clone(),
            },
            "ac" => zp_core::GrantedCapability::ApiCall {
                endpoints: self.sc.clone(),
            },
            "cc" => zp_core::GrantedCapability::ConfigChange {
                settings: self.sc.clone(),
            },
            "ms" => zp_core::GrantedCapability::MeshSend {
                destinations: self.sc.clone(),
            },
            "cu" => zp_core::GrantedCapability::Custom {
                name: self.sc.first().cloned().unwrap_or_default(),
                parameters: self
                    .tl
                    .first()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(serde_json::Value::Null),
            },
            _ => zp_core::GrantedCapability::Read {
                scope: self.sc.clone(),
            },
        };

        let trust_tier = match self.tt {
            0 => zp_core::policy::TrustTier::Tier0,
            1 => zp_core::policy::TrustTier::Tier1,
            _ => zp_core::policy::TrustTier::Tier2,
        };

        let created_at = DateTime::<Utc>::from_timestamp(self.ts, 0).unwrap_or_else(Utc::now);

        let expires_at = self
            .ex
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0));

        zp_core::CapabilityGrant {
            id: self.id.clone(),
            capability,
            constraints: Vec::new(),
            grantor: self.gr.clone(),
            grantee: self.ge.clone(),
            trust_tier,
            created_at,
            expires_at,
            receipt_id: self.ri.clone(),
            signature: None,
            signer_public_key: None,
            parent_grant_id: self.pi.clone(),
            delegation_depth: self.dd,
            max_delegation_depth: self.md,
            provenance: zp_core::GrantProvenance::default(),
        }
    }

    /// Encode to msgpack bytes.
    pub fn to_msgpack(&self) -> MeshResult<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    /// Decode from msgpack bytes.
    pub fn from_msgpack(data: &[u8]) -> MeshResult<Self> {
        rmp_serde::from_slice(data).map_err(|e| MeshError::Serialization(e.to_string()))
    }
}

/// Envelope type — what kind of payload this envelope carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EnvelopeType {
    /// A compact receipt.
    Receipt = 0x01,
    /// A delegation request (agent→agent).
    Delegation = 0x02,
    /// A guard evaluation request.
    GuardRequest = 0x03,
    /// A guard evaluation response.
    GuardResponse = 0x04,
    /// An announce with agent capabilities.
    AgentAnnounce = 0x05,
    /// A receipt chain segment (multiple receipts).
    ReceiptChain = 0x06,

    // --- Phase 3: Policy propagation ---
    /// Broadcast of loaded policy module metadata.
    PolicyAdvertisement = 0x10,
    /// Request to pull specific policy modules by hash.
    PolicyPullRequest = 0x11,
    /// Response indicating which modules will be sent.
    PolicyPullResponse = 0x12,
    /// Propose which policies should govern a link.
    PolicyProposal = 0x13,
    /// Vote on a policy proposal.
    PolicyVote = 0x14,
    /// Finalized agreement on enforced policies.
    PolicyAgreement = 0x15,
    /// A chunk of WASM module bytes.
    PolicyChunk = 0x16,

    // --- Phase 3 Step 3: Collective audit ---
    /// An audit challenge requesting chain segments from a peer.
    AuditChallenge = 0x20,
    /// An audit response containing compact audit entries.
    AuditResponse = 0x21,
    /// An attestation that a peer's audit chain was verified.
    AuditAttestation = 0x22,

    // --- Phase 3 Step 4: Reputation ---
    /// A reputation summary broadcast about a peer.
    ReputationSummary = 0x30,
}

/// Mesh envelope — the carrier for receipts and agent messages.
///
/// Adds routing metadata, sequencing, and authentication around
/// the payload (typically a CompactReceipt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelope {
    /// Envelope type.
    pub envelope_type: EnvelopeType,
    /// Sender's destination hash (16 bytes, hex).
    pub sender: String,
    /// Sequence number (for ordering and dedup).
    pub seq: u64,
    /// Timestamp (Unix seconds).
    pub ts: i64,
    /// The payload (msgpack-encoded inner data).
    pub payload: Vec<u8>,
    /// Ed25519 signature over (envelope_type ‖ sender ‖ seq ‖ ts ‖ payload), 64 bytes.
    pub signature: Vec<u8>,
}

impl MeshEnvelope {
    /// Create and sign an envelope carrying a compact receipt.
    pub fn receipt(
        identity: &crate::identity::MeshIdentity,
        receipt: &CompactReceipt,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload = receipt.to_msgpack()?;
        Self::new(identity, EnvelopeType::Receipt, payload, seq)
    }

    /// Create and sign an envelope with arbitrary typed payload.
    pub fn new(
        identity: &crate::identity::MeshIdentity,
        envelope_type: EnvelopeType,
        payload: Vec<u8>,
        seq: u64,
    ) -> MeshResult<Self> {
        let sender = identity.address();
        let ts = Utc::now().timestamp();

        // Build signing material
        let sign_data = signing_material(envelope_type as u8, &sender, seq, ts, &payload);
        let signature = identity.sign(&sign_data).to_vec();

        Ok(Self {
            envelope_type,
            sender,
            seq,
            ts,
            payload,
            signature,
        })
    }

    /// Encode to msgpack bytes for inclusion in a mesh packet.
    /// Uses named (map) encoding for forward compatibility.
    pub fn to_msgpack(&self) -> MeshResult<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    /// Decode from msgpack bytes.
    pub fn from_msgpack(data: &[u8]) -> MeshResult<Self> {
        rmp_serde::from_slice(data).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    /// Verify the envelope signature against a known public key.
    pub fn verify(&self, signing_public_key: &[u8; 32]) -> MeshResult<bool> {
        if self.signature.len() != 64 {
            return Err(MeshError::InvalidPacket(format!(
                "signature must be 64 bytes, got {}",
                self.signature.len()
            )));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&self.signature);

        let sign_data = signing_material(
            self.envelope_type as u8,
            &self.sender,
            self.seq,
            self.ts,
            &self.payload,
        );
        crate::identity::MeshIdentity::verify_with_key(signing_public_key, &sign_data, &sig)
    }

    /// Extract the compact receipt from a Receipt-type envelope.
    pub fn extract_receipt(&self) -> MeshResult<CompactReceipt> {
        if self.envelope_type as u8 != EnvelopeType::Receipt as u8 {
            return Err(MeshError::InvalidPacket(
                "envelope is not a receipt type".into(),
            ));
        }
        CompactReceipt::from_msgpack(&self.payload)
    }

    /// Create and sign an envelope carrying a compact delegation.
    pub fn delegation(
        identity: &crate::identity::MeshIdentity,
        delegation: &CompactDelegation,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload = delegation.to_msgpack()?;
        Self::new(identity, EnvelopeType::Delegation, payload, seq)
    }

    /// Extract the compact delegation from a Delegation-type envelope.
    pub fn extract_delegation(&self) -> MeshResult<CompactDelegation> {
        if self.envelope_type as u8 != EnvelopeType::Delegation as u8 {
            return Err(MeshError::InvalidPacket(
                "envelope is not a delegation type".into(),
            ));
        }
        CompactDelegation::from_msgpack(&self.payload)
    }

    /// Create and sign an envelope carrying a policy advertisement.
    pub fn policy_advertisement(
        identity: &crate::identity::MeshIdentity,
        ad: &crate::policy_sync::PolicyAdvertisement,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload =
            rmp_serde::to_vec_named(ad).map_err(|e| MeshError::Serialization(e.to_string()))?;
        Self::new(identity, EnvelopeType::PolicyAdvertisement, payload, seq)
    }

    /// Create and sign an envelope carrying a policy chunk.
    pub fn policy_chunk(
        identity: &crate::identity::MeshIdentity,
        chunk: &crate::policy_sync::PolicyChunk,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload =
            rmp_serde::to_vec_named(chunk).map_err(|e| MeshError::Serialization(e.to_string()))?;
        Self::new(identity, EnvelopeType::PolicyChunk, payload, seq)
    }

    // =========================================================================
    // Phase 3 Step 3: Collective Audit envelopes
    // =========================================================================

    /// Create and sign an envelope carrying an audit challenge.
    pub fn audit_challenge(
        identity: &crate::identity::MeshIdentity,
        challenge: &zp_audit::AuditChallenge,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload = rmp_serde::to_vec_named(challenge)
            .map_err(|e| MeshError::Serialization(e.to_string()))?;
        Self::new(identity, EnvelopeType::AuditChallenge, payload, seq)
    }

    /// Create and sign an envelope carrying an audit response.
    pub fn audit_response(
        identity: &crate::identity::MeshIdentity,
        response: &zp_audit::AuditResponse,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload = rmp_serde::to_vec_named(response)
            .map_err(|e| MeshError::Serialization(e.to_string()))?;
        Self::new(identity, EnvelopeType::AuditResponse, payload, seq)
    }

    /// Create and sign an envelope carrying a peer audit attestation.
    pub fn audit_attestation(
        identity: &crate::identity::MeshIdentity,
        attestation: &zp_audit::PeerAuditAttestation,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload = rmp_serde::to_vec_named(attestation)
            .map_err(|e| MeshError::Serialization(e.to_string()))?;
        Self::new(identity, EnvelopeType::AuditAttestation, payload, seq)
    }

    /// Extract an audit challenge from an AuditChallenge-type envelope.
    pub fn extract_audit_challenge(&self) -> MeshResult<zp_audit::AuditChallenge> {
        if self.envelope_type as u8 != EnvelopeType::AuditChallenge as u8 {
            return Err(MeshError::InvalidPacket(
                "envelope is not an audit challenge type".into(),
            ));
        }
        rmp_serde::from_slice(&self.payload).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    /// Extract an audit response from an AuditResponse-type envelope.
    pub fn extract_audit_response(&self) -> MeshResult<zp_audit::AuditResponse> {
        if self.envelope_type as u8 != EnvelopeType::AuditResponse as u8 {
            return Err(MeshError::InvalidPacket(
                "envelope is not an audit response type".into(),
            ));
        }
        rmp_serde::from_slice(&self.payload).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    /// Extract a peer audit attestation from an AuditAttestation-type envelope.
    pub fn extract_audit_attestation(&self) -> MeshResult<zp_audit::PeerAuditAttestation> {
        if self.envelope_type as u8 != EnvelopeType::AuditAttestation as u8 {
            return Err(MeshError::InvalidPacket(
                "envelope is not an audit attestation type".into(),
            ));
        }
        rmp_serde::from_slice(&self.payload).map_err(|e| MeshError::Serialization(e.to_string()))
    }

    // =========================================================================
    // Phase 3 Step 4: Reputation envelopes
    // =========================================================================

    /// Create and sign an envelope carrying a reputation summary.
    pub fn reputation_summary(
        identity: &crate::identity::MeshIdentity,
        summary: &crate::reputation::CompactReputationSummary,
        seq: u64,
    ) -> MeshResult<Self> {
        let payload = summary.to_msgpack()?;
        Self::new(identity, EnvelopeType::ReputationSummary, payload, seq)
    }

    /// Extract a reputation summary from a ReputationSummary-type envelope.
    pub fn extract_reputation_summary(
        &self,
    ) -> MeshResult<crate::reputation::CompactReputationSummary> {
        if self.envelope_type as u8 != EnvelopeType::ReputationSummary as u8 {
            return Err(MeshError::InvalidPacket(
                "envelope is not a reputation summary type".into(),
            ));
        }
        crate::reputation::CompactReputationSummary::from_msgpack(&self.payload)
    }

    /// Total wire size of this envelope when msgpack-encoded.
    pub fn wire_size(&self) -> MeshResult<usize> {
        Ok(self.to_msgpack()?.len())
    }
}

/// Build the canonical bytes for signing/verification.
fn signing_material(envelope_type: u8, sender: &str, seq: u64, ts: i64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + 32 + 8 + 8 + payload.len());
    data.push(envelope_type);
    data.extend_from_slice(sender.as_bytes());
    data.extend_from_slice(&seq.to_be_bytes());
    data.extend_from_slice(&ts.to_be_bytes());
    data.extend_from_slice(payload);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MeshIdentity;

    fn make_test_receipt() -> zp_receipt::Receipt {
        zp_receipt::Receipt::execution("test-agent")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C)
            .executor_type(zp_receipt::ExecutorType::Agent)
            .runtime("shell")
            .action(zp_receipt::Action::shell_command("ls -la", 0))
            .policy_full(zp_receipt::PolicyDecision {
                decision: zp_receipt::Decision::Allow,
                policy_id: Some("zp-guard-v2".into()),
                trust_tier: None,
                rationale: Some("Safe command".into()),
            })
            .finalize()
    }

    // ------------------------------------------------------------
    // Sweep 6 (RFC §3.2) — CompactReceipt signature policy table
    // ------------------------------------------------------------

    fn signing_pair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        use rand::rngs::OsRng;
        let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn test_sweep6_verify_signature_unsigned() {
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);
        assert!(compact.sg.is_none());
        let (_s, v) = signing_pair();
        assert_eq!(
            compact.verify_signature(&v).unwrap(),
            SignatureStatus::Unsigned
        );
    }

    #[test]
    fn test_sweep6_verify_signature_valid() {
        let receipt = make_test_receipt();
        let mut compact = CompactReceipt::from_receipt(&receipt);
        let (signing, verifying) = signing_pair();
        compact.sign_content_hash(&signing);
        assert_eq!(
            compact.verify_signature(&verifying).unwrap(),
            SignatureStatus::Valid
        );
    }

    #[test]
    fn test_sweep6_verify_signature_wrong_key_rejected() {
        let receipt = make_test_receipt();
        let mut compact = CompactReceipt::from_receipt(&receipt);
        let (signing, _) = signing_pair();
        let (_, other_verify) = signing_pair();
        compact.sign_content_hash(&signing);
        assert!(compact.verify_signature(&other_verify).is_err());
    }

    #[test]
    fn test_sweep6_verify_signature_tampered_ch_rejected() {
        let receipt = make_test_receipt();
        let mut compact = CompactReceipt::from_receipt(&receipt);
        let (signing, verifying) = signing_pair();
        compact.sign_content_hash(&signing);
        // Tamper with the content hash after signing.
        compact.ch = "0".repeat(64);
        assert!(compact.verify_signature(&verifying).is_err());
    }

    #[test]
    fn test_sweep6_verify_signature_malformed_hex_rejected() {
        let receipt = make_test_receipt();
        let mut compact = CompactReceipt::from_receipt(&receipt);
        compact.sg = Some("not-hex!!!".to_string());
        let (_, verifying) = signing_pair();
        assert!(compact.verify_signature(&verifying).is_err());
    }

    #[test]
    fn test_sweep6_verify_signature_wrong_length_rejected() {
        let receipt = make_test_receipt();
        let mut compact = CompactReceipt::from_receipt(&receipt);
        // Valid hex, but only 32 bytes instead of 64.
        compact.sg = Some("aa".repeat(32));
        let (_, verifying) = signing_pair();
        assert!(compact.verify_signature(&verifying).is_err());
    }

    #[test]
    fn test_compact_receipt_from_full() {
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);

        assert!(compact.id.starts_with("rcpt-"));
        assert_eq!(compact.rt, "execution");
        assert_eq!(compact.st, "success");
        assert_eq!(compact.tg, "C");
        assert!(!compact.ch.is_empty());
        assert_eq!(compact.pd, Some("allow".to_string()));
        assert_eq!(compact.ra, Some("Safe command".to_string()));
    }

    #[test]
    fn test_compact_receipt_msgpack_roundtrip() {
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);

        let encoded = compact.to_msgpack().unwrap();
        let decoded = CompactReceipt::from_msgpack(&encoded).unwrap();

        assert_eq!(decoded.id, compact.id);
        assert_eq!(decoded.rt, compact.rt);
        assert_eq!(decoded.tg, compact.tg);
        assert_eq!(decoded.ch, compact.ch);
    }

    #[test]
    fn test_compact_receipt_fits_mtu() {
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);
        let encoded = compact.to_msgpack().unwrap();

        // A typical receipt should be well under the limit
        println!("Compact receipt size: {} bytes", encoded.len());
        assert!(
            encoded.len() <= MAX_COMPACT_RECEIPT_SIZE,
            "Compact receipt is {} bytes, max is {}",
            encoded.len(),
            MAX_COMPACT_RECEIPT_SIZE,
        );
    }

    #[test]
    fn test_envelope_sign_and_verify() {
        let identity = MeshIdentity::generate();
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);

        let envelope = MeshEnvelope::receipt(&identity, &compact, 1).unwrap();

        // Verify with correct key
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        // Verify with wrong key fails
        let other = MeshIdentity::generate();
        assert!(!envelope.verify(&other.signing_public_key()).unwrap());
    }

    #[test]
    fn test_envelope_extract_receipt() {
        let identity = MeshIdentity::generate();
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);

        let envelope = MeshEnvelope::receipt(&identity, &compact, 42).unwrap();
        let extracted = envelope.extract_receipt().unwrap();

        assert_eq!(extracted.id, compact.id);
        assert_eq!(extracted.tg, compact.tg);
    }

    #[test]
    fn test_envelope_fits_mesh_packet() {
        let identity = MeshIdentity::generate();
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);

        let envelope = MeshEnvelope::receipt(&identity, &compact, 1).unwrap();
        let wire_size = envelope.wire_size().unwrap();

        println!("Envelope wire size: {} bytes", wire_size);
        assert!(
            wire_size <= crate::packet::MAX_DATA_TYPE1,
            "Envelope is {} bytes, max data is {}",
            wire_size,
            crate::packet::MAX_DATA_TYPE1,
        );
    }

    #[test]
    fn test_policy_advertisement_envelope_roundtrip() {
        use crate::policy_sync::{PolicyAdvertisement, PolicyModuleInfo};
        let identity = MeshIdentity::generate();
        let ad = PolicyAdvertisement {
            modules: vec![PolicyModuleInfo {
                name: "safety_gate".to_string(),
                content_hash: "abc123".to_string(),
                size_bytes: 500,
                min_tier: 0,
            }],
            sender_tier: 1,
        };

        let envelope = MeshEnvelope::policy_advertisement(&identity, &ad, 10).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::PolicyAdvertisement);
        assert_eq!(envelope.seq, 10);
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        let encoded = envelope.to_msgpack().unwrap();
        let decoded = MeshEnvelope::from_msgpack(&encoded).unwrap();
        assert_eq!(decoded.envelope_type, EnvelopeType::PolicyAdvertisement);

        // Decode the payload back to verify
        let decoded_ad: PolicyAdvertisement = rmp_serde::from_slice(&decoded.payload).unwrap();
        assert_eq!(decoded_ad.modules.len(), 1);
        assert_eq!(decoded_ad.modules[0].name, "safety_gate");
    }

    #[test]
    fn test_policy_chunk_envelope_roundtrip() {
        use crate::policy_sync::PolicyChunk;
        let identity = MeshIdentity::generate();
        let chunk = PolicyChunk {
            content_hash: "deadbeef".to_string(),
            chunk_index: 2,
            total_chunks: 5,
            data: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };

        let envelope = MeshEnvelope::policy_chunk(&identity, &chunk, 42).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::PolicyChunk);
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        let decoded_chunk: PolicyChunk = rmp_serde::from_slice(&envelope.payload).unwrap();
        assert_eq!(decoded_chunk.chunk_index, 2);
        assert_eq!(decoded_chunk.total_chunks, 5);
        assert_eq!(decoded_chunk.data, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn test_envelope_msgpack_roundtrip() {
        let identity = MeshIdentity::generate();
        let receipt = make_test_receipt();
        let compact = CompactReceipt::from_receipt(&receipt);

        let envelope = MeshEnvelope::receipt(&identity, &compact, 7).unwrap();
        let encoded = envelope.to_msgpack().unwrap();
        let decoded = MeshEnvelope::from_msgpack(&encoded).unwrap();

        assert_eq!(decoded.sender, envelope.sender);
        assert_eq!(decoded.seq, 7);
        assert_eq!(decoded.signature, envelope.signature);
    }

    #[test]
    fn test_compact_delegation_roundtrip() {
        let grant = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "rcpt1".to_string(),
        );

        let compact = CompactDelegation::from_grant(&grant);
        assert_eq!(compact.ct, "r");
        assert_eq!(compact.gr, "alice");
        assert_eq!(compact.ge, "bob");
        assert_eq!(compact.sc, vec!["data/*"]);
        assert_eq!(compact.dd, 0);

        // Msgpack roundtrip
        let bytes = compact.to_msgpack().unwrap();
        let decoded = CompactDelegation::from_msgpack(&bytes).unwrap();
        assert_eq!(decoded.id, compact.id);
        assert_eq!(decoded.ct, "r");
        assert_eq!(decoded.gr, "alice");

        // Reconstruct grant
        let reconstructed = decoded.to_grant();
        assert_eq!(reconstructed.id, grant.id);
        assert_eq!(reconstructed.grantor, "alice");
        assert_eq!(reconstructed.grantee, "bob");
    }

    #[test]
    fn test_compact_delegation_fits_mtu() {
        let grant = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "rcpt1".to_string(),
        );
        let child = grant
            .delegate(
                "charlie".to_string(),
                zp_core::GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "rcpt2".to_string(),
            )
            .unwrap();

        let compact = CompactDelegation::from_grant(&child);
        let identity = MeshIdentity::generate();
        let envelope = MeshEnvelope::delegation(&identity, &compact, 1).unwrap();
        let wire_size = envelope.wire_size().unwrap();

        println!("Delegation envelope wire size: {} bytes", wire_size);
        assert!(
            wire_size <= crate::packet::MAX_DATA_TYPE1,
            "Delegation envelope is {} bytes, max data is {}",
            wire_size,
            crate::packet::MAX_DATA_TYPE1,
        );
    }

    // ====================================================================
    // Phase 3 Step 3: Audit envelope tests
    // ====================================================================

    #[test]
    fn test_audit_challenge_envelope_roundtrip() {
        let identity = MeshIdentity::generate();
        let challenge = zp_audit::AuditChallenge::recent(5);

        let envelope = MeshEnvelope::audit_challenge(&identity, &challenge, 10).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::AuditChallenge);
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        // Msgpack roundtrip
        let encoded = envelope.to_msgpack().unwrap();
        let decoded = MeshEnvelope::from_msgpack(&encoded).unwrap();
        assert_eq!(decoded.envelope_type, EnvelopeType::AuditChallenge);

        let extracted = decoded.extract_audit_challenge().unwrap();
        assert_eq!(extracted.id, challenge.id);
    }

    #[test]
    fn test_audit_response_envelope_roundtrip() {
        let identity = MeshIdentity::generate();
        let response = zp_audit::AuditResponse {
            challenge_id: "chal-test".to_string(),
            entries: vec![],
            chain_tip: "abc123".to_string(),
            total_available: 0,
            has_more: false,
        };

        let envelope = MeshEnvelope::audit_response(&identity, &response, 20).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::AuditResponse);
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        let extracted = envelope.extract_audit_response().unwrap();
        assert_eq!(extracted.challenge_id, "chal-test");
        assert_eq!(extracted.chain_tip, "abc123");
    }

    #[test]
    fn test_audit_attestation_envelope_roundtrip() {
        use chrono::DateTime;
        let identity = MeshIdentity::generate();
        let attestation = zp_audit::PeerAuditAttestation {
            id: "att-test".to_string(),
            peer: "peer-abc".to_string(),
            oldest_hash: "aaa".to_string(),
            newest_hash: "bbb".to_string(),
            entries_verified: 5,
            chain_valid: true,
            signatures_valid: 3,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            signature: None,
        };

        let envelope = MeshEnvelope::audit_attestation(&identity, &attestation, 30).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::AuditAttestation);
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        let extracted = envelope.extract_audit_attestation().unwrap();
        assert_eq!(extracted.id, "att-test");
        assert_eq!(extracted.peer, "peer-abc");
        assert!(extracted.chain_valid);
        assert_eq!(extracted.entries_verified, 5);
    }

    #[test]
    fn test_audit_envelope_wrong_type_errors() {
        let identity = MeshIdentity::generate();
        let challenge = zp_audit::AuditChallenge::recent(3);
        let envelope = MeshEnvelope::audit_challenge(&identity, &challenge, 1).unwrap();

        // Extracting wrong type should fail
        assert!(envelope.extract_audit_response().is_err());
        assert!(envelope.extract_audit_attestation().is_err());
        assert!(envelope.extract_receipt().is_err());
    }

    // ====================================================================
    // Phase 3 Step 4: Reputation envelope tests
    // ====================================================================

    #[test]
    fn test_reputation_summary_envelope_roundtrip() {
        let identity = MeshIdentity::generate();
        let summary = crate::reputation::CompactReputationSummary {
            peer: "target_peer".to_string(),
            sc: 0.82,
            gr: "E".to_string(),
            ps: 15,
            ns: 2,
            ts: 1700000000,
        };

        let envelope = MeshEnvelope::reputation_summary(&identity, &summary, 50).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::ReputationSummary);
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        // Msgpack roundtrip
        let encoded = envelope.to_msgpack().unwrap();
        let decoded = MeshEnvelope::from_msgpack(&encoded).unwrap();
        assert_eq!(decoded.envelope_type, EnvelopeType::ReputationSummary);

        let extracted = decoded.extract_reputation_summary().unwrap();
        assert_eq!(extracted.peer, "target_peer");
        assert!((extracted.sc - 0.82).abs() < 0.001);
        assert_eq!(extracted.ps, 15);
    }

    #[test]
    fn test_reputation_envelope_fits_mtu() {
        let identity = MeshIdentity::generate();
        let summary = crate::reputation::CompactReputationSummary {
            peer: "abcdef0123456789abcdef0123456789".to_string(),
            sc: 0.95,
            gr: "E".to_string(),
            ps: 100,
            ns: 5,
            ts: 1700000000,
        };

        let envelope = MeshEnvelope::reputation_summary(&identity, &summary, 1).unwrap();
        let wire_size = envelope.wire_size().unwrap();
        println!("Reputation summary envelope wire size: {} bytes", wire_size);
        assert!(
            wire_size <= crate::packet::MAX_DATA_TYPE1,
            "Reputation envelope is {} bytes, max data is {}",
            wire_size,
            crate::packet::MAX_DATA_TYPE1,
        );
    }

    #[test]
    fn test_delegation_envelope_roundtrip() {
        let identity = MeshIdentity::generate();
        let grant = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Execute {
                languages: vec!["python".to_string(), "rust".to_string()],
            },
            "rcpt1".to_string(),
        );

        let compact = CompactDelegation::from_grant(&grant);
        let envelope = MeshEnvelope::delegation(&identity, &compact, 5).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::Delegation);
        assert!(envelope.verify(&identity.signing_public_key()).unwrap());

        let extracted = envelope.extract_delegation().unwrap();
        assert_eq!(extracted.id, grant.id);
        assert_eq!(extracted.ct, "x");
        assert_eq!(extracted.sc, vec!["python", "rust"]);
    }
}
