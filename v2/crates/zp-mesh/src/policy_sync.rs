//! Policy propagation protocol — agents share and negotiate WASM policy modules over the mesh.
//!
//! This module provides the protocol types and logic for:
//!
//! - **Advertising**: Agents broadcast what policy modules they have loaded (metadata only)
//! - **Pulling**: Agents request specific modules by content hash, with trust tier checks
//! - **Chunked transfer**: Large WASM binaries are split into mesh-MTU-sized chunks
//! - **Negotiation**: Bilateral agreement on which policies govern a link
//!
//! ## Protocol Flow
//!
//! ```text
//! Agent A                        Agent B
//!   │                               │
//!   ├── PolicyAdvertisement ──────>│     (broadcast loaded modules)
//!   │                               │
//!   │<── PolicyPullRequest ────────┤     (B wants module X)
//!   ├── PolicyPullResponse ───────>│     (A approves transfer)
//!   ├── PolicyChunk [0/N] ────────>│     (chunked WASM bytes)
//!   ├── PolicyChunk [1/N] ────────>│
//!   ├── PolicyChunk [N-1/N] ──────>│     (B reassembles + verifies hash)
//!   │                               │
//!   ├── PolicyProposal ───────────>│     (A proposes enforcing modules X, Y)
//!   │<── PolicyVote ───────────────┤     (B accepts X, rejects Y)
//!   ├── PolicyAgreement ──────────>│     (both enforce X)
//! ```

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum bytes per chunk. Leaves room for envelope overhead
/// (envelope_type, sender, seq, ts, signature ~100 bytes) plus
/// msgpack encoding overhead within the 465-byte MTU.
pub const CHUNK_DATA_SIZE: usize = 350;

// ---------------------------------------------------------------------------
// Advertisement
// ---------------------------------------------------------------------------

/// Advertise which policy modules this agent has loaded.
/// Broadcast to all peers so they know what's available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAdvertisement {
    /// Info about each loaded module.
    pub modules: Vec<PolicyModuleInfo>,
    /// Sender's trust tier (as u8: 0, 1, or 2).
    pub sender_tier: u8,
}

/// Compact metadata about a single policy module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyModuleInfo {
    /// Human-readable module name.
    pub name: String,
    /// Blake3 content hash (hex), used as the module's identity.
    pub content_hash: String,
    /// Size of the WASM binary in bytes.
    pub size_bytes: usize,
    /// Minimum trust tier required to receive this module (0, 1, or 2).
    pub min_tier: u8,
}

// ---------------------------------------------------------------------------
// Pull request / response
// ---------------------------------------------------------------------------

/// Request specific policy modules from a peer by content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPullRequest {
    /// Content hashes of the modules being requested.
    pub content_hashes: Vec<String>,
    /// Requester's trust tier.
    pub requester_tier: u8,
}

/// Response to a pull request: which modules will be sent, which denied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPullResponse {
    /// Hashes of modules that will be transferred.
    pub approved: Vec<String>,
    /// Hashes of modules denied with reasons.
    pub denied: Vec<PolicyDenial>,
}

/// A denied module transfer with reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDenial {
    /// Content hash of the denied module.
    pub content_hash: String,
    /// Why the transfer was denied.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Bilateral negotiation (which policies govern a link)
// ---------------------------------------------------------------------------

/// Propose which policies should govern this link.
/// Initiator sends this; responder replies with a PolicyVote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProposal {
    /// Unique proposal ID.
    pub proposal_id: String,
    /// Content hashes of policies the proposer wants both sides to enforce.
    pub proposed_hashes: Vec<String>,
    /// Proposer's trust tier.
    pub proposer_tier: u8,
}

/// Responder's vote on a policy proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVote {
    /// Matches the proposal being voted on.
    pub proposal_id: String,
    /// Hashes the voter agrees to enforce.
    pub accepted: Vec<String>,
    /// Hashes the voter rejects with reasons.
    pub rejected: Vec<PolicyDenial>,
}

/// Final agreement: which policies both sides will enforce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAgreement {
    /// Matches the original proposal.
    pub proposal_id: String,
    /// Both parties agree to enforce these modules.
    pub enforced: Vec<String>,
    /// These were rejected by one or both parties.
    pub rejected: Vec<String>,
}

// ---------------------------------------------------------------------------
// Chunked transfer
// ---------------------------------------------------------------------------

/// A chunk of WASM module bytes for transfer over the mesh.
///
/// Modules larger than a single packet (~350 bytes usable) are split
/// into numbered chunks. The receiver reassembles using a BTreeMap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChunk {
    /// Content hash of the module being transferred.
    pub content_hash: String,
    /// Zero-based chunk index.
    pub chunk_index: u16,
    /// Total number of chunks.
    pub total_chunks: u16,
    /// The chunk payload (up to CHUNK_DATA_SIZE bytes).
    pub data: Vec<u8>,
}

/// Tracks the state of an in-flight chunked transfer.
#[derive(Debug, Clone)]
pub struct TransferState {
    /// Blake3 hash we expect the reassembled bytes to match.
    pub content_hash: String,
    /// Expected total size in bytes (from the advertisement).
    pub expected_size: usize,
    /// Total number of chunks expected.
    pub total_chunks: u16,
    /// Received chunks keyed by index.
    pub chunks: BTreeMap<u16, Vec<u8>>,
    /// When the transfer started.
    pub started_at: DateTime<Utc>,
}

impl TransferState {
    /// Create a new transfer state.
    pub fn new(content_hash: String, expected_size: usize, total_chunks: u16) -> Self {
        Self {
            content_hash,
            expected_size,
            total_chunks,
            chunks: BTreeMap::new(),
            started_at: Utc::now(),
        }
    }

    /// Record a received chunk. Returns true if this was a new chunk.
    pub fn receive_chunk(&mut self, chunk: &PolicyChunk) -> bool {
        if chunk.chunk_index >= self.total_chunks {
            return false;
        }
        self.chunks
            .entry(chunk.chunk_index)
            .or_insert_with(|| chunk.data.clone());
        true
    }

    /// Check if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.chunks.len() == self.total_chunks as usize
    }

    /// How many chunks are still missing.
    pub fn missing_count(&self) -> usize {
        self.total_chunks as usize - self.chunks.len()
    }
}

// ---------------------------------------------------------------------------
// Protocol functions
// ---------------------------------------------------------------------------

/// Create a new policy proposal ID.
pub fn new_proposal_id() -> String {
    format!("pprop-{}", Uuid::now_v7())
}

/// Evaluate a pull request against local modules and trust tiers.
///
/// For each requested hash:
/// - If the module exists and the requester's tier >= min_tier → approved
/// - If the module doesn't exist → denied ("module_not_found")
/// - If the tier is insufficient → denied ("insufficient_trust_tier")
pub fn evaluate_pull_request(
    request: &PolicyPullRequest,
    local_modules: &[(PolicyModuleInfo, Vec<u8>)],
) -> PolicyPullResponse {
    let mut approved = Vec::new();
    let mut denied = Vec::new();

    for hash in &request.content_hashes {
        match local_modules
            .iter()
            .find(|(info, _)| info.content_hash == *hash)
        {
            Some((info, _bytes)) => {
                if request.requester_tier >= info.min_tier {
                    approved.push(hash.clone());
                } else {
                    denied.push(PolicyDenial {
                        content_hash: hash.clone(),
                        reason: "insufficient_trust_tier".to_string(),
                    });
                }
            }
            None => {
                denied.push(PolicyDenial {
                    content_hash: hash.clone(),
                    reason: "module_not_found".to_string(),
                });
            }
        }
    }

    PolicyPullResponse { approved, denied }
}

/// Negotiate a policy proposal: vote on which policies to accept.
///
/// The voter accepts any proposed policy that they also have loaded
/// (identified by content hash). Policies they don't have are rejected.
pub fn negotiate_policies(
    proposal: &PolicyProposal,
    our_available_hashes: &[String],
    _our_tier: u8,
) -> PolicyVote {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    for hash in &proposal.proposed_hashes {
        if our_available_hashes.contains(hash) {
            accepted.push(hash.clone());
        } else {
            rejected.push(PolicyDenial {
                content_hash: hash.clone(),
                reason: "module_not_loaded".to_string(),
            });
        }
    }

    PolicyVote {
        proposal_id: proposal.proposal_id.clone(),
        accepted,
        rejected,
    }
}

/// Finalize a policy agreement from the proposer's perspective.
///
/// The enforced set is the intersection: proposed by A AND accepted by B.
/// Everything else is rejected.
pub fn finalize_agreement(proposal: &PolicyProposal, vote: &PolicyVote) -> PolicyAgreement {
    let enforced: Vec<String> = proposal
        .proposed_hashes
        .iter()
        .filter(|h| vote.accepted.contains(h))
        .cloned()
        .collect();

    let rejected: Vec<String> = proposal
        .proposed_hashes
        .iter()
        .filter(|h| !vote.accepted.contains(h))
        .cloned()
        .collect();

    PolicyAgreement {
        proposal_id: proposal.proposal_id.clone(),
        enforced,
        rejected,
    }
}

/// Split WASM bytes into chunks for mesh transfer.
pub fn chunk_module(content_hash: &str, wasm_bytes: &[u8], chunk_size: usize) -> Vec<PolicyChunk> {
    let total_chunks = if wasm_bytes.is_empty() {
        1
    } else {
        wasm_bytes.len().div_ceil(chunk_size) as u16
    };

    wasm_bytes
        .chunks(chunk_size)
        .enumerate()
        .map(|(i, data)| PolicyChunk {
            content_hash: content_hash.to_string(),
            chunk_index: i as u16,
            total_chunks,
            data: data.to_vec(),
        })
        .collect()
}

/// Reassemble chunks into the original WASM bytes.
///
/// Returns Err if any chunks are missing.
pub fn reassemble_chunks(state: &TransferState) -> Result<Vec<u8>, String> {
    if !state.is_complete() {
        return Err(format!(
            "transfer incomplete: {} of {} chunks received",
            state.chunks.len(),
            state.total_chunks,
        ));
    }

    let mut bytes = Vec::with_capacity(state.expected_size);
    for i in 0..state.total_chunks {
        match state.chunks.get(&i) {
            Some(data) => bytes.extend_from_slice(data),
            None => {
                return Err(format!("missing chunk {}", i));
            }
        }
    }

    Ok(bytes)
}

/// Verify that reassembled bytes match the expected Blake3 hash.
pub fn verify_transfer(bytes: &[u8], expected_hash: &str) -> bool {
    let actual = blake3::hash(bytes);
    actual.to_hex().as_str() == expected_hash
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_module_info(name: &str, min_tier: u8) -> PolicyModuleInfo {
        let hash = blake3::hash(name.as_bytes()).to_hex().to_string();
        PolicyModuleInfo {
            name: name.to_string(),
            content_hash: hash,
            size_bytes: 100,
            min_tier,
        }
    }

    fn sample_wasm_bytes() -> Vec<u8> {
        // Fake WASM bytes (not a real module, just for chunking tests)
        (0u8..=255).cycle().take(1000).collect()
    }

    // --- Pull request tests ---

    #[test]
    fn test_evaluate_pull_request_grants_matching() {
        let info = sample_module_info("safety_gate", 0);
        let wasm = vec![0u8; 100];
        let local = vec![(info.clone(), wasm)];

        let request = PolicyPullRequest {
            content_hashes: vec![info.content_hash.clone()],
            requester_tier: 1,
        };

        let response = evaluate_pull_request(&request, &local);
        assert_eq!(response.approved.len(), 1);
        assert_eq!(response.approved[0], info.content_hash);
        assert!(response.denied.is_empty());
    }

    #[test]
    fn test_evaluate_pull_request_denies_insufficient_tier() {
        let info = sample_module_info("restricted_policy", 2);
        let wasm = vec![0u8; 100];
        let local = vec![(info.clone(), wasm)];

        let request = PolicyPullRequest {
            content_hashes: vec![info.content_hash.clone()],
            requester_tier: 1, // Tier 1 < min_tier 2
        };

        let response = evaluate_pull_request(&request, &local);
        assert!(response.approved.is_empty());
        assert_eq!(response.denied.len(), 1);
        assert_eq!(response.denied[0].reason, "insufficient_trust_tier");
    }

    #[test]
    fn test_evaluate_pull_request_denies_unknown_hash() {
        let local: Vec<(PolicyModuleInfo, Vec<u8>)> = vec![];
        let request = PolicyPullRequest {
            content_hashes: vec!["deadbeef".to_string()],
            requester_tier: 2,
        };

        let response = evaluate_pull_request(&request, &local);
        assert!(response.approved.is_empty());
        assert_eq!(response.denied.len(), 1);
        assert_eq!(response.denied[0].reason, "module_not_found");
    }

    #[test]
    fn test_evaluate_pull_request_mixed_results() {
        let info_ok = sample_module_info("allowed", 0);
        let info_restricted = sample_module_info("restricted", 2);
        let local = vec![
            (info_ok.clone(), vec![0u8; 50]),
            (info_restricted.clone(), vec![0u8; 50]),
        ];

        let request = PolicyPullRequest {
            content_hashes: vec![
                info_ok.content_hash.clone(),
                info_restricted.content_hash.clone(),
                "nonexistent".to_string(),
            ],
            requester_tier: 1,
        };

        let response = evaluate_pull_request(&request, &local);
        assert_eq!(response.approved.len(), 1);
        assert_eq!(response.denied.len(), 2);
    }

    // --- Negotiation tests ---

    #[test]
    fn test_negotiate_accepts_available_policies() {
        let hash_a = "hash_a".to_string();
        let hash_b = "hash_b".to_string();

        let proposal = PolicyProposal {
            proposal_id: new_proposal_id(),
            proposed_hashes: vec![hash_a.clone(), hash_b.clone()],
            proposer_tier: 2,
        };

        let our_available = vec![hash_a.clone(), hash_b.clone()];
        let vote = negotiate_policies(&proposal, &our_available, 2);

        assert_eq!(vote.accepted.len(), 2);
        assert!(vote.rejected.is_empty());
    }

    #[test]
    fn test_negotiate_rejects_unavailable() {
        let hash_a = "hash_a".to_string();
        let hash_b = "hash_b".to_string();

        let proposal = PolicyProposal {
            proposal_id: new_proposal_id(),
            proposed_hashes: vec![hash_a.clone(), hash_b.clone()],
            proposer_tier: 2,
        };

        let our_available = vec![hash_a.clone()]; // only A
        let vote = negotiate_policies(&proposal, &our_available, 2);

        assert_eq!(vote.accepted.len(), 1);
        assert_eq!(vote.accepted[0], hash_a);
        assert_eq!(vote.rejected.len(), 1);
        assert_eq!(vote.rejected[0].content_hash, hash_b);
    }

    #[test]
    fn test_finalize_agreement() {
        let hash_a = "hash_a".to_string();
        let hash_b = "hash_b".to_string();

        let proposal = PolicyProposal {
            proposal_id: "pprop-test".to_string(),
            proposed_hashes: vec![hash_a.clone(), hash_b.clone()],
            proposer_tier: 2,
        };

        let vote = PolicyVote {
            proposal_id: "pprop-test".to_string(),
            accepted: vec![hash_a.clone()],
            rejected: vec![PolicyDenial {
                content_hash: hash_b.clone(),
                reason: "module_not_loaded".to_string(),
            }],
        };

        let agreement = finalize_agreement(&proposal, &vote);
        assert_eq!(agreement.enforced, vec![hash_a]);
        assert_eq!(agreement.rejected, vec![hash_b]);
        assert_eq!(agreement.proposal_id, "pprop-test");
    }

    #[test]
    fn test_finalize_agreement_all_accepted() {
        let hashes = vec!["h1".to_string(), "h2".to_string(), "h3".to_string()];
        let proposal = PolicyProposal {
            proposal_id: "pprop-all".to_string(),
            proposed_hashes: hashes.clone(),
            proposer_tier: 2,
        };

        let vote = PolicyVote {
            proposal_id: "pprop-all".to_string(),
            accepted: hashes.clone(),
            rejected: vec![],
        };

        let agreement = finalize_agreement(&proposal, &vote);
        assert_eq!(agreement.enforced.len(), 3);
        assert!(agreement.rejected.is_empty());
    }

    // --- Chunking tests ---

    #[test]
    fn test_chunk_small_module_single_chunk() {
        let data = vec![1u8, 2, 3, 4, 5];
        let hash = blake3::hash(&data).to_hex().to_string();
        let chunks = chunk_module(&hash, &data, CHUNK_DATA_SIZE);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].total_chunks, 1);
        assert_eq!(chunks[0].data, data);
        assert_eq!(chunks[0].content_hash, hash);
    }

    #[test]
    fn test_chunk_large_module_multiple_chunks() {
        let data = sample_wasm_bytes(); // 1000 bytes
        let hash = blake3::hash(&data).to_hex().to_string();
        let chunks = chunk_module(&hash, &data, 400);

        // ceil(1000/400) = 3 chunks
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].total_chunks, 3);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[1].chunk_index, 1);
        assert_eq!(chunks[2].chunk_index, 2);
        assert_eq!(chunks[0].data.len(), 400);
        assert_eq!(chunks[1].data.len(), 400);
        assert_eq!(chunks[2].data.len(), 200);
    }

    #[test]
    fn test_reassemble_in_order() {
        let data = sample_wasm_bytes();
        let hash = blake3::hash(&data).to_hex().to_string();
        let chunks = chunk_module(&hash, &data, 400);

        let mut state = TransferState::new(hash, data.len(), chunks[0].total_chunks);
        for chunk in &chunks {
            assert!(state.receive_chunk(chunk));
        }

        assert!(state.is_complete());
        let reassembled = reassemble_chunks(&state).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_out_of_order() {
        let data = sample_wasm_bytes();
        let hash = blake3::hash(&data).to_hex().to_string();
        let chunks = chunk_module(&hash, &data, 400);

        let mut state = TransferState::new(hash, data.len(), chunks[0].total_chunks);
        // Deliver in reverse order
        for chunk in chunks.iter().rev() {
            state.receive_chunk(chunk);
        }

        assert!(state.is_complete());
        let reassembled = reassemble_chunks(&state).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_incomplete_fails() {
        let data = sample_wasm_bytes();
        let hash = blake3::hash(&data).to_hex().to_string();
        let chunks = chunk_module(&hash, &data, 400);

        let mut state = TransferState::new(hash, data.len(), chunks[0].total_chunks);
        // Only deliver first chunk
        state.receive_chunk(&chunks[0]);

        assert!(!state.is_complete());
        assert_eq!(state.missing_count(), 2);
        let err = reassemble_chunks(&state).unwrap_err();
        assert!(err.contains("incomplete"));
    }

    #[test]
    fn test_duplicate_chunk_ignored() {
        let data = vec![1u8, 2, 3];
        let hash = blake3::hash(&data).to_hex().to_string();
        let chunks = chunk_module(&hash, &data, 400);

        let mut state = TransferState::new(hash, data.len(), 1);
        assert!(state.receive_chunk(&chunks[0]));
        // Duplicate — still returns true (idempotent) but doesn't double the data
        state.receive_chunk(&chunks[0]);

        let reassembled = reassemble_chunks(&state).unwrap();
        assert_eq!(reassembled, data);
    }

    // --- Verification tests ---

    #[test]
    fn test_verify_transfer_valid_hash() {
        let data = sample_wasm_bytes();
        let hash = blake3::hash(&data).to_hex().to_string();
        assert!(verify_transfer(&data, &hash));
    }

    #[test]
    fn test_verify_transfer_tampered_bytes() {
        let data = sample_wasm_bytes();
        let hash = blake3::hash(&data).to_hex().to_string();

        let mut tampered = data.clone();
        tampered[0] ^= 0xFF;
        assert!(!verify_transfer(&tampered, &hash));
    }

    // --- Trust tier tests ---

    #[test]
    fn test_trust_tier_enforcement_higher_can_pull_from_lower() {
        let info = sample_module_info("open_policy", 0); // min_tier = 0
        let local = vec![(info.clone(), vec![0u8; 50])];

        let request = PolicyPullRequest {
            content_hashes: vec![info.content_hash.clone()],
            requester_tier: 2, // Tier 2 >= min_tier 0
        };

        let response = evaluate_pull_request(&request, &local);
        assert_eq!(response.approved.len(), 1);
    }

    #[test]
    fn test_trust_tier_enforcement_lower_cannot_pull_restricted() {
        let info = sample_module_info("tier2_only", 2); // min_tier = 2
        let local = vec![(info.clone(), vec![0u8; 50])];

        let request = PolicyPullRequest {
            content_hashes: vec![info.content_hash.clone()],
            requester_tier: 0, // Tier 0 < min_tier 2
        };

        let response = evaluate_pull_request(&request, &local);
        assert!(response.approved.is_empty());
        assert_eq!(response.denied[0].reason, "insufficient_trust_tier");
    }

    // --- Serialization tests ---

    #[test]
    fn test_advertisement_msgpack_roundtrip() {
        let ad = PolicyAdvertisement {
            modules: vec![sample_module_info("test_policy", 0)],
            sender_tier: 1,
        };

        let encoded = rmp_serde::to_vec_named(&ad).unwrap();
        let decoded: PolicyAdvertisement = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded.modules.len(), 1);
        assert_eq!(decoded.modules[0].name, "test_policy");
        assert_eq!(decoded.sender_tier, 1);
    }

    #[test]
    fn test_policy_chunk_msgpack_roundtrip() {
        let chunk = PolicyChunk {
            content_hash: "abc123".to_string(),
            chunk_index: 5,
            total_chunks: 10,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let encoded = rmp_serde::to_vec_named(&chunk).unwrap();
        let decoded: PolicyChunk = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded.chunk_index, 5);
        assert_eq!(decoded.total_chunks, 10);
        assert_eq!(decoded.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_proposal_id_format() {
        let id = new_proposal_id();
        assert!(id.starts_with("pprop-"));
        assert!(id.len() > 10);
    }
}
