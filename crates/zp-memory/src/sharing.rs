//! Multi-agent observation sharing and merge control.
//!
//! Phase 4.5: Implements the doctrine's cross-context memory safety rules.
//!
//! **Critical merge control:** When two memory contexts merge (agents sharing
//! observations, or a child returning results to a parent), the merged memory
//! resets to Observed stage regardless of its source stage. This prevents
//! memory poisoning via context blending — an adversary cannot promote memory
//! by introducing it via a trusted peer's context.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

use zp_receipt::{ClaimMetadata, ClaimSemantics, Receipt, Status};

use crate::types::{MemoryEntry, MemoryStage};

// ============================================================================
// Sharing context types
// ============================================================================

/// Describes the sharing relationship between agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingContext {
    /// The agent sending observations.
    pub sender_id: String,
    /// The agent receiving observations.
    pub receiver_id: String,
    /// The delegation scope governing what can be shared.
    pub delegation_scope: Option<String>,
    /// Sender's reputation grade (from mesh, if applicable).
    /// Must be at least "Fair" (0.4) for sharing to be accepted.
    pub sender_reputation: f64,
}

/// Minimum reputation score required for observation sharing.
/// Matches zp-mesh ReputationGrade::Fair threshold.
const MIN_SHARING_REPUTATION: f64 = 0.4;

/// Result of a merge operation.
#[derive(Debug)]
pub struct MergeResult {
    /// New memory entries created from the merge (all at Observed stage).
    pub merged_entries: Vec<MemoryEntry>,
    /// The merge receipt linking both source contexts.
    pub receipt: Receipt,
    /// IDs of source memories that were consumed.
    pub source_ids: Vec<String>,
}

/// Describes the source of a memory being shared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedMemory {
    /// The memory entry being shared.
    pub content: String,
    /// Category of the memory.
    pub category: String,
    /// Original stage in the sender's context.
    pub original_stage: MemoryStage,
    /// The observation ID in the sender's context.
    pub source_id: String,
    /// Confidence in the sender's context.
    pub confidence: f64,
}

// ============================================================================
// Sharing operations
// ============================================================================

/// Check if sharing is permitted based on reputation.
pub fn can_share(context: &SharingContext) -> Result<(), String> {
    if context.sender_reputation < MIN_SHARING_REPUTATION {
        return Err(format!(
            "Sender reputation {:.2} below minimum {:.2} for observation sharing",
            context.sender_reputation, MIN_SHARING_REPUTATION
        ));
    }
    Ok(())
}

/// Merge shared memories into the receiver's context.
///
/// **Critical safety rule:** All merged memories reset to Observed stage
/// regardless of their source stage. This prevents memory poisoning via
/// context blending.
///
/// Returns new MemoryEntry instances (at Observed stage) and a merge receipt.
pub fn merge_memories(
    shared: &[SharedMemory],
    context: &SharingContext,
) -> Result<MergeResult, String> {
    // Gate: check reputation.
    can_share(context)?;

    if shared.is_empty() {
        return Err("No memories to merge".to_string());
    }

    let now = Utc::now();
    let mut merged_entries = Vec::with_capacity(shared.len());
    let mut source_ids = Vec::with_capacity(shared.len());

    for mem in shared {
        source_ids.push(mem.source_id.clone());

        // CRITICAL: Reset to Observed regardless of original stage.
        let entry = MemoryEntry {
            id: format!("mem-{}", uuid::Uuid::now_v7()),
            content: mem.content.clone(),
            category: mem.category.clone(),
            stage: MemoryStage::Observed, // Always reset
            source_observation_id: Some(mem.source_id.clone()),
            promotion_receipts: vec![], // Fresh start — no inherited receipts
            confidence: mem.confidence * context.sender_reputation, // Discount by reputation
            reinforcement_count: 1,
            created_at: now,
            last_promoted_at: now,
            last_reinforced_at: now,
            reviewer: None,
            expires_at: None,
            review_due_at: None,
        };

        if mem.original_stage > MemoryStage::Observed {
            info!(
                source_id = %mem.source_id,
                original_stage = %mem.original_stage,
                "Merged memory reset from {} to Observed (merge safety rule)",
                mem.original_stage
            );
        }

        merged_entries.push(entry);
    }

    // Generate the merge receipt.
    let receipt = generate_merge_receipt(&source_ids, context);

    info!(
        count = merged_entries.len(),
        sender = %context.sender_id,
        receiver = %context.receiver_id,
        "Merged {} memories (all reset to Observed)",
        merged_entries.len()
    );

    Ok(MergeResult {
        merged_entries,
        receipt,
        source_ids,
    })
}

/// Format observations for system prompt injection when delegating to a child agent.
///
/// The parent's active observations are included in the child's system prompt
/// so the child has the parent's context. These are read-only — the child
/// cannot modify the parent's observations.
pub fn format_for_delegation(observations: &[SharedMemory]) -> String {
    if observations.is_empty() {
        return String::new();
    }

    let mut prompt = String::from("\n<parent_observations>\n");

    for obs in observations {
        prompt.push_str(&format!(
            "- [{}] {}: {}\n",
            obs.original_stage, obs.category, obs.content
        ));
    }

    prompt.push_str("</parent_observations>\n");
    prompt
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Generate a merge receipt linking both source contexts.
fn generate_merge_receipt(source_ids: &[String], context: &SharingContext) -> Receipt {
    Receipt::observation(&context.receiver_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::NarrativeSynthesis {
            source_observation_ids: source_ids.to_vec(),
            synthesis_method: "cross_agent_merge".to_string(),
            synthesizer_id: context.receiver_id.clone(),
        })
        .extension(
            "zp.merge.sender_id",
            serde_json::Value::String(context.sender_id.clone()),
        )
        .extension(
            "zp.merge.receiver_id",
            serde_json::Value::String(context.receiver_id.clone()),
        )
        .extension(
            "zp.merge.sender_reputation",
            serde_json::json!(context.sender_reputation),
        )
        .extension("zp.merge.source_count", serde_json::json!(source_ids.len()))
        .extension("zp.merge.safety_reset", serde_json::Value::Bool(true))
        .finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> SharingContext {
        SharingContext {
            sender_id: "agent-parent".to_string(),
            receiver_id: "agent-child".to_string(),
            delegation_scope: Some("read:project-data".to_string()),
            sender_reputation: 0.8,
        }
    }

    fn make_shared_memory(stage: MemoryStage) -> SharedMemory {
        SharedMemory {
            content: "TLS configured on port 8443".to_string(),
            category: "security".to_string(),
            original_stage: stage,
            source_id: "obs-parent-1".to_string(),
            confidence: 0.9,
        }
    }

    #[test]
    fn reputation_gate_blocks_low_reputation() {
        let mut context = make_context();
        context.sender_reputation = 0.2;

        let result = can_share(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("below minimum"));
    }

    #[test]
    fn reputation_gate_allows_fair_reputation() {
        let context = make_context();
        assert!(can_share(&context).is_ok());
    }

    #[test]
    fn merge_resets_all_to_observed() {
        let context = make_context();
        let shared = vec![
            make_shared_memory(MemoryStage::Trusted),
            make_shared_memory(MemoryStage::Remembered),
            make_shared_memory(MemoryStage::IdentityBearing),
        ];

        let result = merge_memories(&shared, &context).unwrap();

        assert_eq!(result.merged_entries.len(), 3);
        for entry in &result.merged_entries {
            assert_eq!(entry.stage, MemoryStage::Observed);
            // Confidence discounted by reputation: 0.9 * 0.8 = 0.72
            assert!((entry.confidence - 0.72).abs() < f64::EPSILON);
            // Fresh start — no inherited receipts.
            assert!(entry.promotion_receipts.is_empty());
        }
    }

    #[test]
    fn merge_receipt_has_correct_metadata() {
        let context = make_context();
        let shared = vec![make_shared_memory(MemoryStage::Trusted)];

        let result = merge_memories(&shared, &context).unwrap();

        match &result.receipt.claim_metadata {
            Some(ClaimMetadata::NarrativeSynthesis {
                synthesis_method,
                synthesizer_id,
                ..
            }) => {
                assert_eq!(synthesis_method, "cross_agent_merge");
                assert_eq!(synthesizer_id, "agent-child");
            }
            other => panic!("Expected NarrativeSynthesis metadata, got {:?}", other),
        }

        // Check extensions.
        let extensions = result.receipt.extensions.as_ref().unwrap();
        assert_eq!(
            extensions.get("zp.merge.safety_reset"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn delegation_prompt_formatting() {
        let shared = vec![
            SharedMemory {
                content: "TLS on 8443".to_string(),
                category: "security".to_string(),
                original_stage: MemoryStage::Trusted,
                source_id: "obs-1".to_string(),
                confidence: 0.9,
            },
            SharedMemory {
                content: "Rate limit is 100/s".to_string(),
                category: "infrastructure".to_string(),
                original_stage: MemoryStage::Observed,
                source_id: "obs-2".to_string(),
                confidence: 0.5,
            },
        ];

        let prompt = format_for_delegation(&shared);
        assert!(prompt.contains("<parent_observations>"));
        assert!(prompt.contains("[trusted] security: TLS on 8443"));
        assert!(prompt.contains("[observed] infrastructure: Rate limit is 100/s"));
        assert!(prompt.contains("</parent_observations>"));
    }

    #[test]
    fn empty_delegation_prompt() {
        assert_eq!(format_for_delegation(&[]), "");
    }

    #[test]
    fn merge_source_ids_tracked() {
        let context = make_context();
        let mut shared = vec![
            make_shared_memory(MemoryStage::Observed),
            make_shared_memory(MemoryStage::Interpreted),
        ];
        shared[1].source_id = "obs-parent-2".to_string();

        let result = merge_memories(&shared, &context).unwrap();
        assert_eq!(result.source_ids, vec!["obs-parent-1", "obs-parent-2"]);
    }
}
