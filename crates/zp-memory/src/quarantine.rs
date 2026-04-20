//! Memory quarantine — operator-controlled isolation of compromised memories.
//!
//! Phase 5.2: Implements the doctrine's memory isolation for compromise response.
//!
//! Any memory can be quarantined by operator action, creating a QuarantineReceipt.
//! Quarantined memories are excluded from policy evaluation, skill matching, and
//! narrative synthesis. Quarantine is reversible — un-quarantine creates a
//! ReinstateReceipt linking back to the quarantine.
//!
//! **Bulk quarantine:** All memories derived from a specific compromised source
//! (e.g., all observations from a revoked agent) can be quarantined in one
//! operation, producing a single receipt that covers the batch.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use zp_receipt::{ClaimMetadata, ClaimSemantics, Receipt, Status};

use crate::types::{MemoryEntry, MemoryStage};

// ============================================================================
// Quarantine reason
// ============================================================================

/// Why a memory is being quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineReason {
    /// The source agent's key was revoked — all its observations are suspect.
    SourceKeyRevoked { agent_key: String },
    /// Operator-directed quarantine during investigation.
    OperatorDirected { explanation: String },
    /// Automated quarantine triggered by anomaly detection.
    AnomalyDetected {
        detector_id: String,
        anomaly_type: String,
    },
    /// Memory content conflicts with a higher-trust source.
    TruthConflict { conflicting_memory_id: String },
    /// Memory's promotion evidence includes receipts signed by a compromised key.
    /// Triggered by the blast radius model (Phase 3, R6-2).
    CompromisedEvidence {
        /// The compromised public key (hex-encoded).
        compromised_key: String,
        /// Receipt IDs in this memory's evidence chain that were signed
        /// by the compromised key.
        affected_receipt_ids: Vec<String>,
    },
}

impl std::fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineReason::SourceKeyRevoked { agent_key } => {
                write!(
                    f,
                    "source_key_revoked({})",
                    &agent_key[..8.min(agent_key.len())]
                )
            }
            QuarantineReason::OperatorDirected { explanation } => {
                write!(f, "operator_directed({})", explanation)
            }
            QuarantineReason::AnomalyDetected { anomaly_type, .. } => {
                write!(f, "anomaly_detected({})", anomaly_type)
            }
            QuarantineReason::TruthConflict {
                conflicting_memory_id,
            } => {
                write!(f, "truth_conflict({})", conflicting_memory_id)
            }
            QuarantineReason::CompromisedEvidence {
                compromised_key,
                affected_receipt_ids,
            } => {
                write!(
                    f,
                    "compromised_evidence(key={}, receipts={})",
                    &compromised_key[..8.min(compromised_key.len())],
                    affected_receipt_ids.len()
                )
            }
        }
    }
}

// ============================================================================
// Quarantine record
// ============================================================================

/// A record of a memory quarantine action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Unique quarantine ID.
    pub id: String,
    /// The memory entry ID that was quarantined.
    pub memory_id: String,
    /// Why it was quarantined.
    pub reason: QuarantineReason,
    /// Who quarantined it (operator key or system ID).
    pub quarantined_by: String,
    /// When the quarantine was applied.
    pub quarantined_at: DateTime<Utc>,
    /// The receipt ID for the quarantine action.
    pub receipt_id: String,
    /// The memory's stage at the time of quarantine (preserved for reinstatement).
    pub original_stage: MemoryStage,
    /// Whether this quarantine has been reversed.
    pub reinstated: bool,
    /// If reinstated, the reinstatement receipt ID.
    pub reinstatement_receipt_id: Option<String>,
    /// If reinstated, when.
    pub reinstated_at: Option<DateTime<Utc>>,
}

/// Result of a bulk quarantine operation.
#[derive(Debug)]
pub struct BulkQuarantineResult {
    /// Number of memories quarantined.
    pub quarantined_count: usize,
    /// Memory IDs that were quarantined.
    pub quarantined_ids: Vec<String>,
    /// The bulk quarantine receipt.
    pub receipt: Receipt,
    /// Memory IDs that were already quarantined (skipped).
    pub already_quarantined: Vec<String>,
}

/// Result of a reinstatement operation.
#[derive(Debug)]
pub struct ReinstatementResult {
    /// The memory ID reinstated.
    pub memory_id: String,
    /// The stage the memory was restored to.
    pub restored_stage: MemoryStage,
    /// The reinstatement receipt.
    pub receipt: Receipt,
}

// ============================================================================
// Quarantine store
// ============================================================================

/// In-memory quarantine store.
///
/// Tracks which memories are quarantined and supports bulk operations
/// by source agent. Produces receipts for all quarantine/reinstatement actions.
#[derive(Debug, Default)]
pub struct QuarantineStore {
    /// Active quarantine records: memory_id → quarantine record.
    quarantines: HashMap<String, QuarantineRecord>,
    /// Index: source observation ID → memory IDs derived from it.
    /// Used for bulk quarantine by source.
    source_index: HashMap<String, Vec<String>>,
    /// All quarantine records (including reinstated), for audit trail.
    history: Vec<QuarantineRecord>,
    /// Operator identity for receipt generation.
    operator_id: String,
}

impl QuarantineStore {
    pub fn new(operator_id: &str) -> Self {
        Self {
            quarantines: HashMap::new(),
            source_index: HashMap::new(),
            history: Vec::new(),
            operator_id: operator_id.to_string(),
        }
    }

    /// Register a memory's source for bulk quarantine tracking.
    ///
    /// Call this when a memory is created from an observation so the store
    /// knows how to find all memories from a given source.
    pub fn register_source(&mut self, memory_id: &str, source_observation_id: &str) {
        self.source_index
            .entry(source_observation_id.to_string())
            .or_default()
            .push(memory_id.to_string());
    }

    /// Check if a memory is currently quarantined.
    pub fn is_quarantined(&self, memory_id: &str) -> bool {
        self.quarantines
            .get(memory_id)
            .is_some_and(|r| !r.reinstated)
    }

    /// Get the quarantine record for a memory (if quarantined).
    pub fn get_quarantine(&self, memory_id: &str) -> Option<&QuarantineRecord> {
        self.quarantines.get(memory_id).filter(|r| !r.reinstated)
    }

    /// Quarantine a single memory.
    pub fn quarantine(
        &mut self,
        memory: &mut MemoryEntry,
        reason: QuarantineReason,
    ) -> QuarantineRecord {
        let receipt = generate_quarantine_receipt(&memory.id, &reason, &self.operator_id);

        let record = QuarantineRecord {
            id: format!("quar-{}", uuid::Uuid::now_v7()),
            memory_id: memory.id.clone(),
            reason: reason.clone(),
            quarantined_by: self.operator_id.clone(),
            quarantined_at: Utc::now(),
            receipt_id: receipt.id.clone(),
            original_stage: memory.stage,
            reinstated: false,
            reinstatement_receipt_id: None,
            reinstated_at: None,
        };

        info!(
            memory_id = %memory.id,
            reason = %reason,
            original_stage = %memory.stage,
            "Memory quarantined"
        );

        self.quarantines.insert(memory.id.clone(), record.clone());
        self.history.push(record.clone());

        record
    }

    /// Bulk quarantine all memories derived from a specific source observation.
    ///
    /// This is the primary response to a source key revocation — quarantine
    /// all memories that originated from the compromised agent's observations.
    pub fn quarantine_by_source(
        &mut self,
        source_observation_id: &str,
        reason: QuarantineReason,
        memories: &mut HashMap<String, MemoryEntry>,
    ) -> BulkQuarantineResult {
        let memory_ids = self
            .source_index
            .get(source_observation_id)
            .cloned()
            .unwrap_or_default();

        let mut quarantined_ids = Vec::new();
        let mut already_quarantined = Vec::new();

        for mem_id in &memory_ids {
            if self.is_quarantined(mem_id) {
                already_quarantined.push(mem_id.clone());
                continue;
            }

            if let Some(memory) = memories.get_mut(mem_id) {
                let record = QuarantineRecord {
                    id: format!("quar-{}", uuid::Uuid::now_v7()),
                    memory_id: mem_id.clone(),
                    reason: reason.clone(),
                    quarantined_by: self.operator_id.clone(),
                    quarantined_at: Utc::now(),
                    receipt_id: String::new(), // Will be set from bulk receipt
                    original_stage: memory.stage,
                    reinstated: false,
                    reinstatement_receipt_id: None,
                    reinstated_at: None,
                };

                self.quarantines.insert(mem_id.clone(), record.clone());
                self.history.push(record);
                quarantined_ids.push(mem_id.clone());
            }
        }

        let receipt = generate_bulk_quarantine_receipt(
            &quarantined_ids,
            source_observation_id,
            &reason,
            &self.operator_id,
        );

        // Backfill receipt ID on all records.
        for mem_id in &quarantined_ids {
            if let Some(record) = self.quarantines.get_mut(mem_id) {
                record.receipt_id = receipt.id.clone();
            }
        }

        info!(
            source = %source_observation_id,
            count = quarantined_ids.len(),
            skipped = already_quarantined.len(),
            "Bulk quarantine by source"
        );

        BulkQuarantineResult {
            quarantined_count: quarantined_ids.len(),
            quarantined_ids,
            receipt,
            already_quarantined,
        }
    }

    /// Reinstate a quarantined memory, restoring it to its original stage.
    ///
    /// Creates a ReinstateReceipt linking back to the quarantine receipt.
    pub fn reinstate(&mut self, memory: &mut MemoryEntry) -> Result<ReinstatementResult, String> {
        let record = self
            .quarantines
            .get(&memory.id)
            .filter(|r| !r.reinstated)
            .ok_or_else(|| format!("Memory {} is not quarantined", memory.id))?;

        let original_stage = record.original_stage;
        let quarantine_receipt_id = record.receipt_id.clone();

        let receipt = generate_reinstatement_receipt(
            &memory.id,
            &quarantine_receipt_id,
            original_stage,
            &self.operator_id,
        );

        // Mark the quarantine as reinstated.
        let record = self.quarantines.get_mut(&memory.id).unwrap();
        record.reinstated = true;
        record.reinstatement_receipt_id = Some(receipt.id.clone());
        record.reinstated_at = Some(Utc::now());

        // Restore the memory's stage.
        memory.stage = original_stage;

        info!(
            memory_id = %memory.id,
            restored_stage = %original_stage,
            quarantine_receipt = %quarantine_receipt_id,
            "Memory reinstated"
        );

        Ok(ReinstatementResult {
            memory_id: memory.id.clone(),
            restored_stage: original_stage,
            receipt,
        })
    }

    /// Filter a list of memory entries, excluding quarantined ones.
    ///
    /// This is the primary integration point for downstream consumers:
    /// policy evaluation, skill matching, and narrative synthesis call
    /// this to get only non-quarantined memories.
    pub fn filter_active<'a>(&self, memories: &'a [&'a MemoryEntry]) -> Vec<&'a MemoryEntry> {
        memories
            .iter()
            .filter(|m| !self.is_quarantined(&m.id))
            .copied()
            .collect()
    }

    /// Total number of currently quarantined memories.
    pub fn active_quarantine_count(&self) -> usize {
        self.quarantines.values().filter(|r| !r.reinstated).count()
    }

    /// Full quarantine history (including reinstated), for audit.
    pub fn history(&self) -> &[QuarantineRecord] {
        &self.history
    }
}

// ============================================================================
// Receipt generation
// ============================================================================

fn generate_quarantine_receipt(
    memory_id: &str,
    reason: &QuarantineReason,
    operator_id: &str,
) -> Receipt {
    Receipt::observation(operator_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::Observation {
            observation_type: "quarantine".to_string(),
            observer_id: operator_id.to_string(),
            confidence: Some(1.0),
            tags: vec!["quarantine".to_string(), "memory".to_string()],
        })
        .extension(
            "zp.quarantine.memory_id",
            serde_json::Value::String(memory_id.to_string()),
        )
        .extension(
            "zp.quarantine.reason",
            serde_json::Value::String(reason.to_string()),
        )
        .extension(
            "zp.quarantine.operator",
            serde_json::Value::String(operator_id.to_string()),
        )
        .finalize()
}

fn generate_bulk_quarantine_receipt(
    memory_ids: &[String],
    source_observation_id: &str,
    reason: &QuarantineReason,
    operator_id: &str,
) -> Receipt {
    Receipt::observation(operator_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::Observation {
            observation_type: "bulk_quarantine".to_string(),
            observer_id: operator_id.to_string(),
            confidence: Some(1.0),
            tags: vec![
                "quarantine".to_string(),
                "bulk".to_string(),
                "memory".to_string(),
            ],
        })
        .extension(
            "zp.quarantine.reason",
            serde_json::Value::String(reason.to_string()),
        )
        .extension(
            "zp.quarantine.source_observation_id",
            serde_json::Value::String(source_observation_id.to_string()),
        )
        .extension("zp.quarantine.count", serde_json::json!(memory_ids.len()))
        .extension("zp.quarantine.memory_ids", serde_json::json!(memory_ids))
        .finalize()
}

fn generate_reinstatement_receipt(
    memory_id: &str,
    quarantine_receipt_id: &str,
    restored_stage: MemoryStage,
    operator_id: &str,
) -> Receipt {
    Receipt::observation(operator_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorshipProof)
        .claim_metadata(ClaimMetadata::Observation {
            observation_type: "reinstatement".to_string(),
            observer_id: operator_id.to_string(),
            confidence: Some(1.0),
            tags: vec!["reinstatement".to_string(), "memory".to_string()],
        })
        .extension(
            "zp.reinstatement.memory_id",
            serde_json::Value::String(memory_id.to_string()),
        )
        .extension(
            "zp.reinstatement.quarantine_receipt_id",
            serde_json::Value::String(quarantine_receipt_id.to_string()),
        )
        .extension(
            "zp.reinstatement.restored_stage",
            serde_json::Value::String(restored_stage.to_string()),
        )
        .finalize()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_memory(id: &str, stage: MemoryStage) -> MemoryEntry {
        let now = Utc::now();
        MemoryEntry {
            id: id.to_string(),
            content: format!("Memory content for {}", id),
            category: "test".to_string(),
            stage,
            source_observation_id: Some("obs-agent-1".to_string()),
            promotion_receipts: vec![],
            confidence: 0.8,
            reinforcement_count: 2,
            created_at: now,
            last_promoted_at: now,
            last_reinforced_at: now,
            reviewer: None,
            expires_at: None,
            review_due_at: None,
        }
    }

    #[test]
    fn quarantine_single_memory() {
        let mut store = QuarantineStore::new("operator-1");
        let mut memory = make_memory("mem-1", MemoryStage::Trusted);

        let record = store.quarantine(
            &mut memory,
            QuarantineReason::OperatorDirected {
                explanation: "Under investigation".to_string(),
            },
        );

        assert!(store.is_quarantined("mem-1"));
        assert_eq!(record.original_stage, MemoryStage::Trusted);
        assert!(!record.reinstated);
        assert_eq!(store.active_quarantine_count(), 1);
    }

    #[test]
    fn reinstate_quarantined_memory() {
        let mut store = QuarantineStore::new("operator-1");
        let mut memory = make_memory("mem-1", MemoryStage::Trusted);

        store.quarantine(
            &mut memory,
            QuarantineReason::OperatorDirected {
                explanation: "test".to_string(),
            },
        );

        // Manually set stage to something else to verify restoration.
        memory.stage = MemoryStage::Observed;

        let result = store.reinstate(&mut memory).unwrap();
        assert_eq!(result.restored_stage, MemoryStage::Trusted);
        assert_eq!(memory.stage, MemoryStage::Trusted);
        assert!(!store.is_quarantined("mem-1"));
        assert_eq!(store.active_quarantine_count(), 0);
    }

    #[test]
    fn reinstate_non_quarantined_fails() {
        let mut store = QuarantineStore::new("operator-1");
        let mut memory = make_memory("mem-1", MemoryStage::Trusted);

        let result = store.reinstate(&mut memory);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not quarantined"));
    }

    #[test]
    fn bulk_quarantine_by_source() {
        let mut store = QuarantineStore::new("operator-1");

        // Register source associations.
        store.register_source("mem-1", "obs-compromised");
        store.register_source("mem-2", "obs-compromised");
        store.register_source("mem-3", "obs-clean");

        let mut memories = HashMap::new();
        memories.insert(
            "mem-1".to_string(),
            make_memory("mem-1", MemoryStage::Trusted),
        );
        memories.insert(
            "mem-2".to_string(),
            make_memory("mem-2", MemoryStage::Remembered),
        );
        memories.insert(
            "mem-3".to_string(),
            make_memory("mem-3", MemoryStage::Observed),
        );

        let result = store.quarantine_by_source(
            "obs-compromised",
            QuarantineReason::SourceKeyRevoked {
                agent_key: "deadbeef01234567".to_string(),
            },
            &mut memories,
        );

        assert_eq!(result.quarantined_count, 2);
        assert!(store.is_quarantined("mem-1"));
        assert!(store.is_quarantined("mem-2"));
        assert!(!store.is_quarantined("mem-3")); // Different source
    }

    #[test]
    fn bulk_quarantine_skips_already_quarantined() {
        let mut store = QuarantineStore::new("operator-1");

        store.register_source("mem-1", "obs-compromised");
        store.register_source("mem-2", "obs-compromised");

        let mut memories = HashMap::new();
        memories.insert(
            "mem-1".to_string(),
            make_memory("mem-1", MemoryStage::Trusted),
        );
        memories.insert(
            "mem-2".to_string(),
            make_memory("mem-2", MemoryStage::Observed),
        );

        // Quarantine mem-1 individually first.
        let mut mem1 = memories.get("mem-1").unwrap().clone();
        store.quarantine(
            &mut mem1,
            QuarantineReason::OperatorDirected {
                explanation: "pre-quarantined".to_string(),
            },
        );

        // Bulk quarantine should skip mem-1.
        let result = store.quarantine_by_source(
            "obs-compromised",
            QuarantineReason::SourceKeyRevoked {
                agent_key: "deadbeef".to_string(),
            },
            &mut memories,
        );

        assert_eq!(result.quarantined_count, 1); // Only mem-2
        assert_eq!(result.already_quarantined.len(), 1);
        assert_eq!(result.already_quarantined[0], "mem-1");
    }

    #[test]
    fn filter_excludes_quarantined() {
        let mut store = QuarantineStore::new("operator-1");

        let mut mem1 = make_memory("mem-1", MemoryStage::Trusted);
        let mem2 = make_memory("mem-2", MemoryStage::Observed);
        let mem3 = make_memory("mem-3", MemoryStage::Interpreted);

        store.quarantine(
            &mut mem1,
            QuarantineReason::OperatorDirected {
                explanation: "test".to_string(),
            },
        );

        let all_mems: Vec<&MemoryEntry> = vec![&mem1, &mem2, &mem3];
        let filtered = store.filter_active(&all_mems);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|m| m.id != "mem-1"));
    }

    #[test]
    fn quarantine_receipt_has_correct_metadata() {
        let mut store = QuarantineStore::new("operator-1");
        let mut memory = make_memory("mem-1", MemoryStage::Trusted);

        let record = store.quarantine(
            &mut memory,
            QuarantineReason::AnomalyDetected {
                detector_id: "anomaly-detector-1".to_string(),
                anomaly_type: "confidence_spike".to_string(),
            },
        );

        // Receipt ID should be set (observation claim prefix).
        assert!(!record.receipt_id.is_empty());
    }

    #[test]
    fn history_tracks_all_actions() {
        let mut store = QuarantineStore::new("operator-1");
        let mut memory = make_memory("mem-1", MemoryStage::Trusted);

        store.quarantine(
            &mut memory,
            QuarantineReason::OperatorDirected {
                explanation: "test".to_string(),
            },
        );

        assert_eq!(store.history().len(), 1); // One quarantine event
        assert!(!store.history()[0].reinstated); // Not yet reinstated

        let result = store.reinstate(&mut memory).unwrap();
        assert_eq!(result.restored_stage, MemoryStage::Trusted);

        // After reinstatement, the quarantine record in the map is updated.
        assert!(!store.is_quarantined("mem-1"));
        assert_eq!(store.active_quarantine_count(), 0);
    }

    #[test]
    fn quarantine_reason_display() {
        let reason = QuarantineReason::SourceKeyRevoked {
            agent_key: "abcdef1234567890".to_string(),
        };
        assert!(reason.to_string().contains("source_key_revoked"));

        let reason = QuarantineReason::TruthConflict {
            conflicting_memory_id: "mem-conflict".to_string(),
        };
        assert!(reason.to_string().contains("truth_conflict"));
    }
}
