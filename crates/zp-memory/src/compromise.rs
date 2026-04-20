//! Compromise-triggered memory quarantine.
//!
//! Phase 3 (R6-2): Wires the blast radius model to the quarantine store.
//! When a key compromise is detected, this module automatically quarantines
//! all memories whose promotion evidence includes receipts signed by the
//! compromised key.
//!
//! ## Integration
//!
//! This module receives the output of `BlastRadiusTracker::compute()` from
//! zp-keys and applies it to the memory subsystem. It does NOT depend on
//! zp-keys directly — instead it accepts the list of affected memory IDs
//! and the compromised key identifier.
//!
//! The server runtime is responsible for:
//! 1. Detecting the compromise (key rotation, external report)
//! 2. Computing blast radius via `BlastRadiusTracker`
//! 3. Calling `quarantine_compromised_memories()` with the results

use std::collections::HashMap;
use tracing::{info, warn};

use crate::quarantine::{QuarantineReason, QuarantineStore};
use crate::types::MemoryEntry;

// ============================================================================
// Compromise quarantine types
// ============================================================================

/// Input describing which memories are affected by a key compromise.
#[derive(Debug, Clone)]
pub struct CompromiseReport {
    /// The compromised public key (hex-encoded).
    pub compromised_key: String,
    /// Memory IDs affected by this compromise (from blast radius computation).
    pub affected_memory_ids: Vec<String>,
    /// Mapping of memory ID → receipt IDs that were signed by the compromised key.
    /// Used to create targeted CompromisedEvidence reasons.
    pub memory_to_receipts: HashMap<String, Vec<String>>,
}

/// Result of a compromise-triggered quarantine operation.
#[derive(Debug)]
pub struct CompromiseQuarantineResult {
    /// The compromised key that triggered this quarantine.
    pub compromised_key: String,
    /// Memory IDs that were successfully quarantined.
    pub quarantined_ids: Vec<String>,
    /// Memory IDs that were already quarantined (skipped).
    pub already_quarantined: Vec<String>,
    /// Memory IDs that were not found in the memory store.
    pub not_found: Vec<String>,
    /// Total memories processed.
    pub total_processed: usize,
}

impl CompromiseQuarantineResult {
    /// Whether any memories were quarantined.
    pub fn has_impact(&self) -> bool {
        !self.quarantined_ids.is_empty()
    }
}

// ============================================================================
// Quarantine function
// ============================================================================

/// Quarantine all memories affected by a key compromise.
///
/// For each affected memory:
/// - If already quarantined, skip it (idempotent).
/// - If found in the memory store, quarantine with `CompromisedEvidence` reason.
/// - If not found, log a warning and record as not_found.
///
/// ## Arguments
///
/// * `report` — The compromise report from blast radius computation.
/// * `quarantine_store` — The quarantine store to write quarantine records to.
/// * `memories` — Mutable access to the memory store for quarantine operations.
pub fn quarantine_compromised_memories(
    report: &CompromiseReport,
    quarantine_store: &mut QuarantineStore,
    memories: &mut HashMap<String, MemoryEntry>,
) -> CompromiseQuarantineResult {
    let mut quarantined_ids = Vec::new();
    let mut already_quarantined = Vec::new();
    let mut not_found = Vec::new();

    for memory_id in &report.affected_memory_ids {
        // Skip if already quarantined.
        if quarantine_store.is_quarantined(memory_id) {
            already_quarantined.push(memory_id.clone());
            continue;
        }

        // Look up the affected receipt IDs for this memory.
        let affected_receipts = report
            .memory_to_receipts
            .get(memory_id)
            .cloned()
            .unwrap_or_default();

        let reason = QuarantineReason::CompromisedEvidence {
            compromised_key: report.compromised_key.clone(),
            affected_receipt_ids: affected_receipts,
        };

        // Get mutable access to the memory entry.
        if let Some(memory) = memories.get_mut(memory_id) {
            quarantine_store.quarantine(memory, reason);
            quarantined_ids.push(memory_id.clone());
        } else {
            warn!(
                memory_id = %memory_id,
                compromised_key = %report.compromised_key,
                "Memory not found during compromise quarantine"
            );
            not_found.push(memory_id.clone());
        }
    }

    let total_processed = quarantined_ids.len() + already_quarantined.len() + not_found.len();

    info!(
        compromised_key = %report.compromised_key,
        quarantined = quarantined_ids.len(),
        already_quarantined = already_quarantined.len(),
        not_found = not_found.len(),
        "Compromise quarantine complete"
    );

    CompromiseQuarantineResult {
        compromised_key: report.compromised_key.clone(),
        quarantined_ids,
        already_quarantined,
        not_found,
        total_processed,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::types::MemoryStage;

    fn make_memory(id: &str, stage: MemoryStage) -> MemoryEntry {
        let now = Utc::now();
        MemoryEntry {
            id: id.to_string(),
            content: format!("Memory content for {}", id),
            category: "test".to_string(),
            stage,
            source_observation_id: Some("obs-1".to_string()),
            promotion_receipts: vec!["rcpt-1".to_string()],
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
    fn quarantine_affected_memories() {
        let mut qstore = QuarantineStore::new("operator-1");
        let mut memories = HashMap::new();
        memories.insert("mem-1".to_string(), make_memory("mem-1", MemoryStage::Trusted));
        memories.insert("mem-2".to_string(), make_memory("mem-2", MemoryStage::Remembered));
        memories.insert("mem-3".to_string(), make_memory("mem-3", MemoryStage::Observed));

        let mut memory_to_receipts = HashMap::new();
        memory_to_receipts.insert("mem-1".to_string(), vec!["rcpt-A".to_string()]);
        memory_to_receipts.insert("mem-2".to_string(), vec!["rcpt-A".to_string(), "rcpt-B".to_string()]);

        let report = CompromiseReport {
            compromised_key: "deadbeef01234567".to_string(),
            affected_memory_ids: vec!["mem-1".to_string(), "mem-2".to_string()],
            memory_to_receipts,
        };

        let result = quarantine_compromised_memories(&report, &mut qstore, &mut memories);

        assert_eq!(result.quarantined_ids.len(), 2);
        assert!(result.already_quarantined.is_empty());
        assert!(result.not_found.is_empty());
        assert!(result.has_impact());

        // Verify quarantine state
        assert!(qstore.is_quarantined("mem-1"));
        assert!(qstore.is_quarantined("mem-2"));
        assert!(!qstore.is_quarantined("mem-3")); // Not in blast radius
    }

    #[test]
    fn skips_already_quarantined() {
        let mut qstore = QuarantineStore::new("operator-1");
        let mut memories = HashMap::new();
        memories.insert("mem-1".to_string(), make_memory("mem-1", MemoryStage::Trusted));
        memories.insert("mem-2".to_string(), make_memory("mem-2", MemoryStage::Observed));

        // Pre-quarantine mem-1
        let mut mem1 = memories.get("mem-1").unwrap().clone();
        qstore.quarantine(
            &mut mem1,
            QuarantineReason::OperatorDirected {
                explanation: "pre-existing".to_string(),
            },
        );

        let report = CompromiseReport {
            compromised_key: "badkey".to_string(),
            affected_memory_ids: vec!["mem-1".to_string(), "mem-2".to_string()],
            memory_to_receipts: HashMap::new(),
        };

        let result = quarantine_compromised_memories(&report, &mut qstore, &mut memories);

        assert_eq!(result.quarantined_ids.len(), 1); // Only mem-2
        assert_eq!(result.already_quarantined.len(), 1); // mem-1
        assert_eq!(result.already_quarantined[0], "mem-1");
    }

    #[test]
    fn handles_missing_memories() {
        let mut qstore = QuarantineStore::new("operator-1");
        let mut memories = HashMap::new();
        memories.insert("mem-1".to_string(), make_memory("mem-1", MemoryStage::Trusted));

        let report = CompromiseReport {
            compromised_key: "badkey".to_string(),
            affected_memory_ids: vec!["mem-1".to_string(), "mem-nonexistent".to_string()],
            memory_to_receipts: HashMap::new(),
        };

        let result = quarantine_compromised_memories(&report, &mut qstore, &mut memories);

        assert_eq!(result.quarantined_ids.len(), 1);
        assert_eq!(result.not_found.len(), 1);
        assert_eq!(result.not_found[0], "mem-nonexistent");
        assert_eq!(result.total_processed, 2);
    }

    #[test]
    fn empty_report_has_no_impact() {
        let mut qstore = QuarantineStore::new("operator-1");
        let mut memories = HashMap::new();

        let report = CompromiseReport {
            compromised_key: "nokey".to_string(),
            affected_memory_ids: vec![],
            memory_to_receipts: HashMap::new(),
        };

        let result = quarantine_compromised_memories(&report, &mut qstore, &mut memories);

        assert!(!result.has_impact());
        assert_eq!(result.total_processed, 0);
    }

    #[test]
    fn compromised_evidence_reason_display() {
        let reason = QuarantineReason::CompromisedEvidence {
            compromised_key: "abcdef1234567890".to_string(),
            affected_receipt_ids: vec!["r1".to_string(), "r2".to_string()],
        };

        let display = reason.to_string();
        assert!(display.contains("compromised_evidence"));
        assert!(display.contains("abcdef12"));
        assert!(display.contains("2"));
    }

    #[test]
    fn idempotent_quarantine() {
        let mut qstore = QuarantineStore::new("operator-1");
        let mut memories = HashMap::new();
        memories.insert("mem-1".to_string(), make_memory("mem-1", MemoryStage::Trusted));

        let report = CompromiseReport {
            compromised_key: "badkey".to_string(),
            affected_memory_ids: vec!["mem-1".to_string()],
            memory_to_receipts: HashMap::new(),
        };

        // First quarantine
        let r1 = quarantine_compromised_memories(&report, &mut qstore, &mut memories);
        assert_eq!(r1.quarantined_ids.len(), 1);

        // Second quarantine — should be skipped
        let r2 = quarantine_compromised_memories(&report, &mut qstore, &mut memories);
        assert_eq!(r2.quarantined_ids.len(), 0);
        assert_eq!(r2.already_quarantined.len(), 1);
    }
}
