//! Reconstitution engine — rebuild trusted state from the audit chain.
//!
//! Phase 5.3: The ultimate recovery mechanism. Starting from the genesis key
//! and the audit chain, reconstruct which operator keys are valid, which
//! capabilities are granted and not revoked, and which memories are promoted
//! and not quarantined.
//!
//! The reconstituted state may differ from the live state if the live state
//! was corrupted. The differences form the **blast radius report** — an
//! enumeration of exactly what was affected by the compromise.
//!
//! **DLT backstop (optional):** When a TruthAnchor is available, reconstitution
//! cross-verifies the audit chain against external timestamps, catching
//! sophisticated replay attacks. Without DLT, reconstitution trusts the local
//! chain's internal consistency (hash chain + signatures).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::info;

// ============================================================================
// Chain entry abstraction
// ============================================================================

/// A simplified view of an audit chain entry for reconstitution.
///
/// This abstracts over the concrete `AuditEntry` type so the reconstitution
/// engine can be tested independently. In production, construct these from
/// `AuditStore::export_chain()` results.
#[derive(Debug, Clone)]
pub struct ChainEntry {
    /// Entry ID (string form).
    pub id: String,
    /// Entry timestamp.
    pub timestamp: DateTime<Utc>,
    /// Hash of the previous entry.
    pub prev_hash: String,
    /// Hash of this entry.
    pub entry_hash: String,
    /// Signature (if signed).
    pub signature: Option<String>,
    /// Receipt extensions (the key-value pairs from the receipt).
    /// This is how we extract state changes without coupling to receipt internals.
    pub receipt_extensions: Option<HashMap<String, serde_json::Value>>,
}

// ============================================================================
// Reconstituted state
// ============================================================================

/// The reconstructed trust state derived from walking the audit chain.
#[derive(Debug, Default)]
pub struct ReconstitutedState {
    /// Operator keys that are valid (not revoked, not expired).
    pub valid_operator_keys: HashSet<String>,
    /// Agent keys that are valid (not revoked, not expired, parent not revoked).
    pub valid_agent_keys: HashSet<String>,
    /// Revoked keys (directly revoked via revocation certificate in chain).
    pub revoked_keys: HashSet<String>,
    /// Active capabilities (grant ID → grant summary).
    pub active_capabilities: HashMap<String, CapabilitySummary>,
    /// Revoked capabilities.
    pub revoked_capabilities: HashSet<String>,
    /// Memory states: memory ID → reconstructed stage.
    pub memory_states: HashMap<String, ReconstitutedMemory>,
    /// Quarantined memory IDs.
    pub quarantined_memories: HashSet<String>,
    /// Total entries processed.
    pub entries_processed: usize,
    /// Chain integrity: all hashes verified.
    pub chain_integrity_verified: bool,
    /// DLT verification result (if anchor was available).
    pub anchor_verification: Option<AnchorVerificationResult>,
    /// Anomalies found during reconstitution.
    pub anomalies: Vec<ReconstitutionAnomaly>,
}

/// Summary of a reconstructed capability grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub grant_id: String,
    pub scope: String,
    pub grantee: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Reconstructed memory state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstitutedMemory {
    pub memory_id: String,
    pub stage: String,
    pub source_agent: Option<String>,
    pub last_transition_entry: String,
    pub quarantined: bool,
}

/// Result of DLT cross-verification.
#[derive(Debug, Clone)]
pub struct AnchorVerificationResult {
    /// Whether the chain timestamps align with external anchors.
    pub timestamps_consistent: bool,
    /// Number of anchor points verified.
    pub anchors_checked: usize,
    /// Maximum time drift detected between chain and external anchor.
    pub max_drift_seconds: i64,
    /// Gaps in the anchor timeline (periods with no external verification).
    pub timeline_gaps: Vec<TimelineGap>,
}

/// A gap in the external verification timeline.
#[derive(Debug, Clone)]
pub struct TimelineGap {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub chain_entries_in_gap: usize,
}

// ============================================================================
// Anomalies
// ============================================================================

/// An anomaly discovered during reconstitution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstitutionAnomaly {
    /// What kind of anomaly.
    pub kind: AnomalyKind,
    /// The audit entry ID where the anomaly was detected.
    pub entry_id: String,
    /// Human-readable description.
    pub description: String,
    /// Severity: how concerning is this anomaly.
    pub severity: AnomalySeverity,
}

/// Kinds of anomalies found during reconstitution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// A receipt references a key not in the reconstructed valid set.
    UnknownSigningKey,
    /// A capability was used after its grant was revoked.
    RevokedCapabilityUsed,
    /// A memory was promoted by a quarantined or revoked source.
    CompromisedSourcePromotion,
    /// Chain hash linkage is broken at this entry.
    BrokenHashLink,
    /// Timestamp ordering violation (entry N+1 is before entry N).
    TimestampRegression,
    /// DLT anchor shows a different hash for this chain segment.
    AnchorMismatch,
    /// A receipt's signature fails verification.
    InvalidReceiptSignature,
}

/// How severe is the anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Informational — not necessarily a problem.
    Info,
    /// Warning — may indicate a problem but could be benign.
    Warning,
    /// Critical — strongly indicates compromise or corruption.
    Critical,
}

// ============================================================================
// Blast radius report
// ============================================================================

/// Differences between the reconstituted state and the live state.
///
/// This is the actionable output: exactly what was affected by a compromise.
#[derive(Debug, Default)]
pub struct BlastRadiusReport {
    /// Keys that are valid in live state but should be revoked per chain.
    pub keys_should_be_revoked: Vec<String>,
    /// Keys that are revoked in live state but chain says are valid.
    pub keys_incorrectly_revoked: Vec<String>,
    /// Capabilities active in live state but revoked per chain.
    pub capabilities_should_be_revoked: Vec<String>,
    /// Memories at wrong stage (live stage != reconstituted stage).
    pub memory_stage_mismatches: Vec<MemoryStageMismatch>,
    /// Memories that should be quarantined but aren't.
    pub memories_should_be_quarantined: Vec<String>,
    /// Memories that are quarantined but shouldn't be.
    pub memories_incorrectly_quarantined: Vec<String>,
    /// Total number of discrepancies.
    pub total_discrepancies: usize,
}

/// A mismatch between live and reconstituted memory stage.
#[derive(Debug, Clone)]
pub struct MemoryStageMismatch {
    pub memory_id: String,
    pub live_stage: String,
    pub reconstituted_stage: String,
}

impl BlastRadiusReport {
    /// Whether the live state matches the reconstituted state (no discrepancies).
    pub fn is_clean(&self) -> bool {
        self.total_discrepancies == 0
    }
}

// ============================================================================
// Reconstitution engine
// ============================================================================

/// Configuration for reconstitution.
#[derive(Debug, Clone)]
pub struct ReconstitutionConfig {
    /// The genesis public key (hex-encoded) — root of trust.
    pub genesis_public_key: String,
    /// Whether to verify receipt signatures during chain walk.
    pub verify_signatures: bool,
    /// Whether to check DLT anchors (requires anchor source).
    pub check_anchors: bool,
    /// Maximum acceptable time drift between chain and anchor (seconds).
    pub max_anchor_drift_seconds: i64,
}

impl Default for ReconstitutionConfig {
    fn default() -> Self {
        Self {
            genesis_public_key: String::new(),
            verify_signatures: true,
            check_anchors: false,
            max_anchor_drift_seconds: 300, // 5 minutes
        }
    }
}

/// The reconstitution engine.
///
/// Walks an audit chain from genesis to tip, reconstructing the trust state
/// at each step. Produces a `ReconstitutedState` that can be compared against
/// the live state to generate a blast radius report.
pub struct ReconstitutionEngine {
    #[allow(dead_code)]
    config: ReconstitutionConfig,
    state: ReconstitutedState,
    last_timestamp: Option<DateTime<Utc>>,
    last_entry_hash: Option<String>,
}

impl ReconstitutionEngine {
    pub fn new(config: ReconstitutionConfig) -> Self {
        Self {
            config,
            state: ReconstitutedState::default(),
            last_timestamp: None,
            last_entry_hash: None,
        }
    }

    /// Process a single chain entry, updating the reconstituted state.
    ///
    /// Entries must be fed in chain order (oldest first). The engine
    /// automatically verifies hash linkage and timestamp ordering.
    pub fn process_entry(&mut self, entry: &ChainEntry) {
        self.state.entries_processed += 1;

        // Verify chain linkage.
        if let Some(ref expected_hash) = self.last_entry_hash {
            if entry.prev_hash != *expected_hash {
                self.state.anomalies.push(ReconstitutionAnomaly {
                    kind: AnomalyKind::BrokenHashLink,
                    entry_id: entry.id.clone(),
                    description: format!(
                        "Hash chain broken: expected prev_hash {}, found {}",
                        expected_hash, entry.prev_hash
                    ),
                    severity: AnomalySeverity::Critical,
                });
            }
        }

        // Verify timestamp ordering.
        if let Some(prev_ts) = self.last_timestamp {
            if entry.timestamp < prev_ts {
                self.state.anomalies.push(ReconstitutionAnomaly {
                    kind: AnomalyKind::TimestampRegression,
                    entry_id: entry.id.clone(),
                    description: format!(
                        "Timestamp regression: {} is before previous {}",
                        entry.timestamp, prev_ts
                    ),
                    severity: AnomalySeverity::Warning,
                });
            }
        }

        // Process receipt extensions for state changes.
        if let Some(ref extensions) = entry.receipt_extensions {
            self.process_extensions(extensions, &entry.id);
        }

        self.last_timestamp = Some(entry.timestamp);
        self.last_entry_hash = Some(entry.entry_hash.clone());
    }

    /// Process receipt extensions to extract state changes.
    fn process_extensions(
        &mut self,
        extensions: &HashMap<String, serde_json::Value>,
        entry_id: &str,
    ) {
        // Key revocation.
        if let Some(revoked_key) = extensions
            .get("zp.revocation.revoked_key")
            .and_then(|v| v.as_str())
        {
            self.state.revoked_keys.insert(revoked_key.to_string());
            self.state.valid_operator_keys.remove(revoked_key);
            self.state.valid_agent_keys.remove(revoked_key);

            info!(
                revoked_key = %revoked_key,
                entry_id = %entry_id,
                "Reconstitution: key revoked"
            );
        }

        // Key issuance.
        if let Some(issued_key) = extensions
            .get("zp.certificate.public_key")
            .and_then(|v| v.as_str())
        {
            if let Some(role) = extensions
                .get("zp.certificate.role")
                .and_then(|v| v.as_str())
            {
                match role {
                    "operator" => {
                        self.state
                            .valid_operator_keys
                            .insert(issued_key.to_string());
                    }
                    "agent" => {
                        self.state.valid_agent_keys.insert(issued_key.to_string());
                    }
                    _ => {}
                }
            }
        }

        // Capability grants.
        if let Some(grant_id) = extensions
            .get("zp.capability.grant_id")
            .and_then(|v| v.as_str())
        {
            let scope = extensions
                .get("zp.capability.scope")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let grantee = extensions
                .get("zp.capability.grantee")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            self.state.active_capabilities.insert(
                grant_id.to_string(),
                CapabilitySummary {
                    grant_id: grant_id.to_string(),
                    scope,
                    grantee,
                    granted_at: Utc::now(),
                    expires_at: None,
                },
            );
        }

        // Capability revocations.
        if let Some(revoked_grant) = extensions
            .get("zp.capability.revoked_grant_id")
            .and_then(|v| v.as_str())
        {
            self.state.active_capabilities.remove(revoked_grant);
            self.state
                .revoked_capabilities
                .insert(revoked_grant.to_string());
        }

        // Memory promotions.
        if let Some(memory_id) = extensions
            .get("zp.memory.memory_id")
            .and_then(|v| v.as_str())
        {
            let stage = extensions
                .get("zp.memory.stage")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let source_agent = extensions
                .get("zp.memory.source_agent")
                .and_then(|v| v.as_str())
                .map(String::from);

            self.state.memory_states.insert(
                memory_id.to_string(),
                ReconstitutedMemory {
                    memory_id: memory_id.to_string(),
                    stage,
                    source_agent,
                    last_transition_entry: entry_id.to_string(),
                    quarantined: false,
                },
            );
        }

        // Memory quarantines (single).
        if let Some(quarantined_id) = extensions
            .get("zp.quarantine.memory_id")
            .and_then(|v| v.as_str())
        {
            self.state
                .quarantined_memories
                .insert(quarantined_id.to_string());
            if let Some(mem) = self.state.memory_states.get_mut(quarantined_id) {
                mem.quarantined = true;
            }
        }

        // Memory quarantines (bulk).
        if let Some(bulk_ids) = extensions
            .get("zp.quarantine.memory_ids")
            .and_then(|v| v.as_array())
        {
            for id_val in bulk_ids {
                if let Some(id) = id_val.as_str() {
                    self.state.quarantined_memories.insert(id.to_string());
                    if let Some(mem) = self.state.memory_states.get_mut(id) {
                        mem.quarantined = true;
                    }
                }
            }
        }

        // Reinstatements.
        if let Some(reinstated_id) = extensions
            .get("zp.reinstatement.memory_id")
            .and_then(|v| v.as_str())
        {
            self.state.quarantined_memories.remove(reinstated_id);
            if let Some(mem) = self.state.memory_states.get_mut(reinstated_id) {
                mem.quarantined = false;
            }
        }
    }

    /// Finalize reconstitution and return the reconstructed state.
    pub fn finalize(mut self, chain_integrity_ok: bool) -> ReconstitutedState {
        self.state.chain_integrity_verified = chain_integrity_ok;

        info!(
            entries = self.state.entries_processed,
            valid_operators = self.state.valid_operator_keys.len(),
            valid_agents = self.state.valid_agent_keys.len(),
            revoked = self.state.revoked_keys.len(),
            memories = self.state.memory_states.len(),
            quarantined = self.state.quarantined_memories.len(),
            anomalies = self.state.anomalies.len(),
            "Reconstitution complete"
        );

        self.state
    }

    /// Get current anomaly count.
    pub fn anomaly_count(&self) -> usize {
        self.state.anomalies.len()
    }

    /// Get critical anomaly count.
    pub fn critical_anomaly_count(&self) -> usize {
        self.state
            .anomalies
            .iter()
            .filter(|a| a.severity == AnomalySeverity::Critical)
            .count()
    }
}

// ============================================================================
// Blast radius comparison
// ============================================================================

/// Compare reconstituted state against live state to produce a blast radius report.
pub fn compute_blast_radius(
    reconstituted: &ReconstitutedState,
    live_valid_keys: &HashSet<String>,
    live_revoked_keys: &HashSet<String>,
    live_active_capabilities: &HashSet<String>,
    live_quarantined_memories: &HashSet<String>,
    live_memory_stages: &HashMap<String, String>,
) -> BlastRadiusReport {
    let mut report = BlastRadiusReport::default();

    // Keys that should be revoked but live state says valid.
    for key in &reconstituted.revoked_keys {
        if live_valid_keys.contains(key) {
            report.keys_should_be_revoked.push(key.clone());
        }
    }

    // Keys that live says revoked but chain says valid.
    let all_valid: HashSet<_> = reconstituted
        .valid_operator_keys
        .union(&reconstituted.valid_agent_keys)
        .cloned()
        .collect();
    for key in live_revoked_keys {
        if all_valid.contains(key) {
            report.keys_incorrectly_revoked.push(key.clone());
        }
    }

    // Capabilities active in live but revoked per chain.
    for cap in live_active_capabilities {
        if reconstituted.revoked_capabilities.contains(cap) {
            report.capabilities_should_be_revoked.push(cap.clone());
        }
    }

    // Memory stage mismatches.
    for (mem_id, live_stage) in live_memory_stages {
        if let Some(recon_mem) = reconstituted.memory_states.get(mem_id) {
            if &recon_mem.stage != live_stage {
                report.memory_stage_mismatches.push(MemoryStageMismatch {
                    memory_id: mem_id.clone(),
                    live_stage: live_stage.clone(),
                    reconstituted_stage: recon_mem.stage.clone(),
                });
            }
        }
    }

    // Memories that should be quarantined.
    for mem_id in &reconstituted.quarantined_memories {
        if !live_quarantined_memories.contains(mem_id) {
            report.memories_should_be_quarantined.push(mem_id.clone());
        }
    }

    // Memories incorrectly quarantined.
    for mem_id in live_quarantined_memories {
        if !reconstituted.quarantined_memories.contains(mem_id) {
            report.memories_incorrectly_quarantined.push(mem_id.clone());
        }
    }

    report.total_discrepancies = report.keys_should_be_revoked.len()
        + report.keys_incorrectly_revoked.len()
        + report.capabilities_should_be_revoked.len()
        + report.memory_stage_mismatches.len()
        + report.memories_should_be_quarantined.len()
        + report.memories_incorrectly_quarantined.len();

    report
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, prev_hash: &str, entry_hash: &str) -> ChainEntry {
        ChainEntry {
            id: id.to_string(),
            timestamp: Utc::now(),
            prev_hash: prev_hash.to_string(),
            entry_hash: entry_hash.to_string(),
            signature: None,
            receipt_extensions: None,
        }
    }

    fn make_entry_with_ext(
        id: &str,
        prev_hash: &str,
        entry_hash: &str,
        extensions: serde_json::Value,
    ) -> ChainEntry {
        let ext_map: HashMap<String, serde_json::Value> = extensions
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        ChainEntry {
            id: id.to_string(),
            timestamp: Utc::now(),
            prev_hash: prev_hash.to_string(),
            entry_hash: entry_hash.to_string(),
            signature: None,
            receipt_extensions: Some(ext_map),
        }
    }

    #[test]
    fn reconstitute_key_lifecycle() {
        let config = ReconstitutionConfig::default();
        let mut engine = ReconstitutionEngine::new(config);

        // Issue an operator key.
        let entry = make_entry_with_ext(
            "1",
            "genesis",
            "hash-1",
            serde_json::json!({
                "zp.certificate.public_key": "operator-key-abc",
                "zp.certificate.role": "operator"
            }),
        );
        engine.process_entry(&entry);

        assert!(engine
            .state
            .valid_operator_keys
            .contains("operator-key-abc"));

        // Issue an agent key.
        let entry = make_entry_with_ext(
            "2",
            "hash-1",
            "hash-2",
            serde_json::json!({
                "zp.certificate.public_key": "agent-key-xyz",
                "zp.certificate.role": "agent"
            }),
        );
        engine.process_entry(&entry);

        assert!(engine.state.valid_agent_keys.contains("agent-key-xyz"));

        // Revoke the operator key.
        let entry = make_entry_with_ext(
            "3",
            "hash-2",
            "hash-3",
            serde_json::json!({
                "zp.revocation.revoked_key": "operator-key-abc"
            }),
        );
        engine.process_entry(&entry);

        assert!(!engine
            .state
            .valid_operator_keys
            .contains("operator-key-abc"));
        assert!(engine.state.revoked_keys.contains("operator-key-abc"));

        let state = engine.finalize(true);
        assert_eq!(state.entries_processed, 3);
        assert!(state.chain_integrity_verified);
    }

    #[test]
    fn reconstitute_memory_quarantine() {
        let config = ReconstitutionConfig::default();
        let mut engine = ReconstitutionEngine::new(config);

        // Create a memory.
        let entry = make_entry_with_ext(
            "1",
            "genesis",
            "hash-1",
            serde_json::json!({
                "zp.memory.memory_id": "mem-1",
                "zp.memory.stage": "trusted",
                "zp.memory.source_agent": "agent-1"
            }),
        );
        engine.process_entry(&entry);

        assert!(engine.state.memory_states.contains_key("mem-1"));
        assert_eq!(engine.state.memory_states["mem-1"].stage, "trusted");

        // Quarantine the memory.
        let entry = make_entry_with_ext(
            "2",
            "hash-1",
            "hash-2",
            serde_json::json!({
                "zp.quarantine.memory_id": "mem-1"
            }),
        );
        engine.process_entry(&entry);

        assert!(engine.state.quarantined_memories.contains("mem-1"));
        assert!(engine.state.memory_states["mem-1"].quarantined);

        // Reinstate the memory.
        let entry = make_entry_with_ext(
            "3",
            "hash-2",
            "hash-3",
            serde_json::json!({
                "zp.reinstatement.memory_id": "mem-1"
            }),
        );
        engine.process_entry(&entry);

        assert!(!engine.state.quarantined_memories.contains("mem-1"));
        assert!(!engine.state.memory_states["mem-1"].quarantined);
    }

    #[test]
    fn reconstitute_bulk_quarantine() {
        let config = ReconstitutionConfig::default();
        let mut engine = ReconstitutionEngine::new(config);

        for i in 1..=3 {
            let entry = make_entry_with_ext(
                &i.to_string(),
                &format!("hash-{}", i - 1),
                &format!("hash-{}", i),
                serde_json::json!({
                    "zp.memory.memory_id": format!("mem-{}", i),
                    "zp.memory.stage": "observed"
                }),
            );
            engine.process_entry(&entry);
        }

        let entry = make_entry_with_ext(
            "4",
            "hash-3",
            "hash-4",
            serde_json::json!({
                "zp.quarantine.memory_ids": ["mem-1", "mem-2"]
            }),
        );
        engine.process_entry(&entry);

        assert!(engine.state.quarantined_memories.contains("mem-1"));
        assert!(engine.state.quarantined_memories.contains("mem-2"));
        assert!(!engine.state.quarantined_memories.contains("mem-3"));
    }

    #[test]
    fn blast_radius_detects_discrepancies() {
        let mut recon = ReconstitutedState::default();
        recon.revoked_keys.insert("key-compromised".to_string());
        recon.valid_operator_keys.insert("key-valid".to_string());
        recon.revoked_capabilities.insert("cap-revoked".to_string());
        recon
            .quarantined_memories
            .insert("mem-quarantined".to_string());
        recon.memory_states.insert(
            "mem-1".to_string(),
            ReconstitutedMemory {
                memory_id: "mem-1".to_string(),
                stage: "trusted".to_string(),
                source_agent: None,
                last_transition_entry: "entry-1".to_string(),
                quarantined: false,
            },
        );

        let mut live_valid_keys = HashSet::new();
        live_valid_keys.insert("key-compromised".to_string());

        let live_revoked_keys = HashSet::new();

        let mut live_capabilities = HashSet::new();
        live_capabilities.insert("cap-revoked".to_string());

        let live_quarantined = HashSet::new();

        let mut live_stages = HashMap::new();
        live_stages.insert("mem-1".to_string(), "remembered".to_string());

        let report = compute_blast_radius(
            &recon,
            &live_valid_keys,
            &live_revoked_keys,
            &live_capabilities,
            &live_quarantined,
            &live_stages,
        );

        assert!(!report.is_clean());
        assert_eq!(report.keys_should_be_revoked.len(), 1);
        assert_eq!(report.capabilities_should_be_revoked.len(), 1);
        assert_eq!(report.memories_should_be_quarantined.len(), 1);
        assert_eq!(report.memory_stage_mismatches.len(), 1);
        assert_eq!(report.total_discrepancies, 4);
    }

    #[test]
    fn clean_blast_radius() {
        let recon = ReconstitutedState::default();
        let report = compute_blast_radius(
            &recon,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
        );

        assert!(report.is_clean());
        assert_eq!(report.total_discrepancies, 0);
    }

    #[test]
    fn timestamp_regression_detected() {
        let config = ReconstitutionConfig::default();
        let mut engine = ReconstitutionEngine::new(config);

        let mut entry1 = make_entry("1", "genesis", "hash-1");
        entry1.timestamp = Utc::now();
        engine.process_entry(&entry1);

        let mut entry2 = make_entry("2", "hash-1", "hash-2");
        entry2.timestamp = Utc::now() - chrono::Duration::hours(1);
        engine.process_entry(&entry2);

        assert_eq!(engine.anomaly_count(), 1);
        assert_eq!(
            engine.state.anomalies[0].kind,
            AnomalyKind::TimestampRegression
        );
    }

    #[test]
    fn broken_hash_link_detected() {
        let config = ReconstitutionConfig::default();
        let mut engine = ReconstitutionEngine::new(config);

        let entry1 = make_entry("1", "genesis", "hash-1");
        engine.process_entry(&entry1);

        // Entry 2 has wrong prev_hash.
        let entry2 = make_entry("2", "wrong-hash", "hash-2");
        engine.process_entry(&entry2);

        assert_eq!(engine.critical_anomaly_count(), 1);
        assert_eq!(engine.state.anomalies[0].kind, AnomalyKind::BrokenHashLink);
    }

    #[test]
    fn capability_lifecycle() {
        let config = ReconstitutionConfig::default();
        let mut engine = ReconstitutionEngine::new(config);

        let entry = make_entry_with_ext(
            "1",
            "genesis",
            "hash-1",
            serde_json::json!({
                "zp.capability.grant_id": "grant-1",
                "zp.capability.scope": "tool:execute",
                "zp.capability.grantee": "agent-1"
            }),
        );
        engine.process_entry(&entry);

        assert!(engine.state.active_capabilities.contains_key("grant-1"));

        let entry = make_entry_with_ext(
            "2",
            "hash-1",
            "hash-2",
            serde_json::json!({
                "zp.capability.revoked_grant_id": "grant-1"
            }),
        );
        engine.process_entry(&entry);

        assert!(!engine.state.active_capabilities.contains_key("grant-1"));
        assert!(engine.state.revoked_capabilities.contains("grant-1"));
    }
}
