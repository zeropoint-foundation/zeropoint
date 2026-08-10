//! Structured crash recovery from the receipt chain.
//!
//! Phase 5.5: The audit chain as a "black box recorder." On unclean shutdown,
//! the recovery engine walks the receipt chain from the last known-good
//! checkpoint and reconstructs operational state.
//!
//! This is distinct from reconstitution (Phase 5.3): reconstitution rebuilds
//! the trust/security state for compromise analysis. Recovery rebuilds the
//! operational state for resuming normal operation after a crash.
//!
//! The recovery engine reconstructs:
//! - Active workflow position (which conversation was in-flight)
//! - Pending tool executions (started but not completed)
//! - In-flight capability grants (granted but not yet used/expired)
//! - Observation store state (which observations were active)
//!
//! On server startup, check for an unclean shutdown marker. If found,
//! run the recovery engine before accepting new requests.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

use zp_core::receipt_extensions as ext;

use crate::reconstitute::ReconstitutionEntry;

// ============================================================================
// Checkpoint
// ============================================================================

/// A known-good checkpoint in the audit chain.
///
/// Checkpoints are created periodically during normal operation. The recovery
/// engine starts from the most recent checkpoint rather than replaying the
/// entire chain from genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Unique checkpoint identifier.
    pub id: String,
    /// The audit entry ID at the time of the checkpoint.
    pub entry_id: String,
    /// The entry hash at the checkpoint (for verification).
    pub entry_hash: String,
    /// When the checkpoint was created.
    pub created_at: DateTime<Utc>,
    /// Active conversation IDs at the time of the checkpoint.
    pub active_conversations: Vec<String>,
    /// Number of active observations at checkpoint time.
    pub observation_count: usize,
}

// ============================================================================
// Recovered state
// ============================================================================

/// The operational state recovered from the audit chain.
#[derive(Debug, Default)]
pub struct RecoveredState {
    /// Conversations that were active at crash time.
    pub active_conversations: HashSet<String>,
    /// Tool executions that were started but not completed.
    pub pending_tool_executions: Vec<PendingToolExecution>,
    /// Capability grants that were in-flight (granted, not yet expired/used).
    pub in_flight_grants: Vec<InFlightGrant>,
    /// Observations that were active (not yet reflected/expired).
    pub active_observations: Vec<ActiveObservation>,
    /// Total entries replayed from checkpoint.
    pub entries_replayed: usize,
    /// Entries that were discarded during recovery (incomplete, timed out).
    pub discarded_entries: Vec<DiscardedEntry>,
    /// Whether recovery was from a checkpoint or full chain replay.
    pub from_checkpoint: bool,
    /// The checkpoint used (if any).
    pub checkpoint_id: Option<String>,
}

/// A tool execution that was started but never completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingToolExecution {
    /// The entry ID where the tool was invoked.
    pub invocation_entry_id: String,
    /// Tool name.
    pub tool_name: String,
    /// Conversation ID.
    pub conversation_id: String,
    /// When the tool was invoked.
    pub invoked_at: DateTime<Utc>,
    /// Whether this execution should be retried or discarded.
    pub action: RecoveryAction,
}

/// What to do with a pending item during recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// Retry the operation (idempotent tools).
    Retry,
    /// Discard the operation (non-idempotent or timed out).
    Discard,
    /// Requires operator decision.
    OperatorReview,
}

/// A capability grant that was active at crash time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InFlightGrant {
    pub grant_id: String,
    pub scope: String,
    pub grantee: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// An observation that was active at crash time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveObservation {
    pub observation_id: String,
    pub category: String,
    pub entry_id: String,
}

/// An entry that was discarded during recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscardedEntry {
    pub entry_id: String,
    pub reason: String,
    pub original_action: String,
}

// ============================================================================
// Shutdown marker
// ============================================================================

/// Unclean shutdown detection.
///
/// On clean shutdown, the marker is removed. On startup, if the marker
/// exists, recovery is needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownMarker {
    /// When the server last started.
    pub started_at: DateTime<Utc>,
    /// Process ID (for multi-instance detection).
    pub pid: u32,
    /// The last known entry hash at startup.
    pub last_known_hash: Option<String>,
}

impl ShutdownMarker {
    /// Create a new shutdown marker for the current process.
    pub fn new() -> Self {
        Self {
            started_at: Utc::now(),
            pid: std::process::id(),
            last_known_hash: None,
        }
    }

    /// Check if recovery is needed based on the marker's presence.
    pub fn needs_recovery(marker: &Option<Self>) -> bool {
        marker.is_some()
    }
}

impl Default for ShutdownMarker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Recovery receipt
// ============================================================================

/// A recovery receipt documenting what was replayed and what was discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    /// Unique receipt identifier.
    pub id: String,
    /// When recovery was performed.
    pub recovered_at: DateTime<Utc>,
    /// The checkpoint used (or "genesis" if full replay).
    pub checkpoint_id: String,
    /// Number of entries replayed.
    pub entries_replayed: usize,
    /// Number of pending tool executions found.
    pub pending_tools_found: usize,
    /// Number of entries discarded.
    pub entries_discarded: usize,
    /// Summary of discarded entries.
    pub discarded_summary: Vec<String>,
    /// Whether recovery completed successfully.
    pub success: bool,
}

// ============================================================================
// Recovery engine
// ============================================================================

/// Configuration for the recovery engine.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Maximum age of a pending tool execution before it's discarded.
    pub tool_timeout: Duration,
    /// Whether to automatically discard timed-out operations.
    pub auto_discard_timeout: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            tool_timeout: Duration::minutes(30),
            auto_discard_timeout: true,
        }
    }
}

/// The recovery engine — replays the audit chain from a checkpoint.
pub struct RecoveryEngine {
    config: RecoveryConfig,
    state: RecoveredState,
    /// Tool invocations seen but not yet completed.
    pending_tools: HashMap<String, PendingToolExecution>,
    /// Conversations with activity since checkpoint.
    conversations: HashSet<String>,
    /// Grants seen but not yet revoked/expired.
    grants: HashMap<String, InFlightGrant>,
    /// Active observations.
    observations: HashMap<String, ActiveObservation>,
    /// How many replayed entries actually carried receipt extensions.
    ///
    /// Every read in [`RecoveryEngine::process_extensions`] draws from
    /// `entry.receipt_extensions`; if that is `None` the whole body is skipped.
    /// Measured 2026-08-08 against the live chain: of 285,071 entries, **zero**
    /// carried a receipt at all, so none of the seventeen `zp.*` keys this
    /// engine reads has ever been present. Producers write their payload into
    /// the `action` event string; this consumer reads receipt extensions. Two
    /// channels, no bridge.
    ///
    /// The failure mode is the dangerous one: recovery replays every entry,
    /// finds nothing, and reports `success: true` having reconstituted no
    /// capability grants, no certificates, no pending tool invocations and no
    /// observations. It looks like a clean recovery of a quiet chain. This
    /// counter exists so that it stops looking like one — see the warning in
    /// [`RecoveryEngine::finalize`]. It does not fix the mismatch; it makes the
    /// mismatch impossible to mistake for health.
    entries_with_extensions: usize,
}

impl RecoveryEngine {
    pub fn new(config: RecoveryConfig) -> Self {
        Self {
            config,
            state: RecoveredState::default(),
            pending_tools: HashMap::new(),
            conversations: HashSet::new(),
            grants: HashMap::new(),
            observations: HashMap::new(),
            entries_with_extensions: 0,
        }
    }

    /// Replay a chain entry, updating the recovered state.
    ///
    /// Call this for each entry from the checkpoint to the chain tip.
    pub fn replay_entry(&mut self, entry: &ReconstitutionEntry) {
        self.state.entries_replayed += 1;

        if let Some(ref extensions) = entry.receipt_extensions {
            self.entries_with_extensions += 1;
            self.process_extensions(extensions, &entry.id, entry.timestamp);
        }
    }

    /// Process receipt extensions for operational state.
    fn process_extensions(
        &mut self,
        extensions: &HashMap<String, serde_json::Value>,
        entry_id: &str,
        timestamp: DateTime<Utc>,
    ) {
        // Tool invocations.
        if let Some(tool_name) = extensions.get(ext::TOOL_NAME).and_then(|v| v.as_str()) {
            let conversation_id = extensions
                .get(ext::TOOL_CONVERSATION_ID)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            self.conversations.insert(conversation_id.clone());

            self.pending_tools.insert(
                entry_id.to_string(),
                PendingToolExecution {
                    invocation_entry_id: entry_id.to_string(),
                    tool_name: tool_name.to_string(),
                    conversation_id,
                    invoked_at: timestamp,
                    action: RecoveryAction::OperatorReview,
                },
            );
        }

        // Tool completions.
        if let Some(invocation_id) = extensions
            .get(ext::TOOL_COMPLETED_INVOCATION_ID)
            .and_then(|v| v.as_str())
        {
            self.pending_tools.remove(invocation_id);
        }

        // Conversation activity.
        if let Some(conv_id) = extensions
            .get(ext::CONVERSATION_ID)
            .and_then(|v| v.as_str())
        {
            self.conversations.insert(conv_id.to_string());
        }

        // Conversation ended.
        if let Some(conv_id) = extensions
            .get(ext::CONVERSATION_ENDED)
            .and_then(|v| v.as_str())
        {
            self.conversations.remove(conv_id);
        }

        // Capability grants.
        if let Some(grant_id) = extensions
            .get(ext::CAPABILITY_GRANT_ID)
            .and_then(|v| v.as_str())
        {
            let scope = extensions
                .get(ext::CAPABILITY_SCOPE)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let grantee = extensions
                .get(ext::CAPABILITY_GRANTEE)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            self.grants.insert(
                grant_id.to_string(),
                InFlightGrant {
                    grant_id: grant_id.to_string(),
                    scope,
                    grantee,
                    granted_at: timestamp,
                    expires_at: None,
                },
            );
        }

        // Capability revocations.
        if let Some(revoked_id) = extensions
            .get(ext::CAPABILITY_REVOKED_GRANT_ID)
            .and_then(|v| v.as_str())
        {
            self.grants.remove(revoked_id);
        }

        // Observations created.
        if let Some(obs_id) = extensions.get(ext::OBSERVATION_ID).and_then(|v| v.as_str()) {
            let category = extensions
                .get(ext::OBSERVATION_CATEGORY)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            self.observations.insert(
                obs_id.to_string(),
                ActiveObservation {
                    observation_id: obs_id.to_string(),
                    category,
                    entry_id: entry_id.to_string(),
                },
            );
        }

        // Observations consumed (by reflection).
        if let Some(consumed_ids) = extensions
            .get(ext::REFLECTION_CONSUMED_IDS)
            .and_then(|v| v.as_array())
        {
            for id_val in consumed_ids {
                if let Some(id) = id_val.as_str() {
                    self.observations.remove(id);
                }
            }
        }
    }

    /// Finalize recovery, applying timeout rules and generating the result.
    pub fn finalize(
        mut self,
        checkpoint: Option<&Checkpoint>,
    ) -> (RecoveredState, RecoveryReceipt) {
        let now = Utc::now();

        // Apply timeout rules to pending tool executions.
        for (entry_id, tool) in &mut self.pending_tools {
            let age = now - tool.invoked_at;
            if age > self.config.tool_timeout {
                if self.config.auto_discard_timeout {
                    tool.action = RecoveryAction::Discard;
                    self.state.discarded_entries.push(DiscardedEntry {
                        entry_id: entry_id.clone(),
                        reason: format!(
                            "Tool execution timed out (age: {}s, limit: {}s)",
                            age.num_seconds(),
                            self.config.tool_timeout.num_seconds()
                        ),
                        original_action: format!("tool:{}", tool.tool_name),
                    });
                }
            } else {
                tool.action = RecoveryAction::Retry;
            }
        }

        self.state.active_conversations = self.conversations;
        self.state.pending_tool_executions = self.pending_tools.into_values().collect();
        self.state.in_flight_grants = self.grants.into_values().collect();
        self.state.active_observations = self.observations.into_values().collect();
        self.state.from_checkpoint = checkpoint.is_some();
        self.state.checkpoint_id = checkpoint.map(|c| c.id.clone());

        let receipt = RecoveryReceipt {
            id: format!("recovery-{}", uuid::Uuid::now_v7()),
            recovered_at: now,
            checkpoint_id: checkpoint
                .map(|c| c.id.clone())
                .unwrap_or_else(|| "genesis".to_string()),
            entries_replayed: self.state.entries_replayed,
            pending_tools_found: self.state.pending_tool_executions.len(),
            entries_discarded: self.state.discarded_entries.len(),
            discarded_summary: self
                .state
                .discarded_entries
                .iter()
                .map(|d| format!("{}: {}", d.entry_id, d.reason))
                .collect(),
            success: true,
        };

        info!(
            entries_replayed = self.state.entries_replayed,
            entries_with_extensions = self.entries_with_extensions,
            active_conversations = self.state.active_conversations.len(),
            pending_tools = self.state.pending_tool_executions.len(),
            discarded = self.state.discarded_entries.len(),
            "Recovery complete"
        );

        // A silent no-op recovery is indistinguishable from a clean one. Say so.
        // Replaying entries while reading extensions from none of them means the
        // operational state above is empty because it was never readable, not
        // because the chain was quiet.
        if self.state.entries_replayed > 0 && self.entries_with_extensions == 0 {
            warn!(
                entries_replayed = self.state.entries_replayed,
                "Recovery reconstituted NO operational state: none of the replayed \
                 entries carried receipt extensions, which is the only channel this \
                 engine reads. Capability grants, certificates, pending tool \
                 invocations and observations were not recovered — they were not \
                 looked at. Producers currently emit their payload in the `action` \
                 event string instead. Treat `success: true` above as 'replay \
                 completed', not as 'state restored'."
            );
        }

        (self.state, receipt)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, extensions: Option<serde_json::Value>) -> ReconstitutionEntry {
        let ext_map = extensions.map(|v| {
            v.as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        });

        ReconstitutionEntry {
            id: id.to_string(),
            timestamp: Utc::now(),
            prev_hash: "prev".to_string(),
            entry_hash: format!("hash-{}", id),
            signature: None,
            receipt_extensions: ext_map,
        }
    }

    fn make_entry_at(
        id: &str,
        timestamp: DateTime<Utc>,
        extensions: Option<serde_json::Value>,
    ) -> ReconstitutionEntry {
        let mut entry = make_entry(id, extensions);
        entry.timestamp = timestamp;
        entry
    }

    #[test]
    fn recover_pending_tool_execution() {
        let config = RecoveryConfig::default();
        let mut engine = RecoveryEngine::new(config);

        // Tool invoked.
        let entry = make_entry(
            "1",
            Some(serde_json::json!({
                "zp.tool.name": "web_search",
                "zp.tool.conversation_id": "conv-1"
            })),
        );
        engine.replay_entry(&entry);

        // No completion — tool is pending.
        let (state, receipt) = engine.finalize(None);

        assert_eq!(state.pending_tool_executions.len(), 1);
        assert_eq!(state.pending_tool_executions[0].tool_name, "web_search");
        assert_eq!(
            state.pending_tool_executions[0].action,
            RecoveryAction::Retry
        );
        assert!(receipt.success);
    }

    #[test]
    fn completed_tool_not_pending() {
        let config = RecoveryConfig::default();
        let mut engine = RecoveryEngine::new(config);

        // Tool invoked.
        let entry = make_entry(
            "1",
            Some(serde_json::json!({
                "zp.tool.name": "web_search",
                "zp.tool.conversation_id": "conv-1"
            })),
        );
        engine.replay_entry(&entry);

        // Tool completed.
        let entry = make_entry(
            "2",
            Some(serde_json::json!({
                "zp.tool.completed_invocation_id": "1"
            })),
        );
        engine.replay_entry(&entry);

        let (state, _) = engine.finalize(None);
        assert_eq!(state.pending_tool_executions.len(), 0);
    }

    #[test]
    fn timed_out_tool_discarded() {
        let config = RecoveryConfig {
            tool_timeout: Duration::minutes(30),
            auto_discard_timeout: true,
        };
        let mut engine = RecoveryEngine::new(config);

        // Tool invoked 2 hours ago.
        let old_time = Utc::now() - Duration::hours(2);
        let entry = make_entry_at(
            "1",
            old_time,
            Some(serde_json::json!({
                "zp.tool.name": "slow_tool",
                "zp.tool.conversation_id": "conv-1"
            })),
        );
        engine.replay_entry(&entry);

        let (state, receipt) = engine.finalize(None);
        assert_eq!(state.pending_tool_executions.len(), 1);
        assert_eq!(
            state.pending_tool_executions[0].action,
            RecoveryAction::Discard
        );
        assert_eq!(state.discarded_entries.len(), 1);
        assert_eq!(receipt.entries_discarded, 1);
    }

    #[test]
    fn active_conversations_tracked() {
        let config = RecoveryConfig::default();
        let mut engine = RecoveryEngine::new(config);

        // Conversation started.
        let entry = make_entry(
            "1",
            Some(serde_json::json!({
                "zp.conversation.id": "conv-1"
            })),
        );
        engine.replay_entry(&entry);

        let entry = make_entry(
            "2",
            Some(serde_json::json!({
                "zp.conversation.id": "conv-2"
            })),
        );
        engine.replay_entry(&entry);

        // conv-1 ended.
        let entry = make_entry(
            "3",
            Some(serde_json::json!({
                "zp.conversation.ended": "conv-1"
            })),
        );
        engine.replay_entry(&entry);

        let (state, _) = engine.finalize(None);
        assert_eq!(state.active_conversations.len(), 1);
        assert!(state.active_conversations.contains("conv-2"));
    }

    #[test]
    fn capability_grant_lifecycle() {
        let config = RecoveryConfig::default();
        let mut engine = RecoveryEngine::new(config);

        // Grant capability.
        let entry = make_entry(
            "1",
            Some(serde_json::json!({
                "zp.capability.grant_id": "grant-1",
                "zp.capability.scope": "tool:execute",
                "zp.capability.grantee": "agent-1"
            })),
        );
        engine.replay_entry(&entry);

        // Grant another.
        let entry = make_entry(
            "2",
            Some(serde_json::json!({
                "zp.capability.grant_id": "grant-2",
                "zp.capability.scope": "proxy:openai",
                "zp.capability.grantee": "agent-1"
            })),
        );
        engine.replay_entry(&entry);

        // Revoke first.
        let entry = make_entry(
            "3",
            Some(serde_json::json!({
                "zp.capability.revoked_grant_id": "grant-1"
            })),
        );
        engine.replay_entry(&entry);

        let (state, _) = engine.finalize(None);
        assert_eq!(state.in_flight_grants.len(), 1);
        assert_eq!(state.in_flight_grants[0].grant_id, "grant-2");
    }

    #[test]
    fn observation_lifecycle() {
        let config = RecoveryConfig::default();
        let mut engine = RecoveryEngine::new(config);

        // Observations created.
        for i in 1..=3 {
            let entry = make_entry(
                &i.to_string(),
                Some(serde_json::json!({
                    "zp.observation.id": format!("obs-{}", i),
                    "zp.observation.category": "test"
                })),
            );
            engine.replay_entry(&entry);
        }

        // Reflection consumes obs-1 and obs-2.
        let entry = make_entry(
            "4",
            Some(serde_json::json!({
                "zp.reflection.consumed_ids": ["obs-1", "obs-2"]
            })),
        );
        engine.replay_entry(&entry);

        let (state, _) = engine.finalize(None);
        assert_eq!(state.active_observations.len(), 1);
        assert_eq!(state.active_observations[0].observation_id, "obs-3");
    }

    #[test]
    fn recovery_from_checkpoint() {
        let config = RecoveryConfig::default();
        let mut engine = RecoveryEngine::new(config);

        let entry = make_entry(
            "1",
            Some(serde_json::json!({
                "zp.conversation.id": "conv-1"
            })),
        );
        engine.replay_entry(&entry);

        let checkpoint = Checkpoint {
            id: "checkpoint-1".to_string(),
            entry_id: "prev-entry".to_string(),
            entry_hash: "prev-hash".to_string(),
            created_at: Utc::now() - Duration::hours(1),
            active_conversations: vec![],
            observation_count: 0,
        };

        let (state, receipt) = engine.finalize(Some(&checkpoint));
        assert!(state.from_checkpoint);
        assert_eq!(state.checkpoint_id, Some("checkpoint-1".to_string()));
        assert_eq!(receipt.checkpoint_id, "checkpoint-1");
    }

    #[test]
    fn shutdown_marker() {
        let marker = ShutdownMarker::new();
        assert!(ShutdownMarker::needs_recovery(&Some(marker)));
        assert!(!ShutdownMarker::needs_recovery(&None));
    }

    #[test]
    fn recovery_receipt_generated() {
        let config = RecoveryConfig::default();
        let mut engine = RecoveryEngine::new(config);

        for i in 1..=5 {
            let entry = make_entry(&i.to_string(), None);
            engine.replay_entry(&entry);
        }

        let (state, receipt) = engine.finalize(None);
        assert_eq!(state.entries_replayed, 5);
        assert_eq!(receipt.entries_replayed, 5);
        assert!(receipt.success);
        assert!(receipt.id.starts_with("recovery-"));
    }

    /// Round trip: the real producer's output, through the real conversion,
    /// into the real consumer.
    ///
    /// Every other test in this module hands the engine a `make_entry` fixture
    /// with a hand-written extensions map — a shape no emitter had ever
    /// produced. They passed while capability recovery had never once worked,
    /// because they supplied the missing half themselves and then asserted the
    /// other half parsed it. This one starts from
    /// `zp_core::capability_grant_receipt`, the same function the Regent
    /// startup delegation calls, and goes through
    /// `ReconstitutionEntry::from_audit_entry`, the same conversion the
    /// production replay path uses.
    ///
    /// It found a live break the moment it was written: `from_audit_entry` was
    /// discarding `receipt.extensions` entirely and substituting a
    /// Debug-formatted `claim_type` string, so a correctly-emitted receipt
    /// still arrived at the engine with nothing readable on it.
    ///
    /// Fixtures may not supply what production does not produce. If this test
    /// is ever made to pass by editing the fixture rather than the code, it has
    /// been turned back into the thing it replaced.
    #[test]
    fn round_trip_capability_grant_producer_to_recovered_state() {
        use zp_core::capability_grant::{CapabilityGrant, GrantedCapability};
        use zp_core::{ActorId, AuditAction, AuditEntry, AuditId, ConversationId, PolicyDecision};

        let grant = CapabilityGrant::new(
            "genesis".to_string(),
            "regent".to_string(),
            GrantedCapability::ToolCall {
                tools: vec!["chain_query".to_string()],
            },
            "rcpt-round-trip-test".to_string(),
        );
        let scope = "tool:call:chain_query";

        // The producer half — the exact call site used at Regent startup.
        let receipt = zp_core::capability_grant_receipt(&grant, scope);

        let audit_entry = AuditEntry {
            id: AuditId::new(),
            timestamp: Utc::now(),
            prev_hash: "genesis".to_string(),
            entry_hash: "round-trip".to_string(),
            actor: ActorId::System("genesis".to_string()),
            action: AuditAction::SystemEvent {
                event: "delegation:granted:regent".to_string(),
            },
            conversation_id: ConversationId(uuid::Uuid::nil()),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "regent-startup".to_string(),
            receipt: Some(receipt),
            signatures: Vec::new(),
        };

        // The production conversion, not a fixture.
        let entry = ReconstitutionEntry::from_audit_entry(&audit_entry);

        let mut engine = RecoveryEngine::new(RecoveryConfig::default());
        engine.replay_entry(&entry);
        let (state, _) = engine.finalize(None);

        assert_eq!(
            state.in_flight_grants.len(),
            1,
            "the grant a real producer emitted did not survive to RecoveredState — \
             the break is between capability_grant_receipt and RecoveryEngine, not \
             in either end"
        );
        let recovered = &state.in_flight_grants[0];
        assert_eq!(recovered.grant_id, grant.id);
        assert_eq!(recovered.grantee, "regent");
        assert_eq!(recovered.scope, scope);
    }

    #[test]
    fn every_recovery_key_is_namespaced() {
        // Cheap guard on the shared contract itself: the constants the reader
        // uses and the producers write must stay in one namespace and one list.
        for k in zp_core::receipt_extensions::RECOVERY_KEYS {
            assert!(k.starts_with("zp."), "{k} is outside the zp. namespace");
        }
    }
}
