//! Bridges `agent_zp::AuditSink` → `zp_audit::AuditStore`.
//!
//! Maps agent-zp's `GovernanceRecord` and `ExecutionReceipt` to ZP's native
//! `AuditEntry` type, then appends to the hash-linked audit chain via
//! `AuditStore::append()`.

use std::sync::{Arc, Mutex};

use agent_zp::{
    ActorRef, DecisionOutcome, ExecutionReceipt, GovernanceEventType, GovernanceRecord,
};
use async_trait::async_trait;
use tracing;

use zp_audit::AuditStore;
use zp_audit::ChainBuilder;
use zp_core::{
    ActorId, AuditAction, AuditEntry, ConversationId, PolicyDecision,
};

/// Concrete `AuditSink` implementation backed by ZP's `AuditStore`.
///
/// Uses a `Mutex<AuditStore>` for thread-safe access (matching ZP's existing
/// pattern in `tool_chain.rs` and `tool_state.rs`).
pub struct ZpAuditSink {
    store: Arc<Mutex<AuditStore>>,
    conversation_id: ConversationId,
}

impl ZpAuditSink {
    /// Create a new sink backed by an existing `AuditStore`.
    pub fn new(store: Arc<Mutex<AuditStore>>, conversation_id: ConversationId) -> Self {
        Self {
            store,
            conversation_id,
        }
    }

    /// Create a sink with a new conversation ID.
    pub fn with_new_conversation(store: Arc<Mutex<AuditStore>>) -> Self {
        Self {
            store,
            conversation_id: ConversationId::new(),
        }
    }

    /// Get the conversation ID for this sink.
    pub fn conversation_id(&self) -> &ConversationId {
        &self.conversation_id
    }

    /// Append an audit entry to the store.
    fn append_entry(&self, entry: AuditEntry) -> anyhow::Result<()> {
        let store = self
            .store
            .lock()
            .map_err(|e| anyhow::anyhow!("audit store lock poisoned: {}", e))?;
        store.append(entry)?;
        Ok(())
    }

    /// Get the latest hash from the chain for linking.
    fn latest_hash(&self) -> String {
        self.store
            .lock()
            .ok()
            .and_then(|s| s.get_latest_hash().ok())
            .unwrap_or_else(|| "genesis".to_string())
    }
}

#[async_trait]
impl agent_zp::AuditSink for ZpAuditSink {
    async fn emit(&self, record: GovernanceRecord) -> anyhow::Result<()> {
        let actor = map_actor(&record.actor);
        let action = map_governance_action(&record);
        let decision = map_decision(&record.decision);
        let prev_hash = self.latest_hash();

        let entry = ChainBuilder::build_entry(
            &prev_hash,
            actor,
            action,
            self.conversation_id.clone(),
            decision,
            "agent-zp".to_string(),
            None, // receipt — governance records don't carry portable receipts
            None, // signature — added when sovereignty signing is wired
        );

        self.append_entry(entry)?;

        tracing::trace!(
            record_id = %record.id,
            event_type = %record.event_type,
            "Governance record bridged to audit chain"
        );

        Ok(())
    }

    async fn emit_receipt(&self, receipt: &ExecutionReceipt) -> anyhow::Result<()> {
        let actor = ActorId::System(format!("agent:{}", receipt.agent_id));
        let action = map_receipt_action(receipt);
        let decision = if receipt.success {
            PolicyDecision::Allow {
                conditions: vec![],
            }
        } else {
            PolicyDecision::Block {
                reason: format!("execution failed (exit {})", receipt.exit_code),
                policy_module: "agent-zp".to_string(),
            }
        };
        let prev_hash = self.latest_hash();

        // Build a portable receipt from the execution receipt
        let portable_receipt = build_portable_receipt(receipt);

        let entry = ChainBuilder::build_entry(
            &prev_hash,
            actor,
            action,
            self.conversation_id.clone(),
            decision,
            "agent-zp".to_string(),
            Some(portable_receipt),
            None,
        );

        self.append_entry(entry)?;

        tracing::trace!(
            receipt_id = %receipt.receipt_id,
            runtime = %receipt.runtime,
            wall_ms = receipt.timing.wall_ms,
            "Execution receipt bridged to audit chain"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Type mapping functions
// ---------------------------------------------------------------------------

/// Map agent-zp `ActorRef` → ZP `ActorId`.
fn map_actor(actor: &ActorRef) -> ActorId {
    match actor {
        ActorRef::Agent { agent_id } => ActorId::System(format!("agent:{}", agent_id)),
        ActorRef::Human { id } => ActorId::User(id.clone()),
        ActorRef::System { component } => ActorId::System(component.clone()),
    }
}

/// Map agent-zp `DecisionOutcome` → ZP `PolicyDecision`.
fn map_decision(decision: &DecisionOutcome) -> PolicyDecision {
    match decision {
        DecisionOutcome::Allowed => PolicyDecision::Allow {
            conditions: vec![],
        },
        DecisionOutcome::Denied { reason } => PolicyDecision::Block {
            reason: reason.clone(),
            policy_module: "agent-zp".to_string(),
        },
        DecisionOutcome::Deferred { message } => PolicyDecision::Review {
            summary: message.clone(),
            reviewer: zp_core::ReviewTarget::CurrentUser,
            timeout: None,
        },
    }
}

/// Map a `GovernanceRecord` → ZP `AuditAction`.
fn map_governance_action(record: &GovernanceRecord) -> AuditAction {
    match &record.event_type {
        GovernanceEventType::PolicyEvaluation => AuditAction::PolicyInteraction {
            decision_type: record.action.action_type.clone(),
            user_response: None,
        },
        GovernanceEventType::ToolExecution => AuditAction::ToolCompleted {
            tool_name: record
                .action
                .action_type
                .strip_prefix("tool.")
                .and_then(|s| s.strip_suffix(".execute"))
                .unwrap_or(&record.action.action_type)
                .to_string(),
            success: matches!(record.decision, DecisionOutcome::Allowed),
            output_hash: record
                .receipt_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        },
        GovernanceEventType::ProviderCall => AuditAction::ApiCallProxied {
            provider: record
                .action
                .action_type
                .strip_prefix("provider.")
                .and_then(|s| s.split('.').next())
                .unwrap_or("unknown")
                .to_string(),
            endpoint: record
                .action
                .target
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            tokens_input: 0,  // Token counts are in the receipt, not the governance record
            tokens_output: 0,
            cost_usd: 0.0,
        },
        GovernanceEventType::CapabilityVerified => AuditAction::SystemEvent {
            event: format!(
                "capability_verified:{}",
                record.action.action_type
            ),
        },
        GovernanceEventType::TaskTransition => AuditAction::SystemEvent {
            event: record.action.action_type.clone(),
        },
        GovernanceEventType::GuardEvaluation => AuditAction::SystemEvent {
            event: format!("guard:{}", record.action.action_type),
        },
    }
}

/// Map an `ExecutionReceipt` → ZP `AuditAction`.
fn map_receipt_action(receipt: &ExecutionReceipt) -> AuditAction {
    // Determine if this is a tool execution or a provider call from the runtime string
    if receipt.runtime.starts_with("claw/provider/") {
        AuditAction::ApiCallProxied {
            provider: receipt
                .runtime
                .strip_prefix("claw/provider/")
                .unwrap_or("unknown")
                .to_string(),
            endpoint: "stream".to_string(),
            tokens_input: 0,
            tokens_output: 0,
            cost_usd: 0.0,
        }
    } else {
        let tool_name = receipt
            .runtime
            .strip_prefix("claw/")
            .unwrap_or(&receipt.runtime)
            .to_string();

        if receipt.success {
            AuditAction::ToolCompleted {
                tool_name,
                success: true,
                output_hash: receipt.output_hash.clone(),
            }
        } else {
            AuditAction::ToolCompleted {
                tool_name,
                success: false,
                output_hash: receipt.output_hash.clone(),
            }
        }
    }
}

/// Build a ZP portable receipt from an agent-zp `ExecutionReceipt`.
fn build_portable_receipt(receipt: &ExecutionReceipt) -> zp_core::Receipt {
    use zp_receipt::{
        Action, ActionType, ExecutorType, IoHashes, ReceiptBuilder as ZpReceiptBuilder,
        ReceiptType, Resources, Status, TrustGrade,
    };

    let status = if receipt.success {
        Status::Success
    } else {
        Status::Failed
    };

    let action_type = if receipt.runtime.starts_with("claw/provider/") {
        ActionType::ApiRequest
    } else {
        ActionType::ToolCall
    };

    let tool_name = receipt
        .runtime
        .strip_prefix("claw/")
        .unwrap_or(&receipt.runtime)
        .to_string();

    // Compute timing: started_at derived from completed_at - wall_ms
    let completed_at = receipt.completed_at;
    let started_at = completed_at
        - chrono::Duration::milliseconds(receipt.timing.wall_ms as i64);

    ZpReceiptBuilder::new(ReceiptType::Execution, &receipt.agent_id)
        .status(status)
        .trust_grade(TrustGrade::C) // Sandboxed agent execution
        .executor_type(ExecutorType::Agent)
        .runtime(&receipt.runtime)
        .action(Action {
            action_type,
            name: Some(tool_name),
            input_hash: Some(receipt.input_hash.clone()),
            output_hash: Some(receipt.output_hash.clone()),
            exit_code: Some(receipt.exit_code),
            detail: None,
        })
        .timing(started_at, completed_at)
        .resources(Resources {
            cpu_seconds: None,
            memory_peak_bytes: receipt.resources.peak_memory_bytes,
            disk_written_bytes: Some(receipt.resources.bytes_written),
            network_bytes_sent: None,
            network_bytes_received: None,
            tokens_input: None,
            tokens_output: None,
            cost_usd: None,
        })
        .io_hashes(IoHashes {
            stdin_hash: Some(receipt.input_hash.clone()),
            stdout_hash: Some(receipt.output_hash.clone()),
            stderr_hash: None,
            stdout_size: Some(receipt.resources.stdout_bytes as u64),
            stderr_size: Some(receipt.resources.stderr_bytes as u64),
        })
        .finalize()
}
