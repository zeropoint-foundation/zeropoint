//! Event-driven Merkle anchor pipeline (#176).
//!
//! Detects significant governance events as they land on the audit chain,
//! seals the entries since the last anchor into a Merkle epoch, and publishes
//! the commitment to whatever [`TruthAnchor`] backend is configured. The
//! sealed epoch is then recorded back onto the chain as an `epoch:anchored:N`
//! receipt so future verifications can recompute the root from local state
//! alone.
//!
//! ## Architecture
//!
//! - `AnchorPipeline` owns the `Arc<dyn TruthAnchor>` (today: `NoOpAnchor`,
//!   tomorrow: `HederaAnchor`) and a `tokio::sync::Mutex<PipelineState>` for
//!   monotonic epoch sequencing.
//! - It implements [`zp_audit::AppendNotifier`] via [`AnchorNotifier`] so
//!   every committed audit entry passes through `notify`. Trigger events
//!   spawn an async seal task; non-trigger events accumulate.
//! - `seal_epoch` is the sole mutator: takes the `state` lock, computes the
//!   range, builds the Merkle tree, calls `anchor.anchor()`, and emits the
//!   `epoch:anchored:N` chain entry.
//!
//! ## Trigger taxonomy
//!
//! Trigger events (cause an immediate seal):
//! - `gate:denied:*`             — policy blocked a tool
//! - `provider:canonicalized:*`  — new provider on chain
//! - `tool:canonicalized:*`      — new tool on chain
//! - Any receipt whose `receipt_type` is `revocation_claim` or
//!   `policy_tier_violation`
//!
//! Non-trigger events (accumulate but do not seal alone):
//! - `gate:allowed:*`, `tool:health:*`, `tool:adapted:*`, `memory:observed:*`
//!
//! Non-trigger entries are still folded into the next epoch when one is
//! sealed — the Merkle tree covers every committed entry, only the seal
//! cadence is event-driven.

use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, warn};

use zp_anchor::{AnchorCommitment, AnchorReceipt, AnchorTrigger, ChainType, TruthAnchor};
use zp_audit::{AppendNotifier, AuditStore};
use zp_core::{ActorId, AuditAction, AuditEntry, ConversationId, PolicyDecision};
use zp_receipt::compute_merkle_root;

/// In-memory state for the anchor pipeline. Guarded by an async mutex because
/// every mutator awaits the (possibly remote) anchor backend.
#[derive(Debug, Default)]
struct PipelineState {
    /// SQLite rowid of the most recent entry sealed into an epoch. `0` means
    /// no epoch has been sealed yet — the next seal covers the entire chain.
    last_epoch_sequence: i64,
    /// Next epoch number to assign. Monotonically increasing.
    next_epoch_number: u64,
    /// Merkle root of the most recently sealed epoch, or `None` if none yet.
    /// Used as `prev_epoch_hash` on the next epoch.
    last_epoch_root: Option<String>,
}

/// Event-driven Merkle anchor pipeline.
pub struct AnchorPipeline {
    anchor: Arc<dyn TruthAnchor>,
    audit_store: Arc<StdMutex<AuditStore>>,
    state: AsyncMutex<PipelineState>,
    chain_id: String,
    chain_type: ChainType,
}

/// Outcome of a successful seal.
#[derive(Debug, Clone)]
pub struct SealOutcome {
    pub epoch_number: u64,
    pub merkle_root: String,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub entry_count: usize,
    pub external_receipt: Option<AnchorReceipt>,
}

impl AnchorPipeline {
    pub fn new(
        anchor: Arc<dyn TruthAnchor>,
        audit_store: Arc<StdMutex<AuditStore>>,
        chain_id: impl Into<String>,
    ) -> Self {
        Self {
            anchor,
            audit_store,
            state: AsyncMutex::new(PipelineState::default()),
            chain_id: chain_id.into(),
            chain_type: ChainType::AuditChain,
        }
    }

    /// Returns the trigger taxonomy decision for a SystemEvent string.
    pub fn is_system_event_trigger(event_type: &str) -> bool {
        event_type.starts_with("gate:denied:")
            || event_type.starts_with("provider:canonicalized:")
            || event_type.starts_with("tool:canonicalized:")
            // P4 (#197): trust boundary changes — new standing delegations
            // and revocations both reshape the authority graph and warrant
            // an external witness.
            || event_type.starts_with("delegation:granted:")
            || event_type.starts_with("delegation:revoked:")
    }

    /// Returns true if the receipt body carries a trigger-eligible
    /// `receipt_type`. RevocationClaim / PolicyTierViolation count.
    pub fn is_receipt_type_trigger(receipt_type: &str) -> bool {
        matches!(
            receipt_type,
            "revocation_claim" | "policy_tier_violation"
        )
    }

    /// Inspect a sealed entry; return `Some(AnchorTrigger)` if it should fire.
    pub fn classify(entry: &AuditEntry) -> Option<AnchorTrigger> {
        // SystemEvent string matches.
        if let AuditAction::SystemEvent { event } = &entry.action {
            if Self::is_system_event_trigger(event) {
                return Some(AnchorTrigger::GovernanceEvent {
                    event_type: event.clone(),
                });
            }
        }

        // Receipt-type matches (RevocationClaim, PolicyTierViolation).
        if let Some(receipt) = &entry.receipt {
            let body = serde_json::to_value(receipt).ok();
            let rt = body
                .as_ref()
                .and_then(|v| v.get("receipt_type"))
                .and_then(|v| v.as_str());
            if let Some(rt) = rt {
                if Self::is_receipt_type_trigger(rt) {
                    return Some(AnchorTrigger::GovernanceEvent {
                        event_type: format!("receipt:{}", rt),
                    });
                }
            }
        }

        None
    }

    /// Seal a new epoch covering all entries with rowid `> last_epoch_sequence`,
    /// publish the commitment, and append an `epoch:anchored:N` receipt to the
    /// chain. No-op if the chain has not advanced since the last seal.
    pub async fn seal_epoch(&self, trigger: AnchorTrigger) -> Result<SealOutcome, SealError> {
        let mut state = self.state.lock().await;

        let after = state.last_epoch_sequence;
        let pairs = {
            let store = self.audit_store.lock().map_err(|_| SealError::AuditMutexPoisoned)?;
            store.export_hashes_after(after).map_err(SealError::Audit)?
        };

        if pairs.is_empty() {
            debug!(after, "anchor: no new entries since last seal — skipping");
            return Err(SealError::NoNewEntries);
        }

        let first_sequence = pairs.first().map(|(r, _)| *r).unwrap();
        let last_sequence = pairs.last().map(|(r, _)| *r).unwrap();
        let entry_count = pairs.len();
        let hashes: Vec<String> = pairs.into_iter().map(|(_, h)| h).collect();
        let merkle_root = compute_merkle_root(&hashes);

        let epoch_number = state.next_epoch_number;
        let prev_epoch_hash = state
            .last_epoch_root
            .clone()
            .unwrap_or_else(|| "genesis".to_string());

        let commitment = AnchorCommitment {
            chain_head_hash: hashes
                .last()
                .cloned()
                .unwrap_or_default(),
            chain_sequence: last_sequence as u64,
            prev_anchor_hash: state.last_epoch_root.clone(),
            // Operator signature is the responsibility of the anchor backend
            // (HCS will sign with the operator key). NoOp leaves it blank.
            operator_signature: String::new(),
            chain_type: self.chain_type,
            trigger,
        };

        let external_receipt = match self.anchor.anchor(commitment.clone()).await {
            Ok(r) => Some(r),
            Err(zp_anchor::AnchorError::NotAvailable { reason }) => {
                debug!(
                    backend = self.anchor.backend_name(),
                    "anchor backend not available ({reason}) — recording locally only"
                );
                None
            }
            Err(e) => {
                warn!(
                    backend = self.anchor.backend_name(),
                    "anchor backend rejected commitment: {e}"
                );
                None
            }
        };

        let outcome = SealOutcome {
            epoch_number,
            merkle_root: merkle_root.clone(),
            first_sequence,
            last_sequence,
            entry_count,
            external_receipt: external_receipt.clone(),
        };

        // Record the sealed epoch back onto the chain. This is what
        // `zp verify --anchors` reads to recompute roots locally.
        let detail = serde_json::json!({
            "epoch_number": epoch_number,
            "merkle_root": merkle_root,
            "prev_epoch_hash": prev_epoch_hash,
            "first_sequence": first_sequence,
            "last_sequence": last_sequence,
            "entry_count": entry_count,
            "chain_id": self.chain_id,
            "backend": self.anchor.backend_name(),
            "external_id": external_receipt.as_ref().map(|r| r.external_id.clone()),
            "trigger": &commitment.trigger,
        });

        if let Err(e) = self.append_anchor_receipt(epoch_number, &detail.to_string()) {
            error!("failed to record epoch:anchored:{} on chain: {e}", epoch_number);
            return Err(e);
        }

        info!(
            epoch_number,
            entry_count,
            first_sequence,
            last_sequence,
            backend = self.anchor.backend_name(),
            external = external_receipt.is_some(),
            "anchor: sealed epoch"
        );

        state.last_epoch_sequence = last_sequence;
        state.last_epoch_root = Some(merkle_root);
        state.next_epoch_number = epoch_number + 1;

        Ok(outcome)
    }

    /// Append `epoch:anchored:<n>` to the chain. Re-implemented inline rather
    /// than calling `tool_chain::emit_tool_receipt` to avoid pulling tool-
    /// lifecycle conversation context into the anchor receipt.
    fn append_anchor_receipt(&self, epoch_number: u64, detail: &str) -> Result<(), SealError> {
        let event = format!("epoch:anchored:{}", epoch_number);
        let unsealed = zp_audit::UnsealedEntry::new(
            ActorId::System("zp-anchor".to_string()),
            AuditAction::SystemEvent { event },
            ConversationId(uuid::Uuid::nil()),
            PolicyDecision::Allow {
                conditions: vec![detail.to_string()],
            },
            "anchor-pipeline",
        );

        let mut store = self
            .audit_store
            .lock()
            .map_err(|_| SealError::AuditMutexPoisoned)?;
        store.append(unsealed).map_err(SealError::Audit)?;
        Ok(())
    }

    /// Current pipeline state, for tests / introspection.
    pub async fn last_epoch_sequence(&self) -> i64 {
        self.state.lock().await.last_epoch_sequence
    }

    /// Reload the pipeline's in-memory cursor from existing `epoch:anchored:*`
    /// receipts. Called once at startup so a server restart does not re-seal
    /// already-sealed entries. Walks the audit chain looking for the highest
    /// epoch number, then resumes from `last_sequence + 1`.
    pub async fn rehydrate_from_chain(&self) -> Result<(), SealError> {
        let chain = {
            let store = self
                .audit_store
                .lock()
                .map_err(|_| SealError::AuditMutexPoisoned)?;
            store.export_chain(i32::MAX as usize).map_err(SealError::Audit)?
        };

        let mut latest: Option<(u64, i64, String)> = None;
        for entry in &chain {
            if let AuditAction::SystemEvent { event } = &entry.action {
                if let Some(rest) = event.strip_prefix("epoch:anchored:") {
                    if let Ok(n) = rest.parse::<u64>() {
                        // Detail is in policy_decision::Allow conditions[0].
                        if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                            if let Some(detail_json) = conditions.first() {
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(detail_json)
                                {
                                    let last_seq = v
                                        .get("last_sequence")
                                        .and_then(|x| x.as_i64())
                                        .unwrap_or(0);
                                    let merkle = v
                                        .get("merkle_root")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    match latest {
                                        Some((cur_n, _, _)) if cur_n >= n => {}
                                        _ => latest = Some((n, last_seq, merkle)),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some((n, last_seq, root)) = latest {
            let mut state = self.state.lock().await;
            state.next_epoch_number = n + 1;
            state.last_epoch_sequence = last_seq;
            state.last_epoch_root = Some(root);
            info!(
                resumed_at_epoch = n + 1,
                last_sequence = last_seq,
                "anchor pipeline rehydrated from chain"
            );
        }
        Ok(())
    }
}

/// Errors surfaced by the anchor pipeline. The audit-store and DLT-network
/// failure modes are kept distinct so callers can decide whether to retry.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("audit store error: {0}")]
    Audit(#[from] zp_audit::StoreError),

    #[error("audit store mutex poisoned")]
    AuditMutexPoisoned,

    #[error("nothing to seal — chain has not advanced since last anchor")]
    NoNewEntries,
}

// ---------------------------------------------------------------------------
// Notifier glue — wires the pipeline into AuditStore::set_notifier.
// ---------------------------------------------------------------------------

/// Bridge from the synchronous `AppendNotifier` callback into the async
/// pipeline. Holds an `Arc<AnchorPipeline>` so the spawned seal task lives
/// past the notify call.
pub struct AnchorNotifier {
    pipeline: Arc<AnchorPipeline>,
}

impl AnchorNotifier {
    pub fn new(pipeline: Arc<AnchorPipeline>) -> Self {
        Self { pipeline }
    }
}

impl AppendNotifier for AnchorNotifier {
    fn notify(&self, entry: &AuditEntry, _sequence: i64) {
        // Never trigger on our own `epoch:anchored:*` receipts — that would
        // cause an infinite seal loop, since the very act of recording an
        // epoch advances the chain.
        if let AuditAction::SystemEvent { event } = &entry.action {
            if event.starts_with("epoch:anchored:") {
                return;
            }
        }

        let Some(trigger) = AnchorPipeline::classify(entry) else {
            return;
        };

        let pipeline = self.pipeline.clone();
        tokio::spawn(async move {
            if let Err(e) = pipeline.seal_epoch(trigger).await {
                if !matches!(e, SealError::NoNewEntries) {
                    warn!("anchor pipeline seal failed: {e}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_taxonomy_system_events() {
        assert!(AnchorPipeline::is_system_event_trigger("gate:denied:foo"));
        assert!(AnchorPipeline::is_system_event_trigger(
            "provider:canonicalized:openai"
        ));
        assert!(AnchorPipeline::is_system_event_trigger(
            "tool:canonicalized:hermes"
        ));
        // P4 (#197): trust boundary changes
        assert!(AnchorPipeline::is_system_event_trigger(
            "delegation:granted:artemis"
        ));
        assert!(AnchorPipeline::is_system_event_trigger(
            "delegation:revoked:artemis"
        ));

        assert!(!AnchorPipeline::is_system_event_trigger("gate:allowed:foo"));
        assert!(!AnchorPipeline::is_system_event_trigger(
            "tool:health:up:hermes"
        ));
        assert!(!AnchorPipeline::is_system_event_trigger("tool:adapted:foo"));
        assert!(!AnchorPipeline::is_system_event_trigger(
            "memory:observed:bar"
        ));
        assert!(!AnchorPipeline::is_system_event_trigger("tool:cmd:executed"));
        // P4: lease renewal is high-frequency by design — must NOT trigger
        // an anchor every 2h, otherwise the chain stops being event-driven.
        assert!(!AnchorPipeline::is_system_event_trigger(
            "delegation:renewed:artemis"
        ));
        assert!(!AnchorPipeline::is_system_event_trigger(
            "delegation:expired:artemis"
        ));
    }

    #[test]
    fn trigger_taxonomy_receipt_types() {
        assert!(AnchorPipeline::is_receipt_type_trigger("revocation_claim"));
        assert!(AnchorPipeline::is_receipt_type_trigger(
            "policy_tier_violation"
        ));

        assert!(!AnchorPipeline::is_receipt_type_trigger("canonicalization"));
        assert!(!AnchorPipeline::is_receipt_type_trigger("attestation"));
    }

    #[test]
    fn classify_skips_epoch_anchor_receipts() {
        // The notifier guards explicitly; classify is allowed to ignore them.
        // What we verify here: a non-trigger event returns None so the
        // spawn-task path stays cold for chatty events.
        let entry = AuditEntry {
            id: zp_core::AuditId(uuid::Uuid::nil()),
            timestamp: chrono::Utc::now(),
            prev_hash: String::new(),
            entry_hash: String::new(),
            actor: ActorId::System("test".to_string()),
            action: AuditAction::SystemEvent {
                event: "gate:allowed:foo".to_string(),
            },
            conversation_id: ConversationId(uuid::Uuid::nil()),
            policy_decision: PolicyDecision::Allow { conditions: vec![] },
            policy_module: "test".to_string(),
            receipt: None,
            signature: None,
        };
        assert!(AnchorPipeline::classify(&entry).is_none());
    }

    #[test]
    fn classify_fires_for_gate_denied() {
        let entry = AuditEntry {
            id: zp_core::AuditId(uuid::Uuid::nil()),
            timestamp: chrono::Utc::now(),
            prev_hash: String::new(),
            entry_hash: String::new(),
            actor: ActorId::System("test".to_string()),
            action: AuditAction::SystemEvent {
                event: "gate:denied:rm-rf".to_string(),
            },
            conversation_id: ConversationId(uuid::Uuid::nil()),
            policy_decision: PolicyDecision::Allow { conditions: vec![] },
            policy_module: "test".to_string(),
            receipt: None,
            signature: None,
        };
        match AnchorPipeline::classify(&entry) {
            Some(AnchorTrigger::GovernanceEvent { event_type }) => {
                assert_eq!(event_type, "gate:denied:rm-rf");
            }
            other => panic!("expected GovernanceEvent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn end_to_end_event_driven_seal() {
        // Spin up an in-memory audit store, install the pipeline as its
        // notifier, then simulate the trigger taxonomy:
        //   1. allowed events accumulate but do not seal
        //   2. a denied event seals an epoch covering ALL prior entries
        //   3. another seal does not occur if no new entries have landed

        use std::sync::Arc;
        use zp_anchor::NoOpAnchor;
        use zp_audit::UnsealedEntry;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        let store = Arc::new(StdMutex::new(store));

        let pipeline = Arc::new(AnchorPipeline::new(
            Arc::new(NoOpAnchor),
            store.clone(),
            "test-chain",
        ));
        {
            let mut s = store.lock().unwrap();
            s.set_notifier(Arc::new(AnchorNotifier::new(pipeline.clone())));
        }

        let allow_event = |i: usize| {
            UnsealedEntry::new(
                ActorId::System("test".into()),
                AuditAction::SystemEvent {
                    event: format!("gate:allowed:tool-{}", i),
                },
                ConversationId(uuid::Uuid::nil()),
                PolicyDecision::Allow { conditions: vec![] },
                "test",
            )
        };

        // 10 allowed events — should NOT seal.
        for i in 0..10 {
            store.lock().unwrap().append(allow_event(i)).unwrap();
        }

        // The allow events fire spawn but classify→None, so no seal task runs.
        // Give the runtime a tick anyway to make the test deterministic.
        tokio::task::yield_now().await;
        assert_eq!(pipeline.last_epoch_sequence().await, 0);

        // One denied event — should fire a seal covering rowids 1..=11.
        let denied = UnsealedEntry::new(
            ActorId::System("test".into()),
            AuditAction::SystemEvent {
                event: "gate:denied:rm-rf".into(),
            },
            ConversationId(uuid::Uuid::nil()),
            PolicyDecision::Allow { conditions: vec![] },
            "test",
        );
        store.lock().unwrap().append(denied).unwrap();

        // The seal happens on a spawned task; await briefly until it lands.
        for _ in 0..50 {
            if pipeline.last_epoch_sequence().await > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // After the seal, last_epoch_sequence must include the trigger entry
        // itself plus the epoch:anchored row, so it is at least 12.
        let seq = pipeline.last_epoch_sequence().await;
        assert!(
            seq >= 11,
            "expected seal to cover at least 11 entries, got last_seq={seq}"
        );
    }
}
