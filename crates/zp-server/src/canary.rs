//! Chain-Read Canary Discipline — Tier 1 implementation.
//!
//! Spec: `docs/design/CHAIN-READ-CANARY-DISCIPLINE-2026-07.md`
//!
//! First concrete implementation of the discipline. Periodically writes
//! canary marker entries to the chain, then probes each declared observer's
//! tail-read visibility. Missed canary triggers Tier 1 remediation
//! (statement cache flush + WAL checkpoint restart).
//!
//! ## Scope (Tier 1 only)
//!
//! - Cadence: 60s per spec default.
//! - Single hardcoded observer (chain reader via `ChainReader::recent_entries`) —
//!   same code path Steward uses; the exact fault case identified 2026-07-15.
//! - Tier 1 remediation: statement cache flush + WAL checkpoint restart.
//! - Re-probe after remediation to verify success.
//!
//! ## Deferred to later implementation
//!
//! - Tier 2 (Connection rebuild)
//! - Tier 3 (observer restart)
//! - Tier 4 (Circuit breaker escalation)
//! - Multi-observer registry (needs OBSERVER-COHERENCE-DISCIPLINE spec's registry model)
//! - Layer B canonical config for cadence, thresholds, remediation policy
//!
//! ## Chain surface
//!
//! Every cycle emits at least two receipts (write + probe result), possibly
//! more (remediation + re-probe). Structural evidence, no content bloat.
//!
//! - `chain:canary:written <canary_id>` — canary marker
//! - `chain:canary:verified <observer_id> <canary_id>` — probe succeeded
//! - `chain:canary:missed <observer_id> <canary_id>` — probe failed
//! - `chain:canary:remediated <observer_id> <canary_id> <method>` — remediation succeeded
//! - `chain:canary:remediation_failed <observer_id> <canary_id>` — remediation insufficient

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{info, warn};

use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
use zp_officers::officer::ChainReader;

/// How often the canary runtime writes + probes.
///
/// Per spec §"Cadence": 60 seconds for Class 1 chain readers.
const CANARY_INTERVAL_SECS: u64 = 60;

/// How many entries to fetch when probing for the canary marker.
///
/// Bounded high enough that recent activity between canary-write and
/// probe (officer heartbeats, sensor events) doesn't push the canary out
/// of the query window.
const PROBE_LIMIT: usize = 100;

/// Sequential canary ID counter. Wrap-around after u64::MAX would take
/// ~584 billion years at 1 canary/second — not a real concern.
static CANARY_SEQ: AtomicU64 = AtomicU64::new(0);

/// Canonical namespace for canary conversation attribution.
fn canary_conv_id() -> ConversationId {
    // UUID `00000000-0003-7000-8001-000000000001` — canary namespace.
    ConversationId(uuid::Uuid::parse_str("00000000-0003-7000-8001-000000000001").unwrap())
}

/// Canonical actor identity for canary-emitted receipts.
fn canary_actor() -> ActorId {
    ActorId::System("canary".to_string())
}

/// The Chain-Read Canary runtime.
pub struct CanaryRuntime {
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
    interval_secs: u64,
}

impl CanaryRuntime {
    pub fn new(audit_store: Arc<std::sync::Mutex<AuditStore>>) -> Self {
        Self {
            audit_store,
            interval_secs: CANARY_INTERVAL_SECS,
        }
    }

    /// Override cadence for tests.
    #[cfg(test)]
    pub fn with_interval_secs(mut self, secs: u64) -> Self {
        self.interval_secs = secs;
        self
    }

    /// Spawn the canary runtime as a long-running background task.
    ///
    /// Returns the JoinHandle so the caller can hold ownership. The task
    /// runs until cancelled or the process exits.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    async fn run(self) {
        info!(
            "chain-read canary discipline: runtime started (cadence {}s)",
            self.interval_secs
        );
        let mut ticker = interval(Duration::from_secs(self.interval_secs));
        // First tick fires immediately — skip to let the substrate settle before
        // the first canary probe.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            self.run_one_cycle().await;
        }
    }

    /// Execute one canary cycle: write + probe + optional remediate + re-probe.
    ///
    /// Public for tests to exercise a single cycle without waiting for the ticker.
    pub async fn run_one_cycle(&self) {
        let canary_id = CANARY_SEQ.fetch_add(1, Ordering::SeqCst);

        // Step 1: write canary marker to chain.
        if let Err(e) = self.write_canary(canary_id) {
            warn!("canary: write failed (canary_id={}): {}", canary_id, e);
            return;
        }

        // Step 2: probe each declared observer. V1 has a single hardcoded observer.
        let observer_id = "chain_reader";
        let probe_start = Instant::now();
        let outcome = self.probe_chain_reader(canary_id, PROBE_LIMIT);
        let probe_ms = probe_start.elapsed().as_millis() as u64;

        match outcome {
            ProbeOutcome::Fresh => {
                self.emit_verified(observer_id, canary_id, probe_ms);
            }
            ProbeOutcome::Stuck { probed_entries } => {
                warn!(
                    "canary: chain_reader observer STUCK (canary_id={}, probed {} entries, marker absent)",
                    canary_id, probed_entries
                );
                self.emit_missed(observer_id, canary_id, probe_ms, probed_entries);
                self.remediate_tier1(observer_id, canary_id);
            }
            ProbeOutcome::Unresponsive(reason) => {
                warn!(
                    "canary: chain_reader probe unresponsive (canary_id={}): {}",
                    canary_id, reason
                );
                // Unresponsive is a different fault class than stuck; skip Tier 1
                // remediation and emit a distinct receipt.
                self.emit_unresponsive(observer_id, canary_id, &reason);
            }
        }
    }

    fn write_canary(&self, canary_id: u64) -> Result<(), String> {
        let event = format!("chain:canary:written {}", canary_id);
        let entry = UnsealedEntry {
            actor: canary_actor(),
            action: AuditAction::SystemEvent { event },
            conversation_id: canary_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "canary".to_string(),
            receipt: None,
        };

        let mut store = self
            .audit_store
            .lock()
            .map_err(|e| format!("audit store lock poisoned: {}", e))?;
        store.append(entry).map(|_| ()).map_err(|e| e.to_string())
    }

    /// Probe the chain-reader observer for canary visibility.
    ///
    /// Uses the same `ChainReader::recent_entries` code path Steward uses in
    /// `check_chain_growth`. This is the exact fault case identified 2026-07-15
    /// during P1.1 diagnosis — if this probe misses the just-written canary,
    /// the connection is stuck at a stale snapshot.
    fn probe_chain_reader(&self, canary_id: u64, limit: usize) -> ProbeOutcome {
        let target_marker = format!("chain:canary:written {}", canary_id);

        let store = match self.audit_store.lock() {
            Ok(s) => s,
            Err(e) => return ProbeOutcome::Unresponsive(format!("lock poisoned: {}", e)),
        };
        let chain = ChainReader::new(&*store);

        let entries = match chain.recent_entries(limit) {
            Ok(e) => e,
            Err(e) => return ProbeOutcome::Unresponsive(format!("read error: {}", e)),
        };

        // Look for our canary marker in the returned tail.
        for entry in &entries {
            if let AuditAction::SystemEvent { ref event } = entry.action {
                if event == &target_marker {
                    return ProbeOutcome::Fresh;
                }
            }
        }

        ProbeOutcome::Stuck {
            probed_entries: entries.len(),
        }
    }

    /// Tier 1 remediation: statement cache flush + WAL checkpoint restart + re-probe.
    ///
    /// If the re-probe succeeds, chain-anchor the remediation success. If it
    /// still fails, chain-anchor remediation-failed — escalation to Tier 2
    /// (Connection rebuild) would happen here in a full implementation.
    fn remediate_tier1(&self, observer_id: &str, canary_id: u64) {
        info!(
            "canary: Tier 1 remediation for observer {} (canary_id={})",
            observer_id, canary_id
        );

        // Step A: flush statement cache. Discards cached prepared statements
        // that may hold implicit read transactions.
        {
            let mut store = match self.audit_store.lock() {
                Ok(s) => s,
                Err(e) => {
                    warn!("canary: remediation lock failed: {}", e);
                    return;
                }
            };
            store.flush_statement_cache();
        }

        // Step B: WAL checkpoint RESTART. Waits for active readers to release
        // their snapshot, then restarts the WAL. Forces snapshot-boundary refresh.
        {
            let store = match self.audit_store.lock() {
                Ok(s) => s,
                Err(e) => {
                    warn!("canary: WAL checkpoint lock failed: {}", e);
                    return;
                }
            };
            match store.wal_checkpoint_restart() {
                Ok((busy, log, checkpointed)) => {
                    info!(
                        "canary: WAL checkpoint RESTART (busy={}, log={}, checkpointed={})",
                        busy, log, checkpointed
                    );
                }
                Err(e) => {
                    warn!("canary: WAL checkpoint failed: {}", e);
                }
            }
        }

        // Step C: re-probe to verify remediation actually made the canary visible.
        let re_probe_start = Instant::now();
        let re_outcome = self.probe_chain_reader(canary_id, PROBE_LIMIT);
        let re_probe_ms = re_probe_start.elapsed().as_millis() as u64;

        match re_outcome {
            ProbeOutcome::Fresh => {
                info!(
                    "canary: Tier 1 remediation SUCCEEDED for {} (canary_id={}, re-probe {}ms)",
                    observer_id, canary_id, re_probe_ms
                );
                self.emit_remediated(observer_id, canary_id, "cache_flush+wal_restart");
            }
            ProbeOutcome::Stuck { .. } => {
                warn!(
                    "canary: Tier 1 remediation INSUFFICIENT for {} (canary_id={}) — Tier 2 (Connection rebuild) would fire here",
                    observer_id, canary_id
                );
                self.emit_remediation_failed(observer_id, canary_id, "cache_flush+wal_restart");
            }
            ProbeOutcome::Unresponsive(reason) => {
                warn!(
                    "canary: re-probe unresponsive after remediation (canary_id={}): {}",
                    canary_id, reason
                );
                self.emit_remediation_failed(observer_id, canary_id, "cache_flush+wal_restart");
            }
        }
    }

    // ── Receipt emission helpers ──────────────────────────────────────────

    fn emit_verified(&self, observer_id: &str, canary_id: u64, probe_ms: u64) {
        self.emit_event(format!(
            "chain:canary:verified {} {} probe_ms={}",
            observer_id, canary_id, probe_ms
        ));
    }

    fn emit_missed(
        &self,
        observer_id: &str,
        canary_id: u64,
        probe_ms: u64,
        probed_entries: usize,
    ) {
        self.emit_event(format!(
            "chain:canary:missed {} {} probe_ms={} probed_entries={}",
            observer_id, canary_id, probe_ms, probed_entries
        ));
    }

    fn emit_unresponsive(&self, observer_id: &str, canary_id: u64, reason: &str) {
        self.emit_event(format!(
            "chain:canary:unresponsive {} {} reason={}",
            observer_id, canary_id, reason
        ));
    }

    fn emit_remediated(&self, observer_id: &str, canary_id: u64, method: &str) {
        self.emit_event(format!(
            "chain:canary:remediated {} {} method={}",
            observer_id, canary_id, method
        ));
    }

    fn emit_remediation_failed(&self, observer_id: &str, canary_id: u64, method: &str) {
        self.emit_event(format!(
            "chain:canary:remediation_failed {} {} method={}",
            observer_id, canary_id, method
        ));
    }

    fn emit_event(&self, event: String) {
        let entry = UnsealedEntry {
            actor: canary_actor(),
            action: AuditAction::SystemEvent { event },
            conversation_id: canary_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "canary".to_string(),
            receipt: None,
        };
        match self.audit_store.lock() {
            Ok(mut store) => {
                if let Err(e) = store.append(entry) {
                    warn!("canary: receipt emission failed: {}", e);
                }
            }
            Err(e) => {
                warn!("canary: receipt emission lock poisoned: {}", e);
            }
        }
    }
}

/// Outcome of a single probe against an observer.
#[derive(Debug)]
enum ProbeOutcome {
    /// Observer saw the canary — read path fresh.
    Fresh,
    /// Observer did not see the canary — read path stuck at stale snapshot.
    Stuck { probed_entries: usize },
    /// Observer probe couldn't complete (lock error, read error, etc.).
    /// Different fault class than Stuck — signals infrastructure failure,
    /// not necessarily a stale snapshot.
    Unresponsive(String),
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_store() -> (Arc<std::sync::Mutex<AuditStore>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path: PathBuf = tmp.path().join("canary_test.db");
        let store = AuditStore::open_unsigned(&path).expect("open store");
        (Arc::new(std::sync::Mutex::new(store)), tmp)
    }

    fn count_events_with_prefix(
        store: &Arc<std::sync::Mutex<AuditStore>>,
        prefix: &str,
    ) -> usize {
        let store = store.lock().expect("lock");
        store
            .search_chain_by_action_keyword(prefix, 1024)
            .expect("search")
            .len()
    }

    #[tokio::test]
    async fn canary_cycle_writes_marker_and_verifies_when_fresh() {
        let (store, _tmp) = temp_store();
        let runtime = CanaryRuntime::new(store.clone()).with_interval_secs(3600);

        runtime.run_one_cycle().await;

        // Expect at least one written marker and one verified receipt.
        assert!(count_events_with_prefix(&store, "chain:canary:written") >= 1);
        assert!(count_events_with_prefix(&store, "chain:canary:verified") >= 1);
        // No missed receipts on a healthy fresh store.
        assert_eq!(count_events_with_prefix(&store, "chain:canary:missed"), 0);
    }

    #[tokio::test]
    async fn multiple_cycles_produce_multiple_verifications() {
        let (store, _tmp) = temp_store();
        let runtime = CanaryRuntime::new(store.clone()).with_interval_secs(3600);

        runtime.run_one_cycle().await;
        runtime.run_one_cycle().await;
        runtime.run_one_cycle().await;

        assert_eq!(count_events_with_prefix(&store, "chain:canary:written"), 3);
        assert_eq!(count_events_with_prefix(&store, "chain:canary:verified"), 3);
    }

    #[tokio::test]
    async fn probe_finds_marker_at_various_tail_positions() {
        let (store, _tmp) = temp_store();
        let runtime = CanaryRuntime::new(store.clone()).with_interval_secs(3600);

        // Emit some background activity that will sit between canary write + probe.
        {
            let mut s = store.lock().unwrap();
            for i in 0..30 {
                let entry = UnsealedEntry {
                    actor: ActorId::System("background".to_string()),
                    action: AuditAction::SystemEvent {
                        event: format!("background:noise:{}", i),
                    },
                    conversation_id: canary_conv_id(),
                    policy_decision: PolicyDecision::Allow {
                        conditions: Vec::new(),
                    },
                    policy_module: "test".to_string(),
                    receipt: None,
                };
                s.append(entry).unwrap();
            }
        }

        runtime.run_one_cycle().await;

        // Canary should still be findable within PROBE_LIMIT (100) — background
        // noise plus canary write is well under the limit.
        assert_eq!(count_events_with_prefix(&store, "chain:canary:verified"), 1);
        assert_eq!(count_events_with_prefix(&store, "chain:canary:missed"), 0);
    }

    #[tokio::test]
    async fn wal_checkpoint_restart_returns_result_triple() {
        let (store, _tmp) = temp_store();
        // Populate the chain with a few entries to force some WAL frames.
        {
            let mut s = store.lock().unwrap();
            for i in 0..10 {
                let entry = UnsealedEntry {
                    actor: ActorId::System("bulk".to_string()),
                    action: AuditAction::SystemEvent {
                        event: format!("bulk:{}", i),
                    },
                    conversation_id: canary_conv_id(),
                    policy_decision: PolicyDecision::Allow {
                        conditions: Vec::new(),
                    },
                    policy_module: "test".to_string(),
                    receipt: None,
                };
                s.append(entry).unwrap();
            }
        }

        let s = store.lock().unwrap();
        let (busy, log, checkpointed) = s.wal_checkpoint_restart().expect("checkpoint");
        // busy typically 0 in a single-thread test; log and checkpointed non-negative.
        assert!(busy >= 0);
        assert!(log >= 0);
        assert!(checkpointed >= 0);
    }

    #[tokio::test]
    async fn statement_cache_flush_does_not_break_subsequent_reads() {
        let (store, _tmp) = temp_store();
        // Warm the cache with a query.
        {
            let s = store.lock().unwrap();
            let _ = s.recent_entries(10).unwrap();
        }
        // Flush.
        {
            let mut s = store.lock().unwrap();
            s.flush_statement_cache();
        }
        // Post-flush query should still work — statements re-prepare on demand.
        {
            let s = store.lock().unwrap();
            let entries = s.recent_entries(10).unwrap();
            // Empty or non-empty is fine; we're verifying no panic and no error.
            let _ = entries;
        }
    }

    #[test]
    fn canary_sequence_is_monotonic() {
        let first = CANARY_SEQ.fetch_add(1, Ordering::SeqCst);
        let second = CANARY_SEQ.fetch_add(1, Ordering::SeqCst);
        assert!(second > first);
    }
}
