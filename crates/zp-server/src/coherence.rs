//! Observer Coherence Discipline — Class 1 (chain readers) implementation.
//!
//! Spec: `docs/design/OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` §Class 1.
//!
//! Periodic cross-check runtime that probes the audit chain via multiple
//! query strategies and emits chain-anchored discrepancy findings when
//! strategies diverge. First concrete Class 1 implementation.
//!
//! ## V1 scope (this file)
//!
//! Three probe strategies on the shared connection:
//! - **Probe A** — newest by rowid (`ORDER BY rowid DESC LIMIT 1`)
//! - **Probe B** — newest by timestamp (`ORDER BY timestamp DESC LIMIT 1`)
//! - **Probe C** — dedicated latest-hash query (redundant with A but through
//!   an independent prepared statement)
//!
//! Agreement → `coherence:verified:class1_chain_readers` receipt.
//! Divergence → `coherence:diverged:class1_chain_readers` receipt with
//! per-probe values so the diagnosis is chain-anchored.
//!
//! ## Deferred to later versions
//!
//! - Ground-truth arbitration via fresh Connection (spec §"Ground-truth
//!   arbitration" — optional, operator-authorized)
//! - Per-observer probes (invoke Steward's chain_growth, Cleo's
//!   search_by_keyword, Regent's chain_query tool independently and compare
//!   their view of the tail)
//! - Class 2 (ontology queriers), Class 3 (observation-plane consumers),
//!   Class 4 (vault key listers) — separate implementation arcs

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{info, warn};

use zp_audit::{AuditStore, TailProbes, UnsealedEntry};
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

/// Cadence for Class 1 cross-check. Per spec §"Trigger": default 5 minutes.
const COHERENCE_INTERVAL_SECS: u64 = 300;

/// Canonical namespace for coherence conversation attribution.
fn coherence_conv_id() -> ConversationId {
    ConversationId(uuid::Uuid::parse_str("00000000-0004-7000-8001-000000000001").unwrap())
}

/// Canonical actor identity for coherence-emitted receipts.
fn coherence_actor() -> ActorId {
    ActorId::System("coherence".to_string())
}

/// The Observer Coherence Class 1 runtime.
pub struct CoherenceRuntime {
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
    interval_secs: u64,
}

impl CoherenceRuntime {
    pub fn new(audit_store: Arc<std::sync::Mutex<AuditStore>>) -> Self {
        Self {
            audit_store,
            interval_secs: COHERENCE_INTERVAL_SECS,
        }
    }

    #[cfg(test)]
    pub fn with_interval_secs(mut self, secs: u64) -> Self {
        self.interval_secs = secs;
        self
    }

    /// Spawn the coherence runtime as a long-running background task.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    async fn run(self) {
        info!(
            "observer coherence discipline (Class 1 chain readers): runtime started (cadence {}s)",
            self.interval_secs
        );
        let mut ticker = interval(Duration::from_secs(self.interval_secs));
        // First tick fires immediately — skip to let substrate settle.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            self.run_one_cycle().await;
        }
    }

    /// Execute one Class 1 cross-check cycle.
    ///
    /// Public for tests to exercise a single cycle without waiting for ticker.
    pub async fn run_one_cycle(&self) {
        let probe_start = Instant::now();
        let probes = match self.fetch_probes() {
            Ok(p) => p,
            Err(e) => {
                warn!("coherence class1: tail_probes failed: {}", e);
                return;
            }
        };
        let probe_ms = probe_start.elapsed().as_millis() as u64;

        let report = evaluate_class1_coherence(&probes);
        self.emit_receipt(&report, probe_ms, &probes);
    }

    fn fetch_probes(&self) -> Result<TailProbes, String> {
        let store = self
            .audit_store
            .lock()
            .map_err(|e| format!("audit store lock poisoned: {}", e))?;
        store.tail_probes().map_err(|e| e.to_string())
    }

    fn emit_receipt(&self, report: &CoherenceReport, probe_ms: u64, probes: &TailProbes) {
        let event = match report {
            CoherenceReport::EmptyChain => {
                // Empty chain is not a coherence failure — nothing to compare.
                // Emit informational receipt so absence is chain-anchored.
                "coherence:verified:class1_chain_readers empty_chain=true".to_string()
            }
            CoherenceReport::Verified {
                tail_rowid,
                tail_hash,
                tail_timestamp,
            } => {
                let short = &tail_hash[..tail_hash.len().min(12)];
                format!(
                    "coherence:verified:class1_chain_readers tail_rowid={} tail_hash={} tail_ts={} probe_ms={} live_count={}",
                    tail_rowid, short, tail_timestamp, probe_ms, probes.live_count
                )
            }
            CoherenceReport::Diverged { detail } => {
                warn!(
                    "coherence class1: CHAIN READERS DIVERGED — {}",
                    detail
                );
                format!(
                    "coherence:diverged:class1_chain_readers probe_ms={} live_count={} detail={}",
                    probe_ms, probes.live_count, detail
                )
            }
        };

        let entry = UnsealedEntry {
            actor: coherence_actor(),
            action: AuditAction::SystemEvent { event },
            conversation_id: coherence_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "coherence".to_string(),
            receipt: None,
        };

        match self.audit_store.lock() {
            Ok(mut store) => {
                if let Err(e) = store.append(entry) {
                    warn!("coherence receipt emission failed: {}", e);
                }
            }
            Err(e) => {
                warn!("coherence receipt lock poisoned: {}", e);
            }
        }
    }
}

/// Outcome of a Class 1 coherence evaluation.
#[derive(Debug)]
pub enum CoherenceReport {
    /// Chain is empty — no coherence to evaluate; not a failure.
    EmptyChain,
    /// All three probe strategies agree on the tail.
    Verified {
        tail_rowid: i64,
        tail_hash: String,
        tail_timestamp: String,
    },
    /// Probes disagree — chain readers are producing incoherent views.
    Diverged { detail: String },
}

/// Pure evaluation function — takes probe results, returns coherence assessment.
/// Extracted for testability.
pub fn evaluate_class1_coherence(probes: &TailProbes) -> CoherenceReport {
    match (&probes.by_rowid, &probes.by_timestamp, &probes.via_latest_hash) {
        (None, None, None) => CoherenceReport::EmptyChain,
        (Some(a), Some(b), Some(hash_c)) => {
            // All three probes returned data — check agreement.
            let rowid_match = a.rowid == b.rowid;
            let hash_ab_match = a.entry_hash == b.entry_hash;
            let hash_ac_match = a.entry_hash == *hash_c;
            let ts_match = a.timestamp == b.timestamp;

            if rowid_match && hash_ab_match && hash_ac_match && ts_match {
                CoherenceReport::Verified {
                    tail_rowid: a.rowid,
                    tail_hash: a.entry_hash.clone(),
                    tail_timestamp: a.timestamp.to_rfc3339(),
                }
            } else {
                // Divergence detected — build detailed diagnosis.
                let mut faults = Vec::new();
                if !rowid_match {
                    faults.push(format!(
                        "rowid_mismatch(by_rowid={} by_timestamp={})",
                        a.rowid, b.rowid
                    ));
                }
                if !hash_ab_match {
                    faults.push(format!(
                        "hash_ab_mismatch(by_rowid={}...{}, by_timestamp={}...{})",
                        &a.entry_hash[..a.entry_hash.len().min(8)],
                        if a.entry_hash.len() > 8 { "…" } else { "" },
                        &b.entry_hash[..b.entry_hash.len().min(8)],
                        if b.entry_hash.len() > 8 { "…" } else { "" }
                    ));
                }
                if !hash_ac_match {
                    faults.push(format!(
                        "hash_ac_mismatch(by_rowid_hash={}...{} vs latest_hash={}...{})",
                        &a.entry_hash[..a.entry_hash.len().min(8)],
                        if a.entry_hash.len() > 8 { "…" } else { "" },
                        &hash_c[..hash_c.len().min(8)],
                        if hash_c.len() > 8 { "…" } else { "" }
                    ));
                }
                if !ts_match {
                    faults.push(format!(
                        "timestamp_mismatch(by_rowid_ts={} by_timestamp_ts={})",
                        a.timestamp.to_rfc3339(),
                        b.timestamp.to_rfc3339()
                    ));
                }
                CoherenceReport::Diverged {
                    detail: faults.join("|"),
                }
            }
        }
        _ => {
            // Partial results — some probes returned Some, others None.
            // That's a divergence too (all probes should behave alike on
            // the same non-empty chain).
            let a = probes.by_rowid.is_some();
            let b = probes.by_timestamp.is_some();
            let c = probes.via_latest_hash.is_some();
            CoherenceReport::Diverged {
                detail: format!(
                    "partial_probe_results(by_rowid={} by_timestamp={} via_latest_hash={})",
                    a, b, c
                ),
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use zp_audit::TailEntry;

    fn temp_store() -> (Arc<std::sync::Mutex<AuditStore>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path: PathBuf = tmp.path().join("coherence_test.db");
        let store = AuditStore::open_unsigned(&path).expect("open store");
        (Arc::new(std::sync::Mutex::new(store)), tmp)
    }

    fn write_event(store: &Arc<std::sync::Mutex<AuditStore>>, event: &str) {
        let entry = UnsealedEntry {
            actor: ActorId::System("test".to_string()),
            action: AuditAction::SystemEvent {
                event: event.to_string(),
            },
            conversation_id: coherence_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "test".to_string(),
            receipt: None,
        };
        store.lock().unwrap().append(entry).expect("append");
    }

    fn count_events_with_prefix(
        store: &Arc<std::sync::Mutex<AuditStore>>,
        prefix: &str,
    ) -> usize {
        let store = store.lock().unwrap();
        store
            .search_chain_by_action_keyword(prefix, 1024)
            .expect("search")
            .len()
    }

    #[tokio::test]
    async fn empty_chain_reports_empty_not_divergence() {
        let (store, _tmp) = temp_store();
        let runtime = CoherenceRuntime::new(store.clone()).with_interval_secs(3600);
        runtime.run_one_cycle().await;
        // Empty chain emits informational verified receipt.
        assert!(count_events_with_prefix(&store, "coherence:verified:class1_chain_readers") >= 1);
        assert_eq!(count_events_with_prefix(&store, "coherence:diverged:class1_chain_readers"), 0);
    }

    #[tokio::test]
    async fn healthy_chain_produces_verified_receipt() {
        let (store, _tmp) = temp_store();
        // Write some background activity to populate the chain.
        for i in 0..5 {
            write_event(&store, &format!("bg:activity:{}", i));
        }
        let runtime = CoherenceRuntime::new(store.clone()).with_interval_secs(3600);
        runtime.run_one_cycle().await;
        // Healthy chain: probes agree, verified receipt emitted, no divergence.
        assert!(count_events_with_prefix(&store, "coherence:verified:class1_chain_readers") >= 1);
        assert_eq!(count_events_with_prefix(&store, "coherence:diverged:class1_chain_readers"), 0);
    }

    #[test]
    fn evaluate_returns_empty_for_all_none_probes() {
        let probes = TailProbes {
            by_rowid: None,
            by_timestamp: None,
            via_latest_hash: None,
            live_count: 0,
            archive_exists: false,
        };
        match evaluate_class1_coherence(&probes) {
            CoherenceReport::EmptyChain => {}
            other => panic!("expected EmptyChain, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_returns_verified_when_all_probes_agree() {
        let ts = chrono::Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let tail = TailEntry {
            rowid: 42,
            entry_hash: "abcdef1234567890".to_string(),
            timestamp: ts,
        };
        let probes = TailProbes {
            by_rowid: Some(tail.clone()),
            by_timestamp: Some(tail.clone()),
            via_latest_hash: Some(tail.entry_hash.clone()),
            live_count: 100,
            archive_exists: false,
        };
        match evaluate_class1_coherence(&probes) {
            CoherenceReport::Verified { tail_rowid, tail_hash, .. } => {
                assert_eq!(tail_rowid, 42);
                assert_eq!(tail_hash, "abcdef1234567890");
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_returns_diverged_on_rowid_mismatch() {
        let ts_a = chrono::Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let ts_b = chrono::Utc.timestamp_opt(1_800_000_100, 0).unwrap();
        let probes = TailProbes {
            by_rowid: Some(TailEntry {
                rowid: 42,
                entry_hash: "aaa".to_string(),
                timestamp: ts_a,
            }),
            by_timestamp: Some(TailEntry {
                rowid: 41, // different rowid — by_rowid says 42, by_timestamp says 41
                entry_hash: "bbb".to_string(),
                timestamp: ts_b,
            }),
            via_latest_hash: Some("aaa".to_string()),
            live_count: 100,
            archive_exists: false,
        };
        match evaluate_class1_coherence(&probes) {
            CoherenceReport::Diverged { detail } => {
                assert!(detail.contains("rowid_mismatch"));
            }
            other => panic!("expected Diverged, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_returns_diverged_on_partial_probes() {
        let ts = chrono::Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let probes = TailProbes {
            by_rowid: Some(TailEntry {
                rowid: 42,
                entry_hash: "aaa".to_string(),
                timestamp: ts,
            }),
            by_timestamp: None, // one probe missing
            via_latest_hash: Some("aaa".to_string()),
            live_count: 100,
            archive_exists: false,
        };
        match evaluate_class1_coherence(&probes) {
            CoherenceReport::Diverged { detail } => {
                assert!(detail.contains("partial_probe_results"));
            }
            other => panic!("expected Diverged, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_returns_diverged_on_hash_mismatch() {
        let ts = chrono::Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let probes = TailProbes {
            by_rowid: Some(TailEntry {
                rowid: 42,
                entry_hash: "aaa".to_string(),
                timestamp: ts,
            }),
            by_timestamp: Some(TailEntry {
                rowid: 42,
                entry_hash: "aaa".to_string(),
                timestamp: ts,
            }),
            via_latest_hash: Some("DIFFERENT".to_string()), // hash mismatch
            live_count: 100,
            archive_exists: false,
        };
        match evaluate_class1_coherence(&probes) {
            CoherenceReport::Diverged { detail } => {
                assert!(detail.contains("hash_ac_mismatch"));
            }
            other => panic!("expected Diverged, got {:?}", other),
        }
    }
}

