//! Cartographer — background task that materializes the ontology from
//! the receipt chain.
//!
//! Per `docs/design/CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md` §Section 3.
//!
//! ## P3 scope (this file)
//!
//! - Startup: open `ontology.db`, catchup from `last_processed_sequence`
//! - Per-receipt processing pipeline:
//!   - Project `AuditEntry` → `BoundaryInput`
//!   - Load current active trajectory from ontology (or None on cold start)
//!   - Evaluate boundary via `zp_ontology::evaluate_boundary`
//!   - On `NewTrajectory`: create Trajectory row, link receipt, advance HWM
//!   - On `ContinueTrajectory`: update trajectory's last_active, link receipt
//! - Notifier hook (`AppendNotifier`) pushing rowids into a bounded tokio channel
//! - Steady-state loop consuming the channel
//! - Backpressure: bounded channel with catchup-mode fallback
//!
//! ## Deferred to P3.1+
//!
//! - Cartographer's own receipt emission (`ontology:cartographer:startup`,
//!   `ontology:trajectory:created`, etc.) — requires signing-key derivation
//!   integrated with sovereignty loader; separate arc.
//! - `multi_conversation_history` tracking (stubbed to `false` in v1;
//!   defer to P4 with per-trajectory conversation-id set persistence).
//! - Dormant → resumption matching (P4).
//! - Object CREATE/UPDATE for sub-objects (Decision, Insight, Artifact,
//!   Friction) — currently only Trajectory materialization is wired.
//! - Graceful-shutdown ceremony beyond channel-drain (P3.2).
//! - Operator-correction receipt consumption (P6).

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use zp_audit::{AppendNotifier, AuditStore};
use zp_core::{ActorId, AuditAction, AuditEntry};
use zp_ontology::boundary::extract_event_prefix;
use zp_ontology::{
    canonicalize_boundary_signals, derive_trajectory_id, evaluate_boundary, BoundaryConfig,
    BoundaryDecision, BoundaryInput, OntologyStore, Trajectory, TrajectoryContext,
    TrajectoryStatus,
};

// ── Config ─────────────────────────────────────────────────────────────────

/// Cartographer runtime configuration.
pub struct CartographerConfig {
    pub enabled: bool,
    /// Path to the ontology.db file. Defaults to `<data_dir>/ontology.db`.
    pub ontology_db_path: PathBuf,
    /// Boundary detection thresholds and tunables.
    pub boundary_config: BoundaryConfig,
    /// Bounded channel capacity for notifier → task communication.
    /// Default 1000. Overflow triggers catchup-mode fallback.
    pub channel_capacity: usize,
    /// Batch size for chain catchup fetches. Default 500.
    pub catchup_batch_size: usize,
}

impl Default for CartographerConfig {
    fn default() -> Self {
        CartographerConfig {
            enabled: false,
            ontology_db_path: PathBuf::from("ontology.db"),
            boundary_config: BoundaryConfig::default(),
            channel_capacity: 1000,
            catchup_batch_size: 500,
        }
    }
}

// ── Notifier ───────────────────────────────────────────────────────────────

/// Notifier implementing `AppendNotifier` that pushes sealed-entry rowids
/// into the Cartographer's processing channel.
///
/// Non-blocking per the `AppendNotifier` contract — uses `try_send` and drops
/// on overflow (triggering catchup-mode fallback on the consumer side).
pub struct CartographerNotifier {
    tx: mpsc::Sender<i64>,
}

impl CartographerNotifier {
    pub fn new(tx: mpsc::Sender<i64>) -> Self {
        CartographerNotifier { tx }
    }
}

impl AppendNotifier for CartographerNotifier {
    fn notify(&self, _entry: &AuditEntry, sequence: i64) {
        // try_send prevents blocking the append path. On full channel we drop
        // the notification; consumer detects gap via last_processed_sequence
        // and enters catchup mode.
        if self.tx.try_send(sequence).is_err() {
            debug!(
                sequence,
                "Cartographer notifier channel full — signal dropped; catchup will recover"
            );
        }
    }
}

/// The one place the ontology database path is computed.
///
/// It exists because the Cartographer and the Regent each derived it
/// independently and derived it differently. The Cartographer used
/// `config.data_dir`; the Regent used the argument `spawn_regent` calls
/// `data_dir`, which `lib.rs` populates with `config.home_dir`. On this
/// machine that is `~/ZeroPoint` against `~/ZeroPoint/data`, so the producer
/// wrote one file and the consumer opened another, empty one — and neither
/// logged anything wrong, because opening a fresh ontology store is a normal
/// thing to succeed at.
///
/// P8: one canonical path per substrate concern. Two call sites deriving the
/// same path from different fields is that principle being violated in the
/// most literal sense available.
pub fn ontology_db_path(data_dir: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(data_dir).join("ontology.db")
}

// ── Task ───────────────────────────────────────────────────────────────────

/// Spawn the Cartographer background task.
///
/// The task:
/// 1. Opens the ontology store, migrates schema
/// 2. Catches up from `last_processed_sequence` by paging through chain
/// 3. Enters steady-state loop consuming from the notifier channel
///
/// Returns a `CartographerNotifier` the caller must install via
/// `AuditStore::set_notifier`. If `config.enabled` is false, returns None.
pub fn spawn_cartographer_task(
    config: CartographerConfig,
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
) -> Option<Arc<CartographerNotifier>> {
    if !config.enabled {
        debug!("Cartographer disabled — task not spawned");
        return None;
    }

    let (tx, mut rx) = mpsc::channel::<i64>(config.channel_capacity);
    let notifier = Arc::new(CartographerNotifier::new(tx));

    tokio::spawn(async move {
        // ── Startup: open ontology store ──────────────────────────────────
        let ontology = match OntologyStore::open(&config.ontology_db_path) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    path = %config.ontology_db_path.display(),
                    error = %e,
                    "Cartographer failed to open ontology store — task exiting"
                );
                return;
            }
        };

        let starting_hwm = ontology
            .last_processed_sequence()
            .unwrap_or(None)
            .unwrap_or(0);
        info!(
            last_processed_sequence = starting_hwm,
            "Cartographer starting"
        );

        // ── Catchup: page through chain from HWM ──────────────────────────
        if let Err(e) = run_catchup(
            &ontology,
            &audit_store,
            starting_hwm,
            &config.boundary_config,
            config.catchup_batch_size,
        )
        .await
        {
            error!(error = %e, "Cartographer catchup failed — task exiting");
            return;
        }

        // ── Steady state: consume notifier channel ────────────────────────
        info!("Cartographer entering steady-state loop");
        while let Some(sequence) = rx.recv().await {
            let expected_hwm = ontology
                .last_processed_sequence()
                .unwrap_or(None)
                .unwrap_or(0);
            if sequence <= expected_hwm {
                // Already processed (catchup covered it) — skip.
                continue;
            }
            if sequence > expected_hwm + 1 {
                // Gap: notifier dropped one or more signals. Trigger catchup.
                warn!(
                    expected = expected_hwm + 1,
                    got = sequence,
                    "Cartographer detected sequence gap — entering catchup"
                );
                if let Err(e) = run_catchup(
                    &ontology,
                    &audit_store,
                    expected_hwm,
                    &config.boundary_config,
                    config.catchup_batch_size,
                )
                .await
                {
                    error!(error = %e, "Cartographer gap-catchup failed — continuing");
                }
                continue;
            }
            // Normal path: process this receipt.
            if let Err(e) =
                process_one_receipt(&ontology, &audit_store, sequence, &config.boundary_config)
                    .await
            {
                error!(sequence, error = %e, "Cartographer per-receipt processing failed");
            }
        }

        info!("Cartographer channel closed — task exiting");
    });

    Some(notifier)
}

// ── Catchup ────────────────────────────────────────────────────────────────

async fn run_catchup(
    ontology: &OntologyStore,
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    starting_after: i64,
    boundary_config: &BoundaryConfig,
    batch_size: usize,
) -> Result<(), String> {
    let mut cursor = starting_after;
    let mut total_processed = 0usize;

    loop {
        // Fetch a batch of receipts after cursor.
        let batch: Vec<(i64, AuditEntry)> = {
            let guard = audit_store.lock().map_err(|e| format!("audit lock: {e}"))?;
            guard
                .export_entries_after_rowid(cursor, batch_size)
                .map_err(|e| format!("export_entries_after_rowid: {e}"))?
        };

        if batch.is_empty() {
            break;
        }

        for (rowid, entry) in batch {
            if let Err(e) = process_entry(ontology, &entry, rowid, boundary_config) {
                error!(rowid, error = %e, "Cartographer catchup: per-entry failure");
                // Continue processing rest of batch; failed entry stays
                // unprocessed but subsequent entries advance the HWM (which
                // will look like the failed one was processed). Acceptable
                // for P3 — P3.2 could tighten to fail-fast.
            }
            cursor = rowid;
            total_processed += 1;
        }
    }

    if total_processed > 0 {
        info!(count = total_processed, "Cartographer catchup complete");
    }
    Ok(())
}

async fn process_one_receipt(
    ontology: &OntologyStore,
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    sequence: i64,
    boundary_config: &BoundaryConfig,
) -> Result<(), String> {
    // Fetch the specific entry by re-using export_entries_after_rowid
    // with a narrow window. Not ideal — could add a get_by_rowid, but for
    // P3 v1 this works.
    let batch = {
        let guard = audit_store.lock().map_err(|e| format!("audit lock: {e}"))?;
        guard
            .export_entries_after_rowid(sequence - 1, 1)
            .map_err(|e| format!("export_entries_after_rowid: {e}"))?
    };

    let (rowid, entry) = match batch.into_iter().next() {
        Some(pair) => pair,
        None => {
            debug!(sequence, "Cartographer: no entry at requested sequence");
            return Ok(());
        }
    };

    process_entry(ontology, &entry, rowid, boundary_config)
}

// ── Per-entry processing ───────────────────────────────────────────────────

fn process_entry(
    ontology: &OntologyStore,
    entry: &AuditEntry,
    rowid: i64,
    boundary_config: &BoundaryConfig,
) -> Result<(), String> {
    let input = project_to_boundary_input(entry);
    let current = ontology
        .most_recently_active_trajectory()
        .map_err(|e| format!("most_recently_active_trajectory: {e}"))?;

    match current {
        None => {
            // Cold start: no trajectory exists yet. Always create new with
            // a synthetic "cold_start" signals marker so the derived ID is
            // stable across rebuilds — same first-receipt always produces
            // the same first-trajectory ID.
            let cold_start_signals = r#"{"conversation":0.0000,"time_gap":0.0000,"explicit_marker":null,"cold_start":true}"#;
            create_new_trajectory(ontology, &input, entry, 1.0, cold_start_signals)?;
        }
        Some(traj) => {
            let ctx = trajectory_context_from(&traj);
            let decision = evaluate_boundary(&input, &ctx, boundary_config);
            match decision {
                BoundaryDecision::NewTrajectory {
                    confidence,
                    signals,
                    reason: _,
                } => {
                    debug!(
                        prior_traj = %traj.id.to_hex(),
                        new_confidence = confidence,
                        "Cartographer: boundary detected"
                    );
                    let signals_json = canonicalize_boundary_signals(&signals);
                    create_new_trajectory(ontology, &input, entry, confidence, &signals_json)?;
                }
                BoundaryDecision::ContinueTrajectory {
                    confidence: _,
                    signals: _,
                } => {
                    // Extend the current trajectory: update last_active,
                    // append receipt_refs, update boundary-detection state,
                    // link receipt row.
                    let mut updated = traj.clone();
                    updated.last_active = input.timestamp;
                    updated.receipt_refs.push(entry.id.clone());

                    // P4 boundary-detection state update — records this
                    // receipt's conversation_id and event prefix so future
                    // S1/S4 evaluations have accurate context.
                    let event_prefix = input.event.as_deref().map(extract_event_prefix);
                    updated.record_receipt_context(
                        input.conversation_id.clone(),
                        event_prefix.as_deref(),
                    );

                    ontology
                        .update_object(&updated)
                        .map_err(|e| format!("update trajectory: {e}"))?;
                    ontology
                        .link_receipt(&updated.id, &entry.id, Some("evidence"))
                        .map_err(|e| format!("link_receipt: {e}"))?;
                }
            }
        }
    }

    // Advance high-water mark. Idempotent — replaying same rowid is fine.
    ontology
        .set_last_processed_sequence(rowid)
        .map_err(|e| format!("set_last_processed_sequence: {e}"))?;
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn project_to_boundary_input(entry: &AuditEntry) -> BoundaryInput {
    let event = match &entry.action {
        AuditAction::SystemEvent { event } => Some(event.clone()),
        _ => None,
    };
    BoundaryInput {
        conversation_id: entry.conversation_id.clone(),
        timestamp: entry.timestamp,
        event,
    }
}

/// Create a new Trajectory for the current receipt, insert it, and link
/// the receipt as origin. Used by both the cold-start branch (no prior
/// trajectory exists) and the NewTrajectory decision branch (boundary
/// detected against prior trajectory).
///
/// On cold-start, `signals_json` should represent a synthetic "cold_start"
/// marker so the derived ID is stable across rebuilds; on boundary
/// detection, callers pass the actual canonicalized signals JSON.
fn create_new_trajectory(
    ontology: &OntologyStore,
    input: &BoundaryInput,
    entry: &AuditEntry,
    boundary_confidence: f32,
    signals_json: &str,
) -> Result<(), String> {
    let id = derive_trajectory_id(&entry.entry_hash, signals_json);

    // Initialize boundary-detection state with this originating receipt's
    // conversation_id + event prefix. Subsequent receipts assigned to this
    // trajectory via ContinueTrajectory will accumulate more state via
    // Trajectory::record_receipt_context.
    let event_prefix = input.event.as_deref().map(extract_event_prefix);
    let mut event_prefix_counts = std::collections::BTreeMap::new();
    if let Some(ref p) = event_prefix {
        event_prefix_counts.insert(p.clone(), 1u32);
    }

    let traj = Trajectory {
        id,
        title: derive_trajectory_title(input),
        status: TrajectoryStatus::Active,
        boundary_confidence,
        parent_id: None,
        tags: vec![],
        created_at: input.timestamp,
        last_active: input.timestamp,
        receipt_refs: vec![entry.id.clone()],
        dominant_conversation_id: input.conversation_id.clone(),
        seen_conversation_ids: vec![input.conversation_id.clone()],
        event_prefix_counts,
    };
    ontology
        .insert_object(&traj)
        .map_err(|e| format!("insert new trajectory: {e}"))?;
    ontology
        .link_receipt(&traj.id, &entry.id, Some("origin"))
        .map_err(|e| format!("link_receipt: {e}"))?;
    Ok(())
}

fn trajectory_context_from(traj: &Trajectory) -> TrajectoryContext {
    // P4: real per-trajectory state carried by Trajectory struct.
    // dominant_conversation_id and event-prefix distribution are
    // populated on every ContinueTrajectory update via
    // Trajectory::record_receipt_context.
    TrajectoryContext {
        dominant_conversation_id: traj.dominant_conversation_id.clone(),
        multi_conversation_history: traj.has_multi_conversation_history(),
        last_active: traj.last_active,
        receipt_count: traj.receipt_refs.len() as u32,
        dominant_event_prefix: traj.dominant_event_prefix(),
        top_prefixes: traj.top_event_prefixes(3),
    }
}

fn derive_trajectory_title(input: &BoundaryInput) -> String {
    // v1: derive a generic title from the originating receipt's event prefix.
    // P3.2+ will use more sophisticated derivation once dominant-domain
    // tracking exists.
    match &input.event {
        Some(e) => {
            let prefix = e.split(':').take(2).collect::<Vec<_>>().join(":");
            format!("Trajectory: {prefix}")
        }
        None => "Trajectory: (untitled)".to_string(),
    }
}

// ── ActorId placeholder (silence unused-import warning if any) ─────────────
#[allow(dead_code)]
fn _actor_id_marker(_: ActorId) {}
