//! Loop runner — drives the Regent's cognitive loop on a timer.
//!
//! Analogous to the officer sweep runner: wakes the Regent periodically,
//! assembles context, runs one cognitive cycle, and handles the resulting
//! Intent. Also accepts operator input injected from cockpit surfaces.
//!
//! The loop runner is also the Regent's system steward — it tracks idle
//! time, manages background tasks (model evaluation sweeps, future
//! maintenance), cancels background work when the operator needs
//! attention, and assembles SystemAwareness for each cognitive cycle.
//! The Regent actively maintains system harmony based on this awareness.

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, info, warn};

use serde::{Deserialize, Serialize};
use serde_json;

use crate::awareness::{BackgroundTask, SystemMonitor};
use crate::context::{
    BackgroundTaskKind, CockpitSource, DelegationSummary, OperatorInput,
    ToolResult, WorkArc,
};
use crate::error::RegentError;
use crate::evaluation;
use crate::events::{CognitiveEvent, EventTx, Phase};
use crate::inference::InferenceBackend;
use crate::intent::Intent;
use crate::regent::Regent;

use zp_audit::AuditStore;
use zp_officers::finding::Finding;
use zp_officers::officer::ChainReader;

/// What happened when an intent was executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentOutcome {
    /// Tool ran successfully.
    ToolCompleted {
        tool: String,
        output: serde_json::Value,
    },
    /// Gate denied the tool call.
    ToolDenied {
        tool: String,
        reason: String,
    },
    /// Response was delivered to a cockpit surface.
    Delivered,
    /// Observation recorded (no visible effect).
    Observed,
    /// Approval request sent to operator.
    ApprovalRequested,
}

/// What a single cognitive cycle produced — used by the arc loop
/// in `start_loop` to decide whether to run another cycle.
enum CycleOutcome {
    /// The Regent is done — deliver this response to the operator.
    Done(String),
    /// The Regent wants to continue — re-enter with accumulated state.
    Continue {
        progress: String,
        tool_results: Vec<ToolResult>,
    },
}

/// Message type for the Regent's input channel.
pub enum RegentMessage {
    /// Operator input from a cockpit surface.
    OperatorInput {
        content: String,
        source: CockpitSource,
        /// If present, the loop sends the Regent's response text back.
        reply_tx: Option<oneshot::Sender<String>>,
    },

    /// Officer findings from a sweep cycle.
    OfficerFindings(Vec<Finding>),

    /// Shutdown signal.
    Shutdown,
}

/// Handle to send messages to the running Regent loop.
#[derive(Clone)]
pub struct RegentHandle {
    tx: mpsc::Sender<RegentMessage>,
}

impl RegentHandle {
    /// Send operator input to the Regent (fire-and-forget).
    pub async fn send_input(
        &self,
        content: String,
        source: CockpitSource,
    ) -> Result<(), RegentError> {
        self.tx
            .send(RegentMessage::OperatorInput {
                content,
                source,
                reply_tx: None,
            })
            .await
            .map_err(|_| RegentError::Inference("regent loop not running".to_string()))
    }

    /// Send operator input and wait for the Regent's response.
    pub async fn send_input_and_wait(
        &self,
        content: String,
        source: CockpitSource,
    ) -> Result<String, RegentError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(RegentMessage::OperatorInput {
                content,
                source,
                reply_tx: Some(tx),
            })
            .await
            .map_err(|_| RegentError::Inference("regent loop not running".to_string()))?;

        rx.await
            .map_err(|_| RegentError::Inference("regent loop dropped reply channel".to_string()))
    }

    /// Forward officer findings to the Regent.
    pub async fn send_findings(&self, findings: Vec<Finding>) -> Result<(), RegentError> {
        self.tx
            .send(RegentMessage::OfficerFindings(findings))
            .await
            .map_err(|_| RegentError::Inference("regent loop not running".to_string()))
    }

    /// Request graceful shutdown.
    pub async fn shutdown(&self) -> Result<(), RegentError> {
        self.tx
            .send(RegentMessage::Shutdown)
            .await
            .map_err(|_| RegentError::Inference("regent loop not running".to_string()))
    }
}

/// Callback for intent execution. The caller (zp-server) provides this
/// to handle intents — emit receipts, deliver responses, dispatch sub-agents.
#[async_trait::async_trait]
pub trait IntentExecutor: Send + Sync {
    /// Execute an intent and return what happened.
    async fn execute(&self, intent: &Intent) -> Result<IntentOutcome, RegentError>;
}

/// Maximum tool-call turns per cognitive cycle.
/// Allows execute-then-narrate: the Regent acts, sees the result,
/// and composes a response — all within one cycle. 3 turns covers
/// act → narrate with one spare. Prevents runaway loops.
const MAX_TOOL_TURNS: u32 = 3;

/// Maximum cognitive cycles per work arc.
/// The Regent can chain up to this many cycles via Continue intents before
/// the loop forces a stop. 10 covers any realistic remediation sequence
/// while preventing runaway. Each cycle allows MAX_TOOL_TURNS tool calls,
/// so the theoretical max is 10 × 3 = 30 tool invocations per arc.
const MAX_ARC_CYCLES: u32 = 10;

/// Default idle threshold before the Regent considers background maintenance.
/// The Regent won't start heavy work (model evaluation) until the operator
/// has been idle for at least this long.
const IDLE_THRESHOLD_SECS: u64 = 300; // 5 minutes

/// Start the Regent's cognitive loop. Returns a handle for sending messages.
///
/// The loop runs until shutdown is requested. It wakes on:
/// 1. Operator input (immediate cycle, cancels background tasks).
/// 2. Officer findings (immediate cycle if urgent).
/// 3. Timer (autonomous cycle — system awareness + harmony maintenance).
///
/// `delegations` — the tools granted to the Regent at startup. Passed into
/// every cognitive cycle so the Regent's prompt includes the tool section.
/// Eventually this will be read from the chain; for now it's static.
pub fn start_loop(
    regent: Arc<Mutex<Regent>>,
    executor: Arc<dyn IntentExecutor>,
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
    interval_secs: u64,
    cognitive_event_tx: Option<EventTx>,
    inference: Arc<InferenceBackend>,
    monitor: Arc<Mutex<SystemMonitor>>,
    operator_name: String,
    genesis_prefix: String,
    delegations: Vec<DelegationSummary>,
) -> RegentHandle {
    let (tx, mut rx) = mpsc::channel::<RegentMessage>(64);

    tokio::spawn(async move {
        let mut latest_findings: Vec<Finding> = Vec::new();
        let interval = if interval_secs > 0 {
            Some(tokio::time::interval(std::time::Duration::from_secs(interval_secs)))
        } else {
            None
        };

        let mut interval = interval;

        info!("regent cognitive loop started (system awareness active)");

        // Mirror: the Regent's prior response, carried across cycles.
        // Updated after each cycle completes; fed into the next perceive()
        // so she can see what she said and self-evaluate.
        let mut last_prior_response: Option<crate::context::PriorResponse> = None;

        loop {
            let message = if let Some(ref mut interval) = interval {
                tokio::select! {
                    msg = rx.recv() => msg,
                    _ = interval.tick() => {
                        // Autonomous wake — check system state, maybe do maintenance.
                        Some(RegentMessage::OperatorInput {
                            content: String::new(),
                            source: CockpitSource::Autonomous,
                            reply_tx: None,
                        })
                    }
                }
            } else {
                rx.recv().await
            };

            let message = match message {
                Some(m) => m,
                None => break, // Channel closed.
            };

            match message {
                RegentMessage::Shutdown => {
                    info!("regent loop shutting down");
                    // Cancel all background tasks before exit.
                    monitor.lock().await.cancel_all();
                    break;
                }

                RegentMessage::OfficerFindings(findings) => {
                    latest_findings = findings;
                    let has_critical = latest_findings.iter().any(|f| {
                        matches!(
                            f.severity,
                            zp_officers::finding::Severity::Critical
                        )
                    });
                    if !has_critical {
                        continue;
                    }
                    debug!("critical finding — triggering immediate cycle");
                    // Fall through to run_cycle below.
                }

                RegentMessage::OperatorInput { content, source, reply_tx } => {
                    let is_operator = !content.is_empty();
                    // Capture operator question for the mirror before content is moved.
                    let operator_question_for_mirror = if is_operator {
                        Some(content.clone())
                    } else {
                        None
                    };

                    if is_operator {
                        // Operator is active — cancel background tasks, reset idle timer.
                        monitor.lock().await.operator_active();
                    }

                    let operator_input = if content.is_empty() {
                        None
                    } else {
                        Some(OperatorInput {
                            content,
                            received_at: chrono::Utc::now(),
                            source,
                        })
                    };

                    // ── Arc loop: run cycles until Done or budget exhausted ──
                    let mut arc: Option<WorkArc> = None;
                    let mut arc_input = operator_input;
                    // Mirror: carry the prior response into the first cycle.
                    // Updated after each cycle so the Regent always sees her
                    // most recent output in the next perceive().
                    let mut cycle_prior = last_prior_response.take();
                    let response = loop {
                        let awareness = monitor.lock().await.snapshot().await;

                        let outcome = run_cycle(
                            &regent,
                            &executor,
                            &audit_store,
                            &latest_findings,
                            arc_input.take(),
                            &cognitive_event_tx,
                            Some(awareness),
                            &delegations,
                            arc.clone(),
                            cycle_prior.take(),
                        ).await;

                        match outcome {
                            CycleOutcome::Done(response) => {
                                if let Some(ref a) = arc {
                                    info!(
                                        cycles = a.cycles_completed,
                                        tools = a.tool_history.len(),
                                        "work arc completed"
                                    );
                                    emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcEnd, 0)
                                        .with_detail(format!(
                                            "cycles={} tools={}",
                                            a.cycles_completed, a.tool_history.len()
                                        )));
                                }
                                break response;
                            }
                            CycleOutcome::Continue { progress, tool_results } => {
                                let is_new_arc = arc.is_none();
                                let current = arc.get_or_insert_with(|| WorkArc {
                                    progress: String::new(),
                                    cycles_completed: 0,
                                    max_cycles: MAX_ARC_CYCLES,
                                    tool_history: Vec::new(),
                                });
                                current.progress = progress.clone();
                                current.cycles_completed += 1;
                                current.tool_history = tool_results;

                                if is_new_arc {
                                    emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcStart, 0)
                                        .with_detail(progress.clone()));
                                }

                                info!(
                                    cycle = current.cycles_completed,
                                    max = MAX_ARC_CYCLES,
                                    progress = progress.as_str(),
                                    "work arc continuing"
                                );

                                emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcProgress, 0)
                                    .with_detail(format!(
                                        "{}/{}: {}",
                                        current.cycles_completed, MAX_ARC_CYCLES, progress
                                    )));

                                // Budget check.
                                if current.cycles_completed >= MAX_ARC_CYCLES {
                                    warn!(
                                        cycles = current.cycles_completed,
                                        "work arc hit budget — forcing stop"
                                    );
                                    break format!(
                                        "Work arc stopped after {} cycles (budget). Last: {}",
                                        current.cycles_completed, progress
                                    );
                                }

                                // Preemption check: if operator sent new input while
                                // the arc was running, break the arc to handle it.
                                // Non-blocking check — don't await.
                                if let Ok(msg) = rx.try_recv() {
                                    match msg {
                                        RegentMessage::Shutdown => {
                                            info!("regent loop shutting down mid-arc");
                                            monitor.lock().await.cancel_all();
                                            // Can't break outer loop from here;
                                            // return and let outer loop handle next recv.
                                            break format!(
                                                "Work arc interrupted by shutdown after {} cycles",
                                                current.cycles_completed
                                            );
                                        }
                                        RegentMessage::OperatorInput { .. } => {
                                            info!(
                                                cycle = current.cycles_completed,
                                                "operator input preempted work arc"
                                            );
                                            // TODO: re-queue this message so the outer
                                            // loop processes it next. For now, break arc.
                                            break format!(
                                                "Work arc preempted by operator after {} cycles. Last: {}",
                                                current.cycles_completed, progress
                                            );
                                        }
                                        RegentMessage::OfficerFindings(f) => {
                                            latest_findings = f;
                                            // Continue the arc — findings are context,
                                            // not preemption.
                                        }
                                    }
                                }

                                // Next cycle — no operator input, arc state carries forward.
                                continue;
                            }
                        }
                    };

                    // Mirror: capture the Regent's response for the next cycle.
                    last_prior_response = if !response.starts_with("error:") {
                        let model = {
                            let rg = regent.lock().await;
                            rg.model_label()
                        };
                        Some(crate::context::PriorResponse {
                            operator_question: operator_question_for_mirror,
                            response_content: response.clone(),
                            model_used: model,
                        })
                    } else {
                        None
                    };

                    if let Some(tx) = reply_tx {
                        let _ = tx.send(response);
                    }

                    // ── Harmony: consider background maintenance on idle ──
                    if !is_operator {
                        maybe_start_background_work(
                            &monitor,
                            &inference,
                            &audit_store,
                            &operator_name,
                            &genesis_prefix,
                        ).await;
                    }

                    continue;
                }
            }

            // Critical finding path — run cycle with no operator input.
            // Critical findings can trigger arcs too (e.g., multi-step remediation).
            let mut arc: Option<WorkArc> = None;
            loop {
                let awareness = monitor.lock().await.snapshot().await;
                let outcome = run_cycle(
                    &regent,
                    &executor,
                    &audit_store,
                    &latest_findings,
                    None,
                    &cognitive_event_tx,
                    Some(awareness),
                    &delegations,
                    arc.clone(),
                    None, // No mirror for autonomous cycles — no operator question to reflect on.
                ).await;

                match outcome {
                    CycleOutcome::Done(_) => {
                        if let Some(ref a) = arc {
                            emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcEnd, 0)
                                .with_detail(format!(
                                    "cycles={} tools={}",
                                    a.cycles_completed, a.tool_history.len()
                                )));
                        }
                        break;
                    }
                    CycleOutcome::Continue { progress, tool_results } => {
                        let is_new_arc = arc.is_none();
                        let current = arc.get_or_insert_with(|| WorkArc {
                            progress: String::new(),
                            cycles_completed: 0,
                            max_cycles: MAX_ARC_CYCLES,
                            tool_history: Vec::new(),
                        });
                        current.progress = progress.clone();
                        current.cycles_completed += 1;
                        current.tool_history = tool_results;

                        if is_new_arc {
                            emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcStart, 0)
                                .with_detail(progress.clone()));
                        }
                        emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcProgress, 0)
                            .with_detail(format!(
                                "{}/{}: {}",
                                current.cycles_completed, MAX_ARC_CYCLES, progress
                            )));

                        if current.cycles_completed >= MAX_ARC_CYCLES {
                            warn!("critical finding arc hit budget");
                            emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcEnd, 0)
                                .with_detail("budget_exhausted"));
                            break;
                        }
                    }
                }
            }
        }

        // Flush memory on shutdown.
        let mut regent = regent.lock().await;
        if let Err(e) = regent.flush_memory() {
            warn!("memory flush on shutdown failed: {}", e);
        }
        info!("regent loop exited");
    });

    RegentHandle { tx }
}

/// Check if conditions are right for background maintenance work.
///
/// The Regent considers:
/// - Idle time (operator hasn't interacted for IDLE_THRESHOLD_SECS)
/// - No active background task of the same kind already running
/// - Memory pressure isn't critical (don't pile on)
///
/// This is the Regent's harmony decision — she actively chooses when
/// background work fits the system's current state.
async fn maybe_start_background_work(
    monitor: &Arc<Mutex<SystemMonitor>>,
    inference: &Arc<InferenceBackend>,
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    operator_name: &str,
    genesis_prefix: &str,
) {
    let mut mon = monitor.lock().await;

    // Not idle long enough — operator might come back.
    if mon.idle_secs() < IDLE_THRESHOLD_SECS {
        return;
    }

    // Already running a model evaluation — don't pile on.
    if mon.has_active_task(&BackgroundTaskKind::ModelEvaluation) {
        return;
    }

    // Check memory pressure — don't start heavy work under pressure.
    // (Quick check without a full snapshot — just read memory.)
    let awareness = mon.snapshot().await;
    if awareness.memory.level == crate::context::PressureLevel::Critical {
        debug!("skipping background evaluation — memory pressure critical");
        return;
    }

    // ── Spawn model evaluation sweep ──────────────────────────────
    let cancel_flag = mon.new_cancel_flag();
    let cancel_clone = cancel_flag.clone();
    let inference_clone = inference.clone();
    let audit_clone = audit_store.clone();
    let operator = operator_name.to_string();
    let prefix = genesis_prefix.to_string();

    info!("regent: system idle, starting background model evaluation sweep");

    let handle = tokio::spawn(async move {
        let emit_receipt: evaluation::ReceiptEmitter = {
            let store = audit_clone.clone();
            Box::new(move |report: &evaluation::EvaluationReport| {
                let entry = zp_audit::UnsealedEntry {
                    actor: zp_core::ActorId::System("regent".to_string()),
                    action: zp_core::AuditAction::SystemEvent {
                        event: format!(
                            "regent:model_evaluated:{} passed={}/{} latency={}ms",
                            report.model, report.passed, report.total_tests,
                            report.total_latency_ms
                        ),
                    },
                    conversation_id: zp_core::ConversationId(
                        uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap()
                    ),
                    policy_decision: zp_core::PolicyDecision::Allow {
                        conditions: Vec::new(),
                    },
                    policy_module: "regent-evaluation".to_string(),
                    receipt: None,
                };

                if let Ok(mut s) = store.lock() {
                    if let Err(e) = s.append(entry) {
                        warn!("evaluation receipt emission failed: {}", e);
                    }
                }
            })
        };

        let result = evaluation::run_evaluation_sweep(
            inference_clone,
            operator,
            prefix,
            cancel_clone,
            emit_receipt,
        ).await;

        if result.cancelled {
            info!(
                evaluated = result.models_evaluated,
                total = result.total_models_discovered,
                "evaluation sweep cancelled — partial results on chain"
            );
        } else {
            info!(
                evaluated = result.models_evaluated,
                total_ms = result.total_latency_ms,
                "evaluation sweep completed — all results on chain"
            );
        }
    });

    mon.register_task(BackgroundTask {
        kind: BackgroundTaskKind::ModelEvaluation,
        started_at: chrono::Utc::now(),
        cancel: cancel_flag,
        join_handle: handle,
    });
}

/// Run one cognitive cycle with multi-turn tool calling.
///
/// Lock ordering is load-bearing:
/// - `perceive()` needs `AuditStore` (std::sync::Mutex) via ChainReader.
/// - `reason()` is async (inference call) — cannot hold std::sync::MutexGuard
///   across an await or the future won't be Send.
/// - `executor.execute()` needs `AuditStore` for gate evaluation and receipts.
///
/// Solution: lock regent (tokio::Mutex, Send-safe), then lock audit_store
/// (std::sync::Mutex) only for the sync `perceive()` call, drop it, then
/// call async `reason()` and `execute()` without holding the std guard.
/// Returns a CycleOutcome: Done with response text, or Continue with
/// accumulated tool results for the next cycle in a work arc.
/// Helper: emit a cognitive event if a sender is wired.
fn emit(tx: &Option<EventTx>, event: CognitiveEvent) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
    }
}

async fn run_cycle(
    regent: &Arc<Mutex<Regent>>,
    executor: &Arc<dyn IntentExecutor>,
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    findings: &[Finding],
    initial_input: Option<OperatorInput>,
    event_tx: &Option<EventTx>,
    system_awareness: Option<crate::context::SystemAwareness>,
    delegations: &[DelegationSummary],
    work_arc: Option<WorkArc>,
    prior_response: Option<crate::context::PriorResponse>,
) -> CycleOutcome {
    let mut current_input = initial_input;
    // If resuming a work arc, seed tool_results with the arc's history
    // so the Regent sees what she's already done across prior cycles.
    let mut tool_results: Vec<ToolResult> = work_arc
        .as_ref()
        .map(|arc| arc.tool_history.clone())
        .unwrap_or_default();

    let cycle_t0 = std::time::Instant::now();
    emit(event_tx, CognitiveEvent::new(Phase::CycleStart, 0)
        .with_detail(format!("findings={} arc={}", findings.len(), work_arc.is_some())));

    for turn in 0..MAX_TOOL_TURNS {
        // Lock the regent first (async-safe tokio Mutex).
        let mut regent_guard = regent.lock().await;

        // ── Perceive ─────────────────────────────────────────────
        let perceive_t0 = std::time::Instant::now();
        let context = {
            let store = match audit_store.lock() {
                Ok(s) => s,
                Err(e) => {
                    warn!("regent cycle: audit store lock poisoned: {}", e);
                    emit(event_tx, CognitiveEvent::new(Phase::Error, cycle_t0.elapsed().as_millis() as u64)
                        .with_detail("audit store lock poisoned"));
                    return CycleOutcome::Done(format!("error: audit store lock poisoned: {}", e));
                }
            };
            let chain_reader = ChainReader::new(&*store);
            match regent_guard.perceive(
                &chain_reader,
                findings,
                current_input.take(),
                &delegations,
                system_awareness.clone(),
                tool_results.clone(),
                work_arc.clone(),
                // Mirror: only show prior response on first turn of the cycle.
                // Subsequent turns (tool dispatch → narration) don't need it.
                if turn == 0 { prior_response.clone() } else { None },
            ) {
                Ok(ctx) => ctx,
                Err(e) => {
                    warn!("regent perceive failed: {}", e);
                    emit(event_tx, CognitiveEvent::new(Phase::Error, cycle_t0.elapsed().as_millis() as u64)
                        .with_detail(format!("perceive: {}", e)));
                    return CycleOutcome::Done(format!("error: perceive failed: {}", e));
                }
            }
        };
        let perceive_ms = perceive_t0.elapsed().as_millis() as u64;
        emit(event_tx, CognitiveEvent::new(Phase::Perceive, perceive_ms)
            .with_detail(format!(
                "chain={} findings={} delegations={} corrections={} prior_tools={}",
                context.recent_chain.len(),
                context.officer_findings.len(),
                context.active_delegations.len(),
                context.standing_corrections.len(),
                context.tool_results.len(),
            )));
        info!(perceive_ms, turn, "regent perceive completed");

        // ── Composition receipt ──────────────────────────────────
        // Chain-anchor the structural composition of Regent's context so
        // future analysis can verify what she was given to reason with
        // per COGNITIVE-INPUT-PLANE-2026-07.md Step 6. Structural only
        // (hashes, counts) — no content bloat on chain per cycle.
        if let Some(ref summary) = context.composition_summary {
            emit_composition_receipt(&audit_store, summary);
        }

        // ── Reason (inference) ───────────────────────────────────
        let reason_t0 = std::time::Instant::now();
        emit(event_tx, CognitiveEvent::new(Phase::InferenceStart, 0)
            .with_detail(format!("model={} turn={}", regent_guard.model_label(), turn)));

        let intent = match regent_guard.reason(&context).await {
            Ok(i) => i,
            Err(e) => {
                warn!("regent reason failed: {}", e);
                emit(event_tx, CognitiveEvent::new(Phase::Error, cycle_t0.elapsed().as_millis() as u64)
                    .with_detail(format!("reason: {}", e)));
                return CycleOutcome::Done(format!("error: reason failed: {}", e));
            }
        };
        let reason_ms = reason_t0.elapsed().as_millis() as u64;
        emit(event_tx, CognitiveEvent::new(Phase::InferenceEnd, reason_ms)
            .with_detail(format!("intent={}", intent.receipt_event())));
        emit(event_tx, CognitiveEvent::new(Phase::IntentParsed, 0)
            .with_detail(format!("{}", intent.receipt_event())));
        info!(reason_ms, turn, intent = intent.receipt_event(), "regent reason completed");

        // ── Fallback diagnostics ─────────────────────────────────
        // If cloud inference failed and the backend fell back to local
        // Ollama, drain the event and emit a chain receipt. This makes
        // fallback auditable — the Regent can query her own chain for
        // repeated fallbacks and escalate to the operator.
        if let Some(fb) = regent_guard.inference().take_fallback_event() {
            warn!(
                cloud_provider = %fb.cloud_provider,
                cloud_error = %fb.cloud_error,
                fallback_model = %fb.fallback_model,
                "inference fell back to local Ollama — emitting chain receipt"
            );
            let entry = zp_audit::UnsealedEntry {
                actor: zp_core::ActorId::System("regent".to_string()),
                action: zp_core::AuditAction::SystemEvent {
                    event: format!(
                        "regent:inference:fallback provider={} error={} fallback_model={}",
                        fb.cloud_provider,
                        fb.cloud_error,
                        fb.fallback_model,
                    ),
                },
                conversation_id: zp_core::ConversationId(
                    uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap()
                ),
                policy_decision: zp_core::PolicyDecision::Allow {
                    conditions: Vec::new(),
                },
                policy_module: "regent-inference".to_string(),
                receipt: None,
            };
            if let Ok(mut s) = audit_store.lock() {
                if let Err(e) = s.append(entry) {
                    warn!("fallback receipt emission failed: {}", e);
                }
            }
        }

        // Post-cycle memory maintenance.
        if let Err(e) = regent_guard.flush_memory() {
            warn!("memory flush failed: {}", e);
        }

        // Drop regent lock before calling executor (which acquires audit_store).
        drop(regent_guard);

        // ── Enrich browser_use params ────────────────────────────────
        // Small models often emit {"tool":"browser_use"} with no params
        // even when the operator said "navigate to X". Extract the URL
        // from the operator's input and inject it.
        let intent = if let Intent::Execute { tool, params } = &intent {
            if tool == "browser_use"
                && params.as_object().is_some_and(|m| m.is_empty())
            {
                if let Some(ref input) = context.pending_input {
                    const ENRICH_DOMAINS: &[(&str, &str)] = &[
                        ("zeropoint.global", "https://zeropoint.global"),
                        ("zeropointfoundation.org", "https://zeropointfoundation.org"),
                        ("github.com/zeropoint-foundation", "https://github.com/zeropoint-foundation"),
                    ];
                    let lower = input.content.to_lowercase();
                    let mut found = None;
                    for (domain, full_url) in ENRICH_DOMAINS {
                        if lower.contains(domain) {
                            info!(domain, "enriching browser_use params from operator input");
                            found = Some(Intent::Execute {
                                tool: tool.clone(),
                                params: serde_json::json!({
                                    "action": "goto_url",
                                    "url": full_url,
                                }),
                            });
                            break;
                        }
                    }
                    found.unwrap_or(intent)
                } else {
                    intent
                }
            } else {
                intent
            }
        } else {
            intent
        };

        match &intent {
            Intent::Execute { tool, .. } => {
                emit(event_tx, CognitiveEvent::new(Phase::ToolDispatch, 0)
                    .with_detail(format!("{}  turn={}", tool, turn)));
                let tool_t0 = std::time::Instant::now();

                let (response, succeeded) = match executor.execute(&intent).await {
                    Ok(IntentOutcome::ToolCompleted { tool: _, output }) => {
                        let s = serde_json::to_string_pretty(&output)
                            .unwrap_or_else(|_| output.to_string());
                        (s, true)
                    }
                    Ok(IntentOutcome::ToolDenied { tool, reason }) => {
                        (format!("{} denied: {}", tool, reason), false)
                    }
                    Ok(_) => ("completed".to_string(), true),
                    Err(e) => {
                        warn!("tool execution failed: {}", e);
                        (format!("error: tool execution failed: {}", e), false)
                    }
                };
                let tool_ms = tool_t0.elapsed().as_millis() as u64;

                emit(event_tx, CognitiveEvent::new(Phase::ToolComplete, tool_ms)
                    .with_detail(format!("response_len={}", response.len())));

                // Feed result back for the next turn — the Regent will
                // see it and can compose a narration or act again.
                tool_results.push(ToolResult {
                    tool: tool.clone(),
                    output: response,
                    succeeded,
                });

                info!(
                    turn,
                    tool_ms,
                    "tool completed — continuing cycle for narration"
                );
                continue;
            }

            Intent::Continue { progress } => {
                // The Regent wants another cycle. Return Continue with
                // accumulated tool results so the arc loop re-enters.
                let total_ms = cycle_t0.elapsed().as_millis() as u64;
                emit(event_tx, CognitiveEvent::new(Phase::CycleEnd, total_ms)
                    .with_detail(format!("continue: {}", progress)));
                info!(
                    turns = turn + 1,
                    total_ms,
                    progress = progress.as_str(),
                    "regent requesting continue"
                );
                return CycleOutcome::Continue {
                    progress: progress.clone(),
                    tool_results,
                };
            }

            _ => {
                let response = match &intent {
                    Intent::Respond { content, .. } => content.clone(),
                    Intent::Observe { observation } => observation.clone(),
                    Intent::RequestApproval { proposed_action, reason } => {
                        format!("[approval requested] {}: {}", proposed_action, reason)
                    }
                    _ => format!("{:?}", intent.receipt_event()),
                };
                if let Err(e) = executor.execute(&intent).await {
                    warn!("intent execution failed: {}", e);
                }
                let total_ms = cycle_t0.elapsed().as_millis() as u64;

                emit(event_tx, CognitiveEvent::new(Phase::ResponseDelivered, 0)
                    .with_detail(format!("len={}", response.len())));

                // ── Cognitive Self-Observer (P2.2) ──────────────────────
                // Post-emission verification of Regent's response against
                // active standing corrections. Only meaningful for content-
                // bearing intents (Respond / Observe); skip for tool-dispatch
                // envelope strings that aren't operator-facing content.
                if matches!(&intent, Intent::Respond { .. } | Intent::Observe { .. }) {
                    run_cognitive_observer(&audit_store, &response, &context.standing_corrections);
                }

                emit(event_tx, CognitiveEvent::new(Phase::CycleEnd, total_ms)
                    .with_detail(format!(
                        "turns={} perceive={}ms inference={}ms",
                        turn + 1, perceive_ms, reason_ms
                    )));

                info!(
                    turns = turn + 1,
                    total_ms,
                    "regent cycle complete"
                );
                return CycleOutcome::Done(response);
            }
        }
    }

    // Max turns reached — return the last tool result if we have one,
    // otherwise the model kept executing tools without ever narrating.
    let total_ms = cycle_t0.elapsed().as_millis() as u64;
    let fallback = if let Some(last) = tool_results.last() {
        emit(event_tx, CognitiveEvent::new(Phase::CycleEnd, total_ms)
            .with_detail(format!("max_turns_reached tools_executed={}", tool_results.len())));
        info!(
            turns = MAX_TOOL_TURNS,
            tools = tool_results.len(),
            total_ms,
            "regent hit max tool turns — returning last tool output"
        );
        last.output.clone()
    } else {
        emit(event_tx, CognitiveEvent::new(Phase::CycleEnd, total_ms)
            .with_detail("max_tool_turns_reached"));
        warn!(
            turns = MAX_TOOL_TURNS,
            total_ms,
            "regent hit max tool turns, forcing stop"
        );
        "error: max tool turns reached".to_string()
    };
    CycleOutcome::Done(fallback)
}

// ── Composition receipt emission (P2.1) ──────────────────────────────────────

/// Emit a `cognitive:input:composed` chain receipt for a cycle's perception.
///
/// Structural provenance only — matrix version, per-class source hashes, counts.
/// The chain now has verifiable evidence of what Regent was given to reason with
/// at time T, without the chain-bloat cost of storing every prompt.
///
/// Per COGNITIVE-INPUT-PLANE-2026-07.md Step 6.
fn emit_composition_receipt(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    summary: &crate::context::CompositionSummary,
) {
    // Encode summary metadata inline in the event string (existing pattern for
    // chain-anchored regent events — see server::regent::emit_remediation_receipt).
    let event = format!(
        "cognitive:input:composed matrix={} corrections={}/{} findings={}/{} chain={} delegations={} reason={}",
        summary.matrix_version,
        summary.standing_correction_count,
        &summary.standing_corrections_hash[..summary.standing_corrections_hash.len().min(12)],
        summary.officer_finding_count,
        &summary.officer_findings_hash[..summary.officer_findings_hash.len().min(12)],
        summary.recent_chain_count,
        summary.active_delegation_count,
        summary.invocation_reason,
    );

    let entry = zp_audit::UnsealedEntry {
        actor: zp_core::ActorId::System("regent".to_string()),
        action: zp_core::AuditAction::SystemEvent { event },
        conversation_id: zp_core::ConversationId(
            uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
        ),
        policy_decision: zp_core::PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "regent-cognitive-input".to_string(),
        receipt: None,
    };

    match audit_store.lock() {
        Ok(mut store) => {
            if let Err(e) = store.append(entry) {
                warn!("composition receipt emission failed: {}", e);
            }
        }
        Err(e) => {
            warn!("composition receipt: audit store lock poisoned: {}", e);
        }
    }
}

// ── Cognitive Self-Observer runtime (P2.2) ───────────────────────────────────

/// Run the Cognitive Self-Observer against Regent's response and chain-anchor
/// findings.
///
/// Emits one `cognitive:correction:violated` receipt per detected violation,
/// plus one `cognitive:observer:verified` summary receipt documenting what
/// was checked. The summary is emitted even when there are no violations —
/// chain-anchored evidence that the observer ran.
///
/// Per COGNITIVE-SELF-OBSERVER-2026-07.md §"Report" and §"Provenance".
fn run_cognitive_observer(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    response: &str,
    corrections: &[crate::corrections::ActiveStandingCorrection],
) {
    // Fast path — no active corrections means nothing to verify. Skip the
    // summary receipt too to avoid chain bloat during pre-issuance operation.
    if corrections.is_empty() {
        return;
    }

    let report = crate::cognitive_observer::verify_against_corrections(response, corrections);

    if !report.is_clean() {
        info!(
            violations = report.violations.len(),
            corrections = report.corrections_checked,
            patterns = report.patterns_checked,
            max_severity = ?report.max_severity,
            "cognitive observer flagged violations"
        );
    }

    // Emit per-violation receipts first, then the summary.
    let mut store_guard = match audit_store.lock() {
        Ok(s) => s,
        Err(e) => {
            warn!("observer receipt: audit store lock poisoned: {}", e);
            return;
        }
    };

    for violation in &report.violations {
        let event = crate::cognitive_observer::violation_event_string(violation);
        let entry = zp_audit::UnsealedEntry {
            actor: zp_core::ActorId::System("regent".to_string()),
            action: zp_core::AuditAction::SystemEvent { event },
            conversation_id: zp_core::ConversationId(
                uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
            ),
            policy_decision: zp_core::PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "cognitive-self-observer".to_string(),
            receipt: None,
        };
        if let Err(e) = store_guard.append(entry) {
            warn!("violation receipt emission failed: {}", e);
        }
    }

    // Summary always — chain-anchored proof the observer ran.
    let summary_event = crate::cognitive_observer::summary_event_string(&report);
    let summary_entry = zp_audit::UnsealedEntry {
        actor: zp_core::ActorId::System("regent".to_string()),
        action: zp_core::AuditAction::SystemEvent {
            event: summary_event,
        },
        conversation_id: zp_core::ConversationId(
            uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
        ),
        policy_decision: zp_core::PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "cognitive-self-observer".to_string(),
        receipt: None,
    };
    if let Err(e) = store_guard.append(summary_entry) {
        warn!("observer summary receipt emission failed: {}", e);
    }
}
