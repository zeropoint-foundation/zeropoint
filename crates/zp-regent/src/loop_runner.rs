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

/// Consecutive no-change cycles before an arc is declared stalled.
///
/// Two, not one: a single repeat can be a model restating itself on the way
/// to acting, and cutting an arc off at the first repetition would kill
/// legitimate slow starts. Two identical cycles with no tool dispatched is
/// not a slow start — it is a loop.
const ARC_STALL_LIMIT: u32 = 2;

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
                    // Enact whatever the operator has granted since the last
                    // tick, before reasoning about anything new. A signature
                    // that has been sitting unhonoured is the oldest
                    // outstanding instruction in the system.
                    drain_enactable_approvals(&audit_store, &executor).await;

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
                                    stall_count: 0,
                                });
                                // Read the arc's prior state before overwriting it.
                                let no_advance = !is_new_arc
                                    && current.progress == progress
                                    && current.tool_history.len() == tool_results.len();
                                current.stall_count =
                                    if no_advance { current.stall_count + 1 } else { 0 };
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

                                // Stall check, ahead of the budget check —
                                // an arc that is going nowhere should say so
                                // rather than spend nine more cycles proving
                                // it, and "stopped after 10 cycles (budget)"
                                // is indistinguishable from work attempted.
                                if current.stall_count >= ARC_STALL_LIMIT {
                                    warn!(
                                        cycles = current.cycles_completed,
                                        stalls = current.stall_count,
                                        progress = progress.as_str(),
                                        "work arc stalled — same plan, no tool dispatched"
                                    );
                                    emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcEnd, 0)
                                        .with_detail(format!(
                                            "stalled after {} cycles: {}",
                                            current.cycles_completed, progress
                                        )));
                                    emit_arc_stalled_receipt(
                                        &audit_store,
                                        &progress,
                                        current.cycles_completed,
                                    );
                                    break format!(
                                        "I started on \"{progress}\" and then made no \
                                         progress on it — {} cycles with the same plan and \
                                         no tool run. I have stopped rather than keep \
                                         going in circles. Tell me what to do differently, \
                                         or ask me to try a specific step.",
                                        current.cycles_completed
                                    );
                                }

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
                            stall_count: 0,
                        });
                        let no_advance = !is_new_arc
                            && current.progress == progress
                            && current.tool_history.len() == tool_results.len();
                        current.stall_count =
                            if no_advance { current.stall_count + 1 } else { 0 };
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

                        if current.stall_count >= ARC_STALL_LIMIT {
                            warn!(
                                cycles = current.cycles_completed,
                                progress = progress.as_str(),
                                "critical finding arc stalled — same plan, no tool dispatched"
                            );
                            emit(&cognitive_event_tx, CognitiveEvent::new(Phase::ArcEnd, 0)
                                .with_detail("stalled"));
                            emit_arc_stalled_receipt(
                                &audit_store,
                                &progress,
                                current.cycles_completed,
                            );
                            break;
                        }

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

        // Long window (Phase 6): emit this session's medium-window
        // summary before the loop exits, so the next session can compare.
        // Emitted before the memory flush — a failed flush should not
        // cost the profile.
        {
            let cycles = regent.lock().await.cycle_count();
            let profile = monitor.lock().await.session_profile(cycles);
            match profile {
                Some(p) => emit_session_profile_receipt(&audit_store, &p),
                // Below MIN_TREND_SAMPLES there is no window to summarise.
                // A short session emitting a profile of two points would
                // pollute the cross-session comparison it exists to serve.
                None => info!("session too short for a profile; none emitted"),
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
    // Retained for every turn of this cycle. `current_input.take()` below
    // hands the operator's message to perceive exactly once, so that a
    // narration turn is not re-read as a new directive — correct, but it
    // also left later turns with no idea what was asked.
    let cycle_directive: Option<String> = initial_input.as_ref().map(|i| i.content.clone());
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

    // Cognitive act accounting (v0, per COGNITIVE-ACT-ACCOUNTING-2026-07.md
    // §6 / BRIEF-cognitive-act-v0-m0-2026-07.md §2). The act receipt cites
    // the composition receipt it reasoned from, so the most recent
    // composition emitted this cycle is tracked here — updated every turn,
    // read at every post-composition exit (including after the loop, for
    // the max-turns fallback path).
    let mut last_composition_hash: Option<String> = None;
    let mut last_composition_summary: Option<crate::context::CompositionSummary> = None;

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
                // Unlike the mirror above, this is passed on *every* turn.
                // It is the one thing a narration turn cannot do without.
                cycle_directive.clone(),
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
            last_composition_hash = emit_composition_receipt(&audit_store, summary);
            last_composition_summary = Some(summary.clone());
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
                // A cycle where reasoning failed is precisely the kind of
                // act the accounting layer exists to make visible — the
                // exit a bottom-of-function emit would silently drop.
                emit_cognitive_act_receipt(
                    &audit_store,
                    last_composition_hash.as_deref(),
                    last_composition_summary.as_ref(),
                    None, // no intent — reasoning never produced one
                    "reason_failed",
                    turn,
                );
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
                // One act per turn within a continuing flow — per
                // COGNITIVE-MODE-AND-AGENCY-2026-07.md §3.1, each turn is
                // one Deliberation; the flow spans them.
                emit_cognitive_act_receipt(
                    &audit_store,
                    last_composition_hash.as_deref(),
                    last_composition_summary.as_ref(),
                    Some(intent.receipt_event()),
                    "continue",
                    turn,
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
                    Intent::RequestApproval {
                        kind,
                        proposed_action,
                        finding,
                        failed_limb,
                        expected_outcome,
                        draft,
                        ..
                    } => {
                        // Render the proposal the operator has to act on.
                        // A bare "[approval requested] x: y" was the floor
                        // EXECUTION-AUTHORITY-MODEL Phase 7 forbids — it
                        // names a limitation without giving anything to
                        // approve or reject.
                        let header = match kind {
                            crate::intent::ProposalKind::Action => "PROPOSAL (needs your approval)",
                            crate::intent::ProposalKind::Mechanism => "PROPOSAL (capability request)",
                        };
                        let mut out = format!("{header}\n{proposed_action}");
                        if let Some(f) = finding {
                            out.push_str(&format!("\n\nWhy: {f}"));
                        }
                        if let Some(l) = failed_limb {
                            out.push_str(&format!("\nBlocked by: {l}"));
                        }
                        if let Some(o) = expected_outcome {
                            out.push_str(&format!("\nIf approved: {o}"));
                        }
                        if let Some(d) = draft {
                            out.push_str(&format!(
                                "\n\nDraft (unsigned — honoured this session only, \
                                 will not survive a restart):\n{d}"
                            ));
                        }
                        out
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
                    // Ground truth for claim verification, taken from this
                    // cycle directly — never re-derived from the chain.
                    let enacted = crate::cognitive_observer::EnactedActs {
                        intent: intent.receipt_event().to_string(),
                        tools_run: tool_results.iter().map(|r| r.tool.clone()).collect(),
                        proposal_emitted: matches!(&intent, Intent::RequestApproval { .. }),
                    };
                    run_cognitive_observer(
                        &audit_store,
                        &response,
                        &context.standing_corrections,
                        &enacted,
                    );
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
                emit_cognitive_act_receipt(
                    &audit_store,
                    last_composition_hash.as_deref(),
                    last_composition_summary.as_ref(),
                    Some(intent.receipt_event()),
                    "done",
                    turn,
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
    // Only the Execute branch's `continue;` reaches this point — Continue,
    // Done, and the RequestApproval/Observe/other arm of Done all `return`
    // earlier in the loop — so the last intent produced before falling out
    // of the loop was always Execute.
    emit_cognitive_act_receipt(
        &audit_store,
        last_composition_hash.as_deref(),
        last_composition_summary.as_ref(),
        Some("execute"),
        "done_fallback",
        MAX_TOOL_TURNS.saturating_sub(1),
    );
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
///
/// Returns the appended entry's chain hash on success (`None` on failure) so
/// callers — namely the cognitive-act receipt (below) — can cite the
/// composition they reasoned from, per
/// COGNITIVE-ACT-ACCOUNTING-2026-07.md §6.
/// Emit `regent:awareness:session_profile` at shutdown.
///
/// Phase 6's long window: each session's medium-window summary lands on
/// chain so the next startup can compare against it. Structural only —
/// counts and deltas — per the same no-content discipline the
/// composition receipt follows.
fn emit_session_profile_receipt(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    profile: &crate::context::SessionProfile,
) {
    let event = format!(
        "regent:awareness:session_profile cycles={} samples={} mem_delta={:.4} \
         mem_rising={} models={} tasks={}",
        profile.cycles,
        profile.samples,
        profile.memory_usage_delta,
        profile.memory_monotonic_rising,
        profile.loaded_model_delta,
        profile.active_task_delta,
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
        policy_module: "regent-awareness".to_string(),
        receipt: None,
    };

    match audit_store.lock() {
        Ok(mut store) => {
            if let Err(e) = store.append(entry) {
                warn!("session profile receipt emission failed: {}", e);
            } else {
                info!(
                    cycles = profile.cycles,
                    samples = profile.samples,
                    "session profile emitted"
                );
            }
        }
        Err(e) => warn!("session profile: audit store lock poisoned: {}", e),
    }
}

fn emit_composition_receipt(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    summary: &crate::context::CompositionSummary,
) -> Option<String> {
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
        Ok(mut store) => match store.append(entry) {
            Ok(appended) => Some(appended.entry_hash),
            Err(e) => {
                warn!("composition receipt emission failed: {}", e);
                None
            }
        },
        Err(e) => {
            warn!("composition receipt: audit store lock poisoned: {}", e);
            None
        }
    }
}

// ── Cognitive act receipt emission (v0) ───────────────────────────────────────

/// Emit a `cognitive:act:recorded` chain receipt at cycle exit.
///
/// v0 per COGNITIVE-ACT-ACCOUNTING-2026-07.md §6 / BRIEF-cognitive-act-v0-m0
/// -2026-07.md §2 and §5: cites the composition receipt this act reasoned
/// from (a cycle-completion record referencing a perception-time one), not
/// emitted beside it. Called at every post-composition exit of `run_cycle` —
/// `reason_failed`, `continue`, `done`, `done_fallback` — so the reason-failed
/// path (the one exit a bottom-of-function emit would silently drop) is
/// covered.
///
/// Structural only — hashes, counts, enums — per the same no-chain-bloat
/// discipline `emit_composition_receipt` follows. `frame`, `suppressed`,
/// `operation` and `flow_ref` from the full Deliberation schema are absent
/// by v0 scope, not by omission; asserted fields (`basis`, `alternatives`,
/// ...) are v1+.
fn emit_cognitive_act_receipt(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    composition_receipt_hash: Option<&str>,
    summary: Option<&crate::context::CompositionSummary>,
    intent_kind: Option<&str>,
    outcome: &str,
    turn: u32,
) {
    // Mode, reason, attended, and sar all derive from the composition this
    // act reasoned from. `summary` should always be `Some` here — the
    // composition receipt is emitted every turn before any of this
    // function's call sites are reached — but degrade structurally rather
    // than panic if a future exit path is added without threading it.
    let (mode, reason, attended, sar) = match summary {
        Some(s) => (
            crate::regent::cognitive_mode(&s.invocation_reason),
            s.invocation_reason.as_str(),
            s.attended_class_count(),
            s.self_authorship_ratio,
        ),
        None => ("unknown", "unknown", 0, 0.0),
    };

    let event = format!(
        "cognitive:act:recorded cycle={} mode={} reason={} intent={} outcome={} turn={} attended={} sar={}",
        composition_receipt_hash.unwrap_or("none"),
        mode,
        reason,
        intent_kind.unwrap_or("none"),
        outcome,
        turn,
        attended,
        sar,
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
        policy_module: "regent-cognitive-act".to_string(),
        receipt: None,
    };

    match audit_store.lock() {
        Ok(mut store) => {
            if let Err(e) = store.append(entry) {
                warn!("cognitive act receipt emission failed: {}", e);
            }
        }
        Err(e) => {
            warn!("cognitive act receipt: audit store lock poisoned: {}", e);
        }
    }
}

// ── Cognitive Self-Observer runtime (P2.2) ───────────────────────────────────

/// Chain-anchor an arc that went nowhere.
///
/// A stall is a real outcome and belongs on the chain next to the acts that
/// succeeded. Without a receipt the only trace is a `warn` in a log that
/// rotates, and the substrate's record shows an arc opening and then simply
/// ceasing — indistinguishable from one that finished.
fn emit_arc_stalled_receipt(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    progress: &str,
    cycles: u32,
) {
    let event = format!(
        "regent:arc:stalled cycles={} progress={}",
        cycles,
        crate::text::preview(progress, 160)
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
        policy_module: "regent-work-arc".to_string(),
        receipt: None,
    };
    match audit_store.lock() {
        Ok(mut store) => {
            if let Err(e) = store.append(entry) {
                warn!("arc stall receipt emission failed: {}", e);
            }
        }
        Err(e) => warn!("arc stall receipt: audit store lock poisoned: {}", e),
    }
}

// ── Enactment of granted approvals ───────────────────────────────────────────

/// Turn operator signatures into substrate acts.
///
/// # Why this exists
///
/// Observed 2026-07-31. A proposal was escalated, queued, rendered, granted,
/// and chain-anchored — and the standing correction it proposed was never
/// created. `ApprovalIndex` appeared in exactly two places outside its own
/// module, both HTTP handlers, and `regent:approval:granted` was read only to
/// stop resolved requests showing in the queue. Nothing consumed a grant.
///
/// The operator signed and the system did not act. That is the mirror of the
/// defect that produced the proposal in the first place — a claimed act
/// without authority, then authority without an act — and it is the worse
/// half, because the first was caught by a verifier and this one presented as
/// success at every visible surface: the queue emptied, the receipt anchored,
/// the command printed a tick.
///
/// # Why it dispatches rather than reasons
///
/// The enactment carried on the request is dispatched verbatim. No model is
/// consulted. The operator signed a specific call, and re-deriving that call
/// from the proposal's prose at enactment time would reintroduce exactly the
/// confabulation surface the Class 5 verifier exists to catch — with the
/// operator's signature already attached to it.
///
/// # Runs on the idle tick
///
/// Called from the message loop, which ticks every ~60s with empty content,
/// so an approval signed while nothing else is happening is honoured within
/// the minute rather than waiting for the next conversation.
async fn drain_enactable_approvals(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    executor: &Arc<dyn IntentExecutor>,
) {
    let work: Vec<(String, crate::intent::Enactment)> = {
        let store = match audit_store.lock() {
            Ok(s) => s,
            Err(e) => {
                warn!("approval enactment: audit store lock poisoned: {}", e);
                return;
            }
        };
        let mut entries = Vec::new();
        for prefix in [
            crate::approvals::EVENT_PREFIX_REQUEST,
            crate::approvals::EVENT_PREFIX_GRANTED,
            crate::approvals::EVENT_PREFIX_DENIED,
            crate::approvals::EVENT_PREFIX_ENACTED,
        ] {
            entries.extend(
                store
                    .search_chain_by_action_keyword(prefix, 1024)
                    .unwrap_or_default(),
            );
        }
        crate::approvals::ApprovalIndex::build(&entries)
            .enactable()
            .iter()
            .filter_map(|r| {
                r.enactment
                    .clone()
                    .map(|e| (r.request_hash.clone(), e))
            })
            .collect()
    };

    if work.is_empty() {
        return;
    }

    for (request_hash, enactment) in work {
        let short = &request_hash[..12.min(request_hash.len())];
        info!(
            tool = %enactment.tool,
            request = short,
            "enacting granted approval"
        );

        let intent = Intent::Execute {
            tool: enactment.tool.clone(),
            params: enactment.params.clone(),
        };

        // The gate still runs. An operator's signature authorises the act; it
        // does not exempt it from policy, and a disagreement between the two
        // is worth a receipt rather than a bypass.
        let outcome = match executor.execute(&intent).await {
            Ok(IntentOutcome::ToolCompleted { .. }) => "completed".to_string(),
            Ok(IntentOutcome::ToolDenied { reason, .. }) => {
                warn!(
                    tool = %enactment.tool,
                    request = short,
                    reason = %reason,
                    "granted approval denied at the gate — operator authority and \
                     gate policy disagree about the same act"
                );
                format!("denied: {reason}")
            }
            Ok(_) => "unexpected_outcome".to_string(),
            Err(e) => {
                warn!(
                    tool = %enactment.tool,
                    request = short,
                    "enactment failed: {}", e
                );
                format!("error: {e}")
            }
        };

        // Receipt regardless of outcome. A failed enactment that leaves no
        // trace would be retried on every tick forever, and an operator
        // reading the chain would see a grant with nothing after it — the
        // same silence this function was written to end.
        let event =
            crate::approvals::enacted_event_string(&request_hash, &enactment.tool, &outcome);
        let entry = zp_audit::UnsealedEntry {
            actor: zp_core::ActorId::System("regent".to_string()),
            action: zp_core::AuditAction::SystemEvent { event },
            conversation_id: zp_core::ConversationId(
                uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
            ),
            policy_decision: zp_core::PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "regent-approval-enactment".to_string(),
            receipt: None,
        };
        match audit_store.lock() {
            Ok(mut store) => {
                if let Err(e) = store.append(entry) {
                    warn!("enactment receipt emission failed: {}", e);
                }
            }
            Err(e) => warn!("enactment receipt: audit store lock poisoned: {}", e),
        }
    }
}

/// Emit chain receipts for act claims the cycle's own record contradicts.
///
/// Runs on every content-bearing response, independent of the standing
/// correction corpus, because its ground truth is the cycle rather than the
/// corpus. Emits nothing when the response is clean — unlike the corrections
/// observer, which anchors a summary every time. The asymmetry is deliberate:
/// the corrections observer's summary proves *it ran* against a corpus that
/// may be empty, whereas this check's inputs are always present, so a receipt
/// here always means a real divergence.
///
/// Per `COGNITIVE-SELF-OBSERVER-2026-07.md` §"Class 5 — Commitment claims".
/// Detection only in this slice: the finding is chain-anchored and logged, and
/// the response still reaches the operator unaltered. Suppression, annotation,
/// and escalation to the propose tier are the natural next moves and are
/// deliberately not taken here — rewriting an emitted response is an authority
/// decision (P9), not an observer's call to make on its own.
fn emit_unbacked_claim_receipts(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    response: &str,
    enacted: &crate::cognitive_observer::EnactedActs,
) {
    let claims = crate::cognitive_observer::verify_claims(response, enacted);
    if claims.is_empty() {
        return;
    }

    for c in &claims {
        warn!(
            kind = ?c.kind,
            phrase = %c.matched_phrase,
            intent = %c.intent,
            tools_run = c.tools_run.len(),
            severity = ?c.severity,
            excerpt = %c.excerpt,
            "regent claimed an act this cycle did not perform"
        );
    }

    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(e) => {
            warn!("unbacked claim receipt: audit store lock poisoned: {}", e);
            return;
        }
    };
    for c in &claims {
        let entry = zp_audit::UnsealedEntry {
            actor: zp_core::ActorId::System("regent".to_string()),
            action: zp_core::AuditAction::SystemEvent {
                event: crate::cognitive_observer::unbacked_claim_event_string(c),
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
        if let Err(e) = store.append(entry) {
            warn!("unbacked claim receipt emission failed: {}", e);
        }
    }
}

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
    enacted: &crate::cognitive_observer::EnactedActs,
) {
    // Class 5 (enactment subset) runs first and unconditionally. Its ground
    // truth is the cycle's own record, not the correction corpus, so an empty
    // corpus must not skip it — which is exactly what would have happened had
    // this been folded in below the fast path. See
    // `cognitive_observer.rs` §"Class 5 (enactment subset)".
    emit_unbacked_claim_receipts(audit_store, response, enacted);

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
