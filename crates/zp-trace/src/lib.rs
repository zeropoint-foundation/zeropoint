//! `zp-trace` — harness-agnostic trace and guard for ZeroPoint.
//!
//! # Why a trait and not a hook
//!
//! Every harness surveyed (2026-08, `docs/design/HARNESS-SURVEY-2026-08.md`)
//! exposes a subprocess hook that *claims* to gate tool calls. In Goose that
//! hook has three verified bypasses and fails open on error. A hook-based
//! guard therefore emits receipts asserting coverage it does not have — which
//! is worse than no guard, because the chain then carries a false claim.
//!
//! So the gate is a trait, installed at the harness's single universal tool
//! dispatch choke point, in-process. Per GAR §3.1: trait integration gives
//! visibility, the process boundary gives enforcement; in a Rust harness we
//! get both without a bridge.
//!
//! # Layering
//!
//! - [`ToolGate`] — what a harness calls. One method, fail-closed by default.
//! - [`ZeroPointGate`] — the implementation: Guard → Policy → Receipt → Audit.
//! - Adapters (`zp-trace-goose`, `zp-trace-codex`) map harness types onto
//!   [`ToolCallCtx`] and nothing more. Adapters hold no policy.

use std::sync::Arc;

use chrono::Utc;
use zp_receipt::{
    canonical_hash, Action, Decision, ExecutorType, Receipt, ReceiptBuilder, ReceiptChain, Signer,
    Status, TrustGrade,
};

pub mod redact;

// ---------------------------------------------------------------------------
// The gate contract
// ---------------------------------------------------------------------------

/// A tool call presented for governance, normalized across harnesses.
///
/// `args` is the raw argument value. It is never persisted or transmitted —
/// [`ZeroPointGate`] hashes it and stores a redacted projection. This mirrors
/// `zp_regent::config::ApiKeySource`: key material resolves at call time and
/// is dropped, never entering the receipt path.
#[derive(Debug, Clone)]
pub struct ToolCallCtx {
    /// Harness identifier, e.g. `"goose"`, `"codex"`.
    pub harness: &'static str,
    /// Stable session/run identifier from the harness.
    pub session_id: String,
    /// Harness-assigned call identifier, for pairing intent with outcome.
    pub call_id: Option<String>,
    /// Fully-qualified tool name as dispatched.
    pub tool_name: String,
    /// Raw arguments. Hashed and redacted, never stored verbatim.
    pub args: serde_json::Value,
    /// Working directory, when the harness knows one.
    pub working_dir: Option<String>,
    /// True when this call originates from a delegated sub-agent.
    ///
    /// Critical field. Goose disables its hook manager entirely for subagents
    /// (`agent.rs:438`), so this is the distinction the harness's own gate
    /// cannot make. A mode-scoped delegation must narrow, never widen.
    pub delegated: bool,
    /// Delegation depth. 0 = the operator's own agent.
    pub depth: u8,
}

/// The gate's answer. Deny carries a reason the model can plan around.
#[derive(Debug, Clone)]
pub enum GateVerdict {
    Allow {
        /// Receipt recording the authorization, for chaining the outcome.
        receipt_id: String,
    },
    Deny {
        reason: String,
        /// Policy that produced the denial, for the operator, not the model.
        policy: Option<String>,
        receipt_id: String,
    },
}

impl GateVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateVerdict::Allow { .. })
    }

    pub fn receipt_id(&self) -> &str {
        match self {
            GateVerdict::Allow { receipt_id } | GateVerdict::Deny { receipt_id, .. } => receipt_id,
        }
    }
}

/// The outcome of a call the gate allowed. Closes the pair.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    pub call_id: Option<String>,
    pub tool_name: String,
    pub is_error: bool,
    pub duration_ms: u64,
    /// Hash of the result body. The body itself is not stored.
    pub result_hash: String,
    pub result_bytes: usize,
    /// Receipt id returned by the preceding [`GateVerdict::Allow`].
    pub authorized_by: String,
}

/// What a harness implements against.
///
/// One method that can deny, one that records. Deliberately minimal: anything
/// richer becomes a second place for policy to live, and policy that lives in
/// two places drifts. (`zp-regent/src/tools.rs` documents what that costs.)
#[async_trait::async_trait]
pub trait ToolGate: Send + Sync {
    /// Called before dispatch. Returning [`GateVerdict::Deny`] must prevent
    /// execution.
    async fn gate(&self, ctx: &ToolCallCtx) -> GateVerdict;

    /// Called after the tool returns. Never blocks; errors are swallowed and
    /// surfaced through [`ToolGate::degraded`].
    async fn record(&self, outcome: ToolOutcome);

    /// True when receipts are buffering because the chain is unreachable.
    /// Surfaced to the operator; never used to relax the gate.
    fn degraded(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// ZeroPoint implementation
// ---------------------------------------------------------------------------

/// How the gate behaves when it cannot reach policy or the chain.
///
/// The default is [`FailureMode::Closed`]. This is the whole reason the crate
/// exists — Goose's hook manager treats a spawn error, a timeout, or any exit
/// code other than 2 as `Allow` (`hooks/mod.rs:474-478`), which means an
/// attacker who can make the gate slow can make it absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureMode {
    #[default]
    Closed,
    /// Allow, and mark every receipt emitted while degraded. Only defensible
    /// for trace-only deployments where no tool crosses a trust boundary.
    Open,
}

pub struct ZeroPointGateConfig {
    pub failure_mode: FailureMode,
    /// Tools that cross a trust boundary. Everything else is trace-only.
    /// Resolved from the active Regent mode, not hardcoded here.
    pub guarded_tools: Vec<String>,
    /// Maximum buffered receipts before the oldest is dropped.
    pub buffer_max: usize,
    /// Identity under which receipts are signed.
    pub executor_id: String,
}

impl Default for ZeroPointGateConfig {
    fn default() -> Self {
        Self {
            failure_mode: FailureMode::Closed,
            guarded_tools: Vec::new(),
            buffer_max: 512,
            executor_id: "harness".to_string(),
        }
    }
}

/// Guard → Policy → Receipt → Audit, in-process.
pub struct ZeroPointGate {
    cfg: ZeroPointGateConfig,
    signer: Arc<Signer>,
    chain: Arc<tokio::sync::Mutex<ReceiptChain>>,
    policy: Arc<dyn PolicyEvaluator>,
    degraded: std::sync::atomic::AtomicBool,
}

/// Policy evaluation, injected so the gate is testable without a live chain.
/// In production this is backed by `zp-policy`'s WASM engine via `zp-pipeline`.
#[async_trait::async_trait]
pub trait PolicyEvaluator: Send + Sync {
    async fn evaluate(&self, ctx: &ToolCallCtx) -> Result<PolicyOutcome, PolicyError>;
}

pub struct PolicyOutcome {
    pub decision: Decision,
    pub policy_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy engine unreachable: {0}")]
    Unreachable(String),
    #[error("policy evaluation failed: {0}")]
    Failed(String),
}

impl ZeroPointGate {
    pub fn new(
        cfg: ZeroPointGateConfig,
        signer: Arc<Signer>,
        chain: Arc<tokio::sync::Mutex<ReceiptChain>>,
        policy: Arc<dyn PolicyEvaluator>,
    ) -> Self {
        Self {
            cfg,
            signer,
            chain,
            policy,
            degraded: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn is_guarded(&self, tool: &str) -> bool {
        self.cfg.guarded_tools.iter().any(|t| t == tool)
    }

    /// Build, sign, and append a receipt. Returns its id.
    ///
    /// NOTE: `ReceiptType` and `Action` variants must be pinned against
    /// `zp-receipt/src/types.rs:604` and `:1097` before this compiles — the
    /// variant names below are placeholders pending that read.
    async fn emit(
        &self,
        ctx: &ToolCallCtx,
        decision: Option<Decision>,
        status: Status,
        extra: Vec<(&str, serde_json::Value)>,
    ) -> Result<String, String> {
        let args_hash = canonical_hash(&ctx.args).map_err(|e| e.to_string())?;
        let preview = redact::project(&ctx.args);

        let mut chain = self.chain.lock().await;
        let (prev_hash, sequence, chain_id) = chain.tip();

        let mut builder = ReceiptBuilder::new(RECEIPT_TYPE_TOOL_CALL, &self.cfg.executor_id)
            .executor_type(ExecutorType::Agent)
            .framework(ctx.harness)
            .status(status)
            .trust_grade(if ctx.delegated {
                TrustGrade::B
            } else {
                TrustGrade::A
            })
            .action(Action::tool_call(&ctx.tool_name))
            .chain(&prev_hash, sequence, &chain_id)
            .extension("args_hash", serde_json::json!(args_hash))
            .extension("args_preview", preview)
            .extension("session_id", serde_json::json!(ctx.session_id))
            .extension("call_id", serde_json::json!(ctx.call_id))
            .extension("delegated", serde_json::json!(ctx.delegated))
            .extension("delegation_depth", serde_json::json!(ctx.depth));

        if let Some(d) = decision {
            builder = builder.policy(d);
        }
        if let Some(wd) = &ctx.working_dir {
            builder = builder.extension("working_dir", serde_json::json!(wd));
        }
        for (k, v) in extra {
            builder = builder.extension(k, v);
        }

        let mut receipt: Receipt = builder.try_finalize().map_err(|e| e.to_string())?;
        self.signer.sign(&mut receipt);
        let id = receipt.id.clone();
        chain.append(receipt).map_err(|e| e.to_string())?;
        Ok(id)
    }

    fn mark_degraded(&self, yes: bool) {
        self.degraded
            .store(yes, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Placeholder — pin against `zp-receipt/src/types.rs:604`.
const RECEIPT_TYPE_TOOL_CALL: zp_receipt::ReceiptType = zp_receipt::ReceiptType::ToolCall;

#[async_trait::async_trait]
impl ToolGate for ZeroPointGate {
    async fn gate(&self, ctx: &ToolCallCtx) -> GateVerdict {
        // Trace-only path: observe, never block.
        if !self.is_guarded(&ctx.tool_name) {
            let receipt_id = self
                .emit(ctx, None, Status::Observed, vec![])
                .await
                .unwrap_or_else(|e| {
                    self.mark_degraded(true);
                    tracing::warn!(error = %e, "trace receipt failed; call is unreceipted");
                    String::new()
                });
            return GateVerdict::Allow { receipt_id };
        }

        // Guarded path.
        let outcome = match self.policy.evaluate(ctx).await {
            Ok(o) => {
                self.mark_degraded(false);
                o
            }
            Err(e) => {
                self.mark_degraded(true);
                // The decision that distinguishes this crate from every hook
                // in the survey. A gate that cannot evaluate has not allowed.
                return match self.cfg.failure_mode {
                    FailureMode::Closed => {
                        let receipt_id = self
                            .emit(
                                ctx,
                                Some(Decision::Deny),
                                Status::Failed,
                                vec![("degraded", serde_json::json!(true))],
                            )
                            .await
                            .unwrap_or_default();
                        GateVerdict::Deny {
                            reason: format!(
                                "ZeroPoint could not evaluate policy ({e}). Denied under \
                                 fail-closed configuration. This is a policy denial, not a \
                                 transient failure — do not retry."
                            ),
                            policy: None,
                            receipt_id,
                        }
                    }
                    FailureMode::Open => {
                        let receipt_id = self
                            .emit(
                                ctx,
                                Some(Decision::Allow),
                                Status::Degraded,
                                vec![
                                    ("degraded", serde_json::json!(true)),
                                    ("coverage_asserted", serde_json::json!(false)),
                                ],
                            )
                            .await
                            .unwrap_or_default();
                        GateVerdict::Allow { receipt_id }
                    }
                };
            }
        };

        let allowed = matches!(outcome.decision, Decision::Allow);
        let receipt_id = self
            .emit(
                ctx,
                Some(outcome.decision),
                if allowed { Status::Allowed } else { Status::Denied },
                vec![("policy_id", serde_json::json!(outcome.policy_id))],
            )
            .await
            .unwrap_or_default();

        if allowed {
            GateVerdict::Allow { receipt_id }
        } else {
            GateVerdict::Deny {
                reason: outcome
                    .reason
                    .unwrap_or_else(|| "denied by governance policy".to_string()),
                policy: outcome.policy_id,
                receipt_id,
            }
        }
    }

    async fn record(&self, outcome: ToolOutcome) {
        let mut chain = self.chain.lock().await;
        let (prev_hash, sequence, chain_id) = chain.tip();

        let built = ReceiptBuilder::new(RECEIPT_TYPE_TOOL_CALL, &self.cfg.executor_id)
            .parent(&outcome.authorized_by)
            .status(if outcome.is_error {
                Status::Failed
            } else {
                Status::Completed
            })
            .action(Action::tool_result(&outcome.tool_name))
            .chain(&prev_hash, sequence, &chain_id)
            .duration_ms(Utc::now(), outcome.duration_ms)
            .extension("result_hash", serde_json::json!(outcome.result_hash))
            .extension("result_bytes", serde_json::json!(outcome.result_bytes))
            .extension("call_id", serde_json::json!(outcome.call_id))
            .try_finalize();

        match built {
            Ok(mut receipt) => {
                self.signer.sign(&mut receipt);
                if let Err(e) = chain.append(receipt) {
                    self.mark_degraded(true);
                    tracing::warn!(error = %e, "outcome receipt not chained");
                }
            }
            Err(e) => {
                self.mark_degraded(true);
                tracing::warn!(error = %e, "outcome receipt not built");
            }
        }
    }

    fn degraded(&self) -> bool {
        self.degraded.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// A gate that denies everything, for tests and for the unconfigured case.
// ---------------------------------------------------------------------------

/// Installed when ZeroPoint is enabled but not yet configured. Denying is the
/// safe default; a harness that silently runs ungoverned because config was
/// missing is the failure this crate exists to prevent.
pub struct DenyAllGate;

#[async_trait::async_trait]
impl ToolGate for DenyAllGate {
    async fn gate(&self, _ctx: &ToolCallCtx) -> GateVerdict {
        GateVerdict::Deny {
            reason: "ZeroPoint governance is enabled but unconfigured; no capability grant is \
                     loaded. Ask the operator to run `zp configure`."
                .to_string(),
            policy: None,
            receipt_id: String::new(),
        }
    }

    async fn record(&self, _outcome: ToolOutcome) {}
}
