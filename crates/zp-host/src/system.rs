//! SystemHostContext — the production HostContext implementation.
//!
//! Every call to `spawn_process` goes through:
//!   1. Gate evaluation (`GovernanceGate::evaluate`)
//!   2. Gate decision appended to the audit chain (allowed or denied)
//!   3. If allowed: OS spawn via `tokio::process::Command`
//!   4. `Ok(SpawnResult)` or the appropriate `HostError`
//!
//! ## Why the gate receipt comes before the spawn
//!
//! The audit chain records *intent* before *execution*.  If the process
//! crashes or the receipt append after execution fails, the chain still shows
//! the gate decision that authorized the action.  This is the receipt-triple
//! shape from the handoff brief: intent → policy → exec.
//!
//! ## The append is a precondition, not a companion (2026-08-14)
//!
//! Until this date, step 2 was best-effort: a failed append or a poisoned
//! lock logged a warning, set `gate_receipt_hash` to `None`, and **the side
//! effect proceeded anyway**.  That made the effect happen with no verifiable
//! record of it — the definition of failing open in
//! `docs/design/THREAT-MODEL-2026-08.md` §1, and the direct counterexample to
//! `ARCHITECTURE.md:250`'s claim that it is "structurally impossible to act
//! without a trace."
//!
//! `HostError::AuditError` already documented the intended behaviour — *"The
//! action was NOT executed — the host treats an unappendable audit chain as
//! fatal for governed actions"* — and `zp-server/src/exec_ws.rs` already
//! handled it.  Nothing constructed it.  `seal_or_refuse` now does.
//!
//! Note the ordering consequence: the append is attempted *before* the block
//! check, so a gate denial that cannot be recorded returns `AuditError`
//! rather than `GateDenied`.  Both refuse the action.  `AuditError` is the
//! more honest of the two, because `GateDenied`'s own doc comment promises
//! the denial is on-chain, and in that case it is not.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use reqwest::header::{HeaderName, HeaderValue};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::error;

use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::{
    ActionType, ActorId, Channel, ConversationId, FileOperation, PolicyContext, PolicyDecision,
    TrustTier,
};
use zp_policy::GovernanceGate;

use crate::{
    context::HostContext,
    error::HostError,
    types::{
        HttpMethod, HttpRequest, HttpResult, SpawnRequest, SpawnResult, WriteMode, WriteRequest,
        WriteResult,
    },
};

/// Production HostContext.  Holds references to the governance gate and audit
/// store — both are `Arc`-wrapped so this can be cheaply cloned into request
/// handlers.
pub struct SystemHostContext {
    gate: Arc<GovernanceGate>,
    audit_store: Arc<Mutex<AuditStore>>,
}

impl SystemHostContext {
    /// Construct a SystemHostContext from the server's shared gate and audit
    /// store.  Called once during `AppState::init`.
    pub fn new(gate: Arc<GovernanceGate>, audit_store: Arc<Mutex<AuditStore>>) -> Self {
        Self { gate, audit_store }
    }

    /// Seal the gate decision into the chain, or refuse the action.
    ///
    /// Returns the sealed entry hash on success.  Every failure path —
    /// poisoned lock, rejected append — returns `HostError::AuditError`, and
    /// every caller propagates it with `?` **before** performing any side
    /// effect.  That is the whole point: an effect the chain cannot record is
    /// an effect this crate will not perform.
    ///
    /// `site` names the host function for the operator-facing log line.  A
    /// refusal here is an infrastructure fault, not a policy outcome, so it
    /// logs at `error` rather than `warn` — the chain being unwritable is the
    /// substrate's most serious non-crash condition.
    fn seal_or_refuse(&self, unsealed: UnsealedEntry, site: &str) -> Result<String, HostError> {
        let mut store = self.audit_store.lock().map_err(|e| {
            error!("zp-host: {site}: audit store lock poisoned — refusing action: {e}");
            HostError::AuditError(format!("{site}: audit store lock poisoned: {e}"))
        })?;

        store
            .append(unsealed)
            .map(|sealed| sealed.entry_hash)
            .map_err(|e| {
                error!("zp-host: {site}: gate receipt append rejected — refusing action: {e}");
                HostError::AuditError(format!("{site}: failed to append gate receipt: {e}"))
            })
    }
}

#[async_trait]
impl HostContext for SystemHostContext {
    async fn spawn_process(&self, req: SpawnRequest) -> Result<SpawnResult, HostError> {
        // ── Stage 1: gate evaluation ───────────────────────────────────────
        let context = PolicyContext {
            action: ActionType::Execute {
                language: req.program.clone(),
            },
            trust_tier: TrustTier::Tier1,
            channel: Channel::Api,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![req.tool_name.clone()],
            mesh_context: None,
        };
        let actor = ActorId::System(req.actor_label.clone());
        let gate_result = self.gate.evaluate(&context, actor);

        // ── Stage 2: seal the gate decision, or refuse ─────────────────────
        // Append regardless of decision — the chain must record denials too.
        // A failure here returns before any spawn happens.
        let gate_receipt_hash =
            Some(self.seal_or_refuse(gate_result.unsealed.clone(), "spawn_process")?);

        // ── Stage 3: honour gate decision ─────────────────────────────────
        if gate_result.is_blocked() {
            let reason = match &gate_result.decision {
                PolicyDecision::Block { reason, .. } => reason.clone(),
                _ => "policy denied".to_string(),
            };
            return Err(HostError::GateDenied { reason });
        }

        // ── Stage 4: spawn — no shell, no re-parsing ──────────────────────
        // argv-form only: program + args.  stdin closed; stdout/stderr piped
        // so the caller can stream output back to the client.
        let mut cmd = Command::new(&req.program);
        cmd.args(&req.args)
            .current_dir(&req.cwd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null());

        // Apply isolated environment if requested (used by execution-engine
        // sandbox: env_clear() then set only the listed vars).
        if let Some(ref vars) = req.env_vars {
            cmd.env_clear();
            for (k, v) in vars {
                cmd.env(k, v);
            }
        }

        let child = cmd.spawn()?; // maps std::io::Error → HostError::Io via From

        Ok(SpawnResult {
            child,
            gate_receipt_hash,
        })
    }

    async fn write_file(&self, req: WriteRequest) -> Result<WriteResult, HostError> {
        // ── Stage 1: gate evaluation ───────────────────────────────────────
        let context = PolicyContext {
            action: ActionType::FileOp {
                op: FileOperation::Write,
                path: req.path.to_string_lossy().to_string(),
            },
            trust_tier: TrustTier::Tier1,
            channel: Channel::Api,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![format!("write/{}", req.description)],
            mesh_context: None,
        };
        let actor = ActorId::System(req.actor_label.clone());
        let gate_result = self.gate.evaluate(&context, actor);

        // ── Stage 2: seal the gate decision, or refuse ─────────────────────
        let gate_receipt_hash =
            Some(self.seal_or_refuse(gate_result.unsealed.clone(), "write_file")?);

        // ── Stage 3: honour gate decision ─────────────────────────────────
        if gate_result.is_blocked() {
            let reason = match &gate_result.decision {
                PolicyDecision::Block { reason, .. } => reason.clone(),
                _ => "policy denied".to_string(),
            };
            return Err(HostError::GateDenied { reason });
        }

        // ── Stage 4: write — create parent dirs best-effort, then write ───
        if let Some(parent) = req.path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
        }

        let bytes_written = req.content.len();

        match req.mode {
            WriteMode::Create => {
                tokio::fs::write(&req.path, &req.content).await?;
            }
            WriteMode::Append => {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&req.path)
                    .await?;
                file.write_all(&req.content).await?;
            }
        }

        Ok(WriteResult {
            gate_receipt_hash,
            bytes_written,
        })
    }

    async fn http_request(&self, req: HttpRequest) -> Result<HttpResult, HostError> {
        // ── Stage 1: gate evaluation ───────────────────────────────────────
        let context = PolicyContext {
            action: ActionType::ApiCall {
                endpoint: req.url.clone(),
            },
            trust_tier: TrustTier::Tier1,
            channel: Channel::Api,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![format!("http/{}", req.description)],
            mesh_context: None,
        };
        let actor = ActorId::System(req.actor_label.clone());
        let gate_result = self.gate.evaluate(&context, actor);

        // ── Stage 2: seal the gate decision, or refuse ─────────────────────
        let gate_receipt_hash =
            Some(self.seal_or_refuse(gate_result.unsealed.clone(), "http_request")?);

        // ── Stage 3: honour gate decision ─────────────────────────────────
        if gate_result.is_blocked() {
            let reason = match &gate_result.decision {
                PolicyDecision::Block { reason, .. } => reason.clone(),
                _ => "policy denied".to_string(),
            };
            return Err(HostError::GateDenied { reason });
        }

        // ── Stage 4: execute HTTP request ─────────────────────────────────
        let response = Self::send_http(&req).await?;
        let status = response.status().as_u16();
        let body = response.bytes().await?.to_vec();

        Ok(HttpResult {
            status,
            body,
            gate_receipt_hash,
        })
    }

    async fn http_request_streaming(
        &self,
        req: HttpRequest,
    ) -> Result<reqwest::Response, HostError> {
        // Stages 1–3: identical gate/receipt pattern as http_request.
        let context = PolicyContext {
            action: ActionType::ApiCall {
                endpoint: req.url.clone(),
            },
            trust_tier: TrustTier::Tier1,
            channel: Channel::Api,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![format!("http/{}", req.description)],
            mesh_context: None,
        };
        let actor = ActorId::System(req.actor_label.clone());
        let gate_result = self.gate.evaluate(&context, actor);

        // Seal or refuse. This function returns a raw `Response` and so has
        // nowhere to carry the hash, but the append is no less a precondition:
        // the value is discarded, the failure is not.
        self.seal_or_refuse(gate_result.unsealed.clone(), "http_request_streaming")?;

        if gate_result.is_blocked() {
            let reason = match &gate_result.decision {
                PolicyDecision::Block { reason, .. } => reason.clone(),
                _ => "policy denied".to_string(),
            };
            return Err(HostError::GateDenied { reason });
        }

        // Stage 4: send — return raw Response for caller to stream.
        Self::send_http(&req).await
    }
}

impl SystemHostContext {
    /// Build a reqwest client from request options and send, returning the
    /// raw Response.  Used by both `http_request` and `http_request_streaming`.
    async fn send_http(req: &HttpRequest) -> Result<reqwest::Response, HostError> {
        let mut client_builder = reqwest::Client::builder();
        if req.no_proxy {
            client_builder = client_builder.no_proxy();
        }
        if let Some(ms) = req.timeout_ms {
            client_builder = client_builder.timeout(std::time::Duration::from_millis(ms));
        }
        let client = client_builder
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        };

        let mut builder = client.request(method, &req.url);
        for (name, value) in &req.headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                builder = builder.header(n, v);
            }
        }
        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }

        Ok(builder.send().await?) // maps reqwest::Error → HostError::Http via From
    }
}
