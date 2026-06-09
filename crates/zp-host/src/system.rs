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

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use reqwest::header::{HeaderName, HeaderValue};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::warn;

use zp_audit::AuditStore;
use zp_core::{ActionType, ActorId, Channel, ConversationId, FileOperation, PolicyContext, PolicyDecision, TrustTier};
use zp_policy::GovernanceGate;

use crate::{
    context::HostContext,
    error::HostError,
    types::{HttpMethod, HttpRequest, HttpResult, SpawnRequest, SpawnResult, WriteMode, WriteRequest, WriteResult},
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

        // ── Stage 2: append gate decision to chain ─────────────────────────
        // Append regardless of decision — the chain must record denials too.
        let gate_receipt_hash = match self.audit_store.lock() {
            Ok(mut store) => match store.append(gate_result.unsealed.clone()) {
                Ok(sealed) => Some(sealed.entry_hash),
                Err(e) => {
                    warn!("zp-host: failed to append gate receipt: {}", e);
                    None
                }
            },
            Err(e) => {
                warn!("zp-host: audit store lock poisoned: {}", e);
                None
            }
        };

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

        Ok(SpawnResult { child, gate_receipt_hash })
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

        // ── Stage 2: append gate decision to chain ─────────────────────────
        let gate_receipt_hash = match self.audit_store.lock() {
            Ok(mut store) => match store.append(gate_result.unsealed.clone()) {
                Ok(sealed) => Some(sealed.entry_hash),
                Err(e) => {
                    warn!("zp-host: failed to append gate receipt for write_file: {}", e);
                    None
                }
            },
            Err(e) => {
                warn!("zp-host: audit store lock poisoned in write_file: {}", e);
                None
            }
        };

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

        Ok(WriteResult { gate_receipt_hash, bytes_written })
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

        // ── Stage 2: append gate decision to chain ─────────────────────────
        let gate_receipt_hash = match self.audit_store.lock() {
            Ok(mut store) => match store.append(gate_result.unsealed.clone()) {
                Ok(sealed) => Some(sealed.entry_hash),
                Err(e) => {
                    warn!("zp-host: failed to append gate receipt for http_request: {}", e);
                    None
                }
            },
            Err(e) => {
                warn!("zp-host: audit store lock poisoned in http_request: {}", e);
                None
            }
        };

        // ── Stage 3: honour gate decision ─────────────────────────────────
        if gate_result.is_blocked() {
            let reason = match &gate_result.decision {
                PolicyDecision::Block { reason, .. } => reason.clone(),
                _ => "policy denied".to_string(),
            };
            return Err(HostError::GateDenied { reason });
        }

        // ── Stage 4: execute HTTP request ─────────────────────────────────
        let client = reqwest::Client::new();
        let method = match req.method {
            HttpMethod::Get    => reqwest::Method::GET,
            HttpMethod::Post   => reqwest::Method::POST,
            HttpMethod::Put    => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch  => reqwest::Method::PATCH,
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
            builder = builder.body(req.body);
        }

        let response = builder.send().await?; // maps reqwest::Error → HostError::Http via From
        let status = response.status().as_u16();
        let body = response.bytes().await?.to_vec();

        Ok(HttpResult { status, body, gate_receipt_hash })
    }
}
