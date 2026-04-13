//! The central request pipeline orchestrator.
//!
//! Wires together policy, skills, audit, LLM, execution engine, and learning.
//! Implements ARCHITECTURE-V2.md §7.2 message flow with tool invocation loop.

use crate::config::{MeshConfig, PipelineConfig};
use crate::mesh_bridge::{MeshBridge, MeshBridgeConfig};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use execution_engine::{ExecutionEngine, ExecutionRequest as ExecRequest, Runtime};
use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::policy::PolicyContext;
use zp_core::{
    ActionType, ActorId, AuditAction, ConversationId, Episode, EpisodeId, Message, MessageId,
    MessageRole, OperatorIdentity, Outcome, PolicyDecision, ReceiptAction, ReceiptStatus, Request,
    Response, ToolCall, ToolResult,
};
use zp_learning::EpisodeStore;
use zp_llm::{ChatMessage, CompletionRequest, PromptBuilder, ProviderPool};
use zp_mesh::envelope::EnvelopeType;
use zp_mesh::identity::MeshIdentity;
use zp_mesh::runtime::{MeshRuntime, RuntimeConfig};
use zp_mesh::transport::MeshNode;
use zp_policy::PolicyEngine;
use zp_skills::{SkillMatcher, SkillRegistry};

/// Maximum tool invocation iterations before forcing a final response.
const MAX_TOOL_ITERATIONS: usize = 10;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("policy blocked: {0}")]
    PolicyBlocked(String),

    #[error("no provider available")]
    NoProvider,

    #[error("provider error: {0}")]
    ProviderError(String),

    #[error("audit error: {0}")]
    AuditError(String),

    #[error("execution error: {0}")]
    ExecutionError(String),

    #[error("internal error: {0}")]
    Internal(String),
}

/// The central orchestrator for ZeroPoint v2.
pub struct Pipeline {
    pub config: PipelineConfig,
    pub policy_engine: PolicyEngine,
    pub skill_registry: SkillRegistry,
    /// Shared audit store. Stage 3 (AUDIT-03): exactly one `AuditStore`
    /// per process, shared by the server's `AppState` and this pipeline.
    /// Opening a second handle to the same DB file is forbidden —
    /// see docs/audit-invariant.md.
    pub audit_store: Arc<Mutex<AuditStore>>,
    pub provider_pool: RwLock<ProviderPool>,
    pub episode_store: Mutex<Option<EpisodeStore>>,
    pub execution_engine: Option<ExecutionEngine>,
    pub operator_identity: OperatorIdentity,
    messages: RwLock<HashMap<ConversationId, Vec<Message>>>,

    // --- Phase 4: Mesh integration ---
    /// Optional mesh bridge for cross-agent receipt forwarding.
    /// When set, receipts and audit entries are forwarded to mesh peers
    /// after each request completes.
    mesh_bridge: Option<MeshBridge>,

    // --- Phase 6: Runtime integration ---
    /// The mesh runtime event loop, if mesh is enabled.
    /// Drives background packet dispatch and inbound envelope processing.
    mesh_runtime: Option<MeshRuntime>,

    // --- Phase 6 Step 3: Persistent mesh state ---
    /// Persistent mesh store for saving/loading peer, reputation, and delegation state.
    /// Wrapped in Mutex because rusqlite::Connection is not Sync.
    mesh_store: Option<Mutex<zp_mesh::store::MeshStore>>,
}

impl Pipeline {
    /// Initialize a new pipeline.
    ///
    /// `audit_store` must be the *single* process-wide `AuditStore` handle.
    /// Stage 3 (AUDIT-03): opening a second handle inside `Pipeline::new`
    /// was the root cause of the concurrent-append race; callers (the
    /// server's `AppState`, the CLI) own the store and pass it in.
    pub fn new(
        config: PipelineConfig,
        audit_store: Arc<Mutex<AuditStore>>,
    ) -> Result<Self, PipelineError> {
        info!("Initializing ZeroPoint pipeline");

        // Create data directory
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| PipelineError::Internal(format!("Failed to create data dir: {}", e)))?;

        let episode_path = config.data_dir.join("episodes.db");
        let episode_store = EpisodeStore::open(&episode_path).ok();

        let operator_identity = config.operator_identity.clone();

        Ok(Self {
            config,
            policy_engine: PolicyEngine::new(),
            skill_registry: SkillRegistry::new(),
            audit_store,
            provider_pool: RwLock::new(ProviderPool::new()),
            episode_store: Mutex::new(episode_store),
            execution_engine: None, // Initialized lazily via init_execution_engine()
            operator_identity,
            messages: RwLock::new(HashMap::new()),
            mesh_bridge: None,
            mesh_runtime: None,
            mesh_store: None,
        })
    }

    /// Initialize the execution engine (async — detects runtimes).
    pub async fn init_execution_engine(&mut self) -> Result<(), PipelineError> {
        let engine = ExecutionEngine::new().await.map_err(|e| {
            PipelineError::ExecutionError(format!("Failed to init execution engine: {}", e))
        })?;
        info!(
            "Execution engine initialized with {} runtimes",
            engine.available_runtimes().len()
        );
        self.execution_engine = Some(engine);
        Ok(())
    }

    /// Attach a mesh node to this pipeline for cross-agent governance.
    ///
    /// Once attached, receipts produced by the pipeline will be forwarded
    /// to mesh peers after each request completes.
    pub fn set_mesh_bridge(&mut self, bridge: MeshBridge) {
        info!(
            mesh_address = %bridge.address(),
            "Mesh bridge attached to pipeline"
        );
        self.mesh_bridge = Some(bridge);
    }

    /// Attach a mesh node with default bridge configuration.
    pub fn set_mesh_node(&mut self, node: Arc<MeshNode>) {
        self.set_mesh_bridge(MeshBridge::with_defaults(node));
    }

    /// Get a reference to the mesh bridge, if attached.
    pub fn mesh_bridge(&self) -> Option<&MeshBridge> {
        self.mesh_bridge.as_ref()
    }

    /// Check if this pipeline has mesh connectivity.
    pub fn has_mesh(&self) -> bool {
        self.mesh_bridge.is_some()
    }

    /// Get a reference to the mesh runtime, if running.
    pub fn mesh_runtime(&self) -> Option<&MeshRuntime> {
        self.mesh_runtime.as_ref()
    }

    /// Initialize the mesh subsystem from configuration.
    ///
    /// Creates a `MeshIdentity`, `MeshNode`, `MeshBridge`, and `MeshRuntime`,
    /// then spawns a background task to process inbound envelopes (receipts,
    /// delegations, etc.) from mesh peers.
    ///
    /// This is the recommended way to enable mesh networking. After calling
    /// this method, the pipeline will automatically:
    /// - Forward receipts to mesh peers after each request (step 14)
    /// - Process inbound receipts and delegations from peers
    /// - Record reputation signals for all peer interactions
    pub async fn init_mesh(&mut self, mesh_config: &MeshConfig) -> Result<(), PipelineError> {
        // 1. Create identity
        let identity = match &mesh_config.identity_secret {
            Some(secret) => MeshIdentity::from_ed25519_secret(secret).map_err(|e| {
                PipelineError::Internal(format!("Invalid mesh identity secret: {}", e))
            })?,
            None => MeshIdentity::generate(),
        };
        info!(
            mesh_address = %identity.address(),
            "Mesh identity created"
        );

        // 2. Create mesh node
        let node = Arc::new(MeshNode::new(identity));

        // 2b. Open persistent store and load previous state
        let mesh_db_path = self.config.data_dir.join("mesh.db");
        let mesh_store = zp_mesh::store::MeshStore::open(&mesh_db_path)
            .map_err(|e| PipelineError::Internal(format!("Failed to open mesh store: {}", e)))?;

        if let Err(e) = node.load_from_store(&mesh_store).await {
            warn!(
                "Failed to load mesh state from store (starting fresh): {}",
                e
            );
        } else {
            info!("Mesh state loaded from persistent store");
        }

        // 3. Connect TCP interfaces if configured
        if let Some(listen_addr) = &mesh_config.tcp_listen {
            let server = zp_mesh::tcp::TcpServerInterface::bind(listen_addr)
                .await
                .map_err(|e| {
                    PipelineError::Internal(format!(
                        "Failed to bind mesh TCP listener on {}: {}",
                        listen_addr, e
                    ))
                })?;
            info!(listen = %listen_addr, "Mesh TCP listener started");
            node.attach_interface(Arc::new(server)).await;
        }

        for peer_addr in &mesh_config.tcp_peers {
            match zp_mesh::tcp::TcpClientInterface::connect(peer_addr).await {
                Ok(client) => {
                    info!(peer = %peer_addr, "Connected to mesh TCP peer");
                    node.attach_interface(Arc::new(client)).await;
                }
                Err(e) => {
                    warn!(
                        peer = %peer_addr,
                        error = %e,
                        "Failed to connect to mesh TCP peer (will retry later)"
                    );
                }
            }
        }

        // 4. Create bridge
        let bridge_config = MeshBridgeConfig {
            forward_receipts: mesh_config.forward_receipts,
            forward_audit: mesh_config.forward_audit,
            max_forward_peers: mesh_config.max_forward_peers,
        };
        let bridge = MeshBridge::new(node.clone(), bridge_config);

        // 5. Start runtime event loop
        let runtime_config = RuntimeConfig {
            poll_interval: Duration::from_millis(mesh_config.poll_interval_ms),
            ..Default::default()
        };
        let mut runtime = MeshRuntime::start(node.clone(), runtime_config);

        // 6. Take the inbound channel and spawn the envelope processor
        if let Some(inbound_rx) = runtime.take_inbound_rx() {
            let processor_node = node.clone();
            tokio::spawn(async move {
                Self::process_inbound_envelopes(inbound_rx, processor_node).await;
            });
        }

        self.mesh_bridge = Some(bridge);
        self.mesh_runtime = Some(runtime);
        self.mesh_store = Some(Mutex::new(mesh_store));

        info!("Mesh subsystem initialized — runtime, bridge, and inbound processor active");
        Ok(())
    }

    /// Background task: consumes inbound envelopes from the MeshRuntime
    /// and dispatches them through the MeshBridge for pipeline-level processing.
    ///
    /// Handles:
    /// - Receipt envelopes → validate + reputation signal + store
    /// - Delegation envelopes → already stored by MeshNode, log here
    /// - Guard/Announce envelopes → log for future processing
    async fn process_inbound_envelopes(
        mut inbound_rx: tokio::sync::mpsc::Receiver<zp_mesh::runtime::InboundEnvelope>,
        node: Arc<MeshNode>,
    ) {
        info!("Inbound envelope processor started");
        let mut receipts_processed: u64 = 0;
        let mut delegations_processed: u64 = 0;
        let mut other_processed: u64 = 0;

        while let Some(inbound) = inbound_rx.recv().await {
            match inbound.envelope.envelope_type {
                EnvelopeType::Receipt => {
                    // Extract and process the compact receipt
                    match inbound.envelope.extract_receipt() {
                        Ok(compact) => {
                            let success = compact.st == "success";
                            let receipt_id = compact.id.clone();

                            // Record reputation signal for the sender
                            let signal = zp_mesh::reputation::signal_from_receipt(
                                &receipt_id,
                                success,
                                Utc::now(),
                            );
                            node.record_reputation_signal(&inbound.sender_hash, signal)
                                .await;

                            receipts_processed += 1;
                            debug!(
                                receipt_id = %receipt_id,
                                sender = %hex::encode(inbound.sender_hash),
                                success = success,
                                interface = %inbound.interface_name,
                                total = receipts_processed,
                                "Processed inbound receipt"
                            );
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                sender = %hex::encode(inbound.sender_hash),
                                "Failed to extract receipt from inbound envelope"
                            );
                        }
                    }
                }

                EnvelopeType::Delegation => {
                    // Delegation already stored by MeshNode in the runtime dispatcher.
                    // Here we record a positive reputation signal for delegation sharing.
                    let signal = zp_mesh::reputation::ReputationSignal {
                        category: zp_mesh::reputation::SignalCategory::DelegationChain,
                        polarity: zp_mesh::reputation::SignalPolarity::Positive,
                        timestamp: Utc::now(),
                        evidence_id: "inbound_delegation".to_string(),
                        detail: None,
                    };
                    node.record_reputation_signal(&inbound.sender_hash, signal)
                        .await;

                    delegations_processed += 1;
                    debug!(
                        sender = %hex::encode(inbound.sender_hash),
                        total = delegations_processed,
                        "Processed inbound delegation"
                    );
                }

                EnvelopeType::ReceiptChain => {
                    // Receipt chains contain multiple receipts — process each
                    // For now, record a single positive signal for the exchange
                    let signal =
                        zp_mesh::reputation::signal_from_receipt("receipt_chain", true, Utc::now());
                    node.record_reputation_signal(&inbound.sender_hash, signal)
                        .await;
                    other_processed += 1;
                    debug!(
                        sender = %hex::encode(inbound.sender_hash),
                        "Processed inbound receipt chain"
                    );
                }

                EnvelopeType::GuardRequest | EnvelopeType::GuardResponse => {
                    other_processed += 1;
                    debug!(
                        envelope_type = ?inbound.envelope.envelope_type,
                        sender = %hex::encode(inbound.sender_hash),
                        "Received guard envelope (future processing)"
                    );
                }

                EnvelopeType::AgentAnnounce => {
                    other_processed += 1;
                    info!(
                        sender = %hex::encode(inbound.sender_hash),
                        interface = %inbound.interface_name,
                        "Agent announce received from mesh peer"
                    );
                }

                _ => {
                    other_processed += 1;
                    debug!(
                        envelope_type = ?inbound.envelope.envelope_type,
                        "Inbound envelope type handled elsewhere"
                    );
                }
            }
        }

        info!(
            receipts = receipts_processed,
            delegations = delegations_processed,
            other = other_processed,
            "Inbound envelope processor stopped"
        );
    }

    /// Shut down the mesh subsystem gracefully.
    pub fn shutdown_mesh(&mut self) {
        if let Some(runtime) = &self.mesh_runtime {
            runtime.shutdown();
            info!("Mesh runtime shutdown signaled");
        }
    }

    /// Save mesh state to persistent storage.
    ///
    /// Call this periodically or before shutdown to persist peer,
    /// reputation, delegation, attestation, and policy agreement state.
    #[allow(clippy::await_holding_lock)]
    pub async fn save_mesh_state(&self) -> Result<(), PipelineError> {
        let store_mutex = match &self.mesh_store {
            Some(s) => s,
            None => return Ok(()), // No mesh, nothing to save
        };

        let bridge = match &self.mesh_bridge {
            Some(b) => b,
            None => return Ok(()),
        };

        let store = store_mutex
            .lock()
            .map_err(|e| PipelineError::Internal(format!("Mesh store lock poisoned: {}", e)))?;

        bridge
            .node()
            .save_to_store(&store)
            .await
            .map_err(|e| PipelineError::Internal(format!("Failed to save mesh state: {}", e)))?;

        info!("Mesh state saved to persistent store");
        Ok(())
    }

    /// Check if the mesh store is initialized.
    pub fn mesh_store(&self) -> Option<&Mutex<zp_mesh::store::MeshStore>> {
        self.mesh_store.as_ref()
    }

    /// Handle a request through the full pipeline.
    ///
    /// Flow: policy → skill matching → capabilities → LLM → tool loop → audit → episode
    pub async fn handle(&self, request: Request) -> Result<Response, PipelineError> {
        let start_time = std::time::Instant::now();
        info!(
            "Processing request for conversation {:?}",
            request.conversation_id
        );

        // 1. Build policy context
        let policy_context = PolicyContext {
            action: ActionType::Chat,
            trust_tier: self.config.trust_tier,
            channel: request.channel.clone(),
            conversation_id: request.conversation_id.clone(),
            skill_ids: vec![],
            tool_names: vec![],
            mesh_context: None,
        };

        // 2. Evaluate policy
        let decision = self.policy_engine.evaluate(&policy_context);
        debug!("Policy decision: {:?}", decision);

        if decision.is_blocked() {
            let reason = match &decision {
                PolicyDecision::Block { reason, .. } => reason.clone(),
                _ => "Blocked by policy".to_string(),
            };
            self.log_audit(
                ActorId::System("policy".to_string()),
                AuditAction::SystemEvent {
                    event: format!("request_blocked: {}", reason),
                },
                &request.conversation_id,
                &decision,
            );
            return Err(PipelineError::PolicyBlocked(reason));
        }

        // 3. Auto-approve Warn/Review in Phase 1
        if decision.needs_interaction() {
            debug!("Policy returned Warn/Review; auto-approving in Phase 1");
        }

        // 4. Match skills
        let matched_skill_ids = SkillMatcher::match_request(&self.skill_registry, &request.content);
        debug!("Matched {} skills", matched_skill_ids.len());

        // 5. Build capabilities
        let skill_id_strings: Vec<String> = matched_skill_ids.iter().map(|s| s.0.clone()).collect();
        let capabilities = self
            .policy_engine
            .capabilities_for(&policy_context, &skill_id_strings);

        // 6. Determine model preference
        let model_preference = self.policy_engine.model_for(&policy_context);

        // 7. Build prompt
        let history = self.get_history(&request.conversation_id).await;
        let completion_request = PromptBuilder::build(
            &self.operator_identity,
            &capabilities,
            &history,
            &request.content,
        );

        // 8. Select provider and call LLM
        let pool = self.provider_pool.read().await;
        let provider = pool.select(&model_preference).map_err(|e| {
            error!("No provider available: {}", e);
            PipelineError::NoProvider
        })?;

        let mut completion = provider.complete(&completion_request).await.map_err(|e| {
            error!("Provider error: {}", e);
            PipelineError::ProviderError(e.to_string())
        })?;

        // 9. Tool invocation loop
        // If the LLM returns tool_calls, execute them, feed results back, and repeat
        // until the LLM responds with content only (no more tool_calls) or we hit the limit.
        let mut all_tool_calls: Vec<ToolCall> = Vec::new();
        let mut iteration = 0;
        let mut continuation_messages = completion_request.messages.clone();

        while !completion.tool_calls.is_empty() && iteration < MAX_TOOL_ITERATIONS {
            iteration += 1;
            debug!(
                "Tool invocation iteration {} with {} tool calls",
                iteration,
                completion.tool_calls.len()
            );

            // Add assistant message (the tool-calling response)
            continuation_messages.push(ChatMessage::assistant(completion.content.clone()));

            // Execute each tool call and collect results
            for tc in &completion.tool_calls {
                let tool_result = self.execute_tool_call(&tc.tool_name, &tc.arguments).await;

                let (success, output_value, receipt) = match &tool_result {
                    Ok((output, exec_receipt)) => (
                        true,
                        serde_json::json!({ "output": output }),
                        exec_receipt.as_ref().map(|r| {
                            zp_receipt::Receipt::execution("zp-pipeline")
                                .status(if r.exit_code == 0 {
                                    ReceiptStatus::Success
                                } else {
                                    ReceiptStatus::Failed
                                })
                                .trust_grade(zp_receipt::TrustGrade::C) // Sandboxed execution
                                .runtime(&r.runtime)
                                .action(ReceiptAction::code_execution(&r.runtime, r.exit_code))
                                .timing(
                                    r.completed_at
                                        - chrono::Duration::milliseconds(r.timing.wall_ms as i64),
                                    r.completed_at,
                                )
                                .extension(
                                    "dev.zeropoint.legacy",
                                    serde_json::json!({
                                        "input_hash": r.input_hash,
                                        "output_hash": r.output_hash,
                                        "receipt_hash": r.receipt_hash,
                                    }),
                                )
                                .finalize()
                        }),
                    ),
                    Err(err_msg) => (false, serde_json::json!({ "error": err_msg }), None),
                };

                all_tool_calls.push(ToolCall {
                    tool_name: tc.tool_name.clone(),
                    arguments: tc.arguments.clone(),
                    result: Some(ToolResult {
                        success,
                        output: output_value.clone(),
                        receipt,
                    }),
                });

                // Build tool result message for LLM continuation
                let result_text = serde_json::to_string_pretty(&output_value).unwrap_or_default();
                continuation_messages.push(ChatMessage::tool(format!(
                    "[{}] {}",
                    tc.tool_name, result_text
                )));

                // Audit each tool execution
                self.log_audit(
                    ActorId::System("execution-engine".to_string()),
                    AuditAction::SystemEvent {
                        event: format!(
                            "tool_executed: {} success={} iteration={}",
                            tc.tool_name, success, iteration,
                        ),
                    },
                    &request.conversation_id,
                    &decision,
                );
            }

            // Call LLM again with tool results
            let continuation = CompletionRequest::new(
                completion_request.system_prompt.clone(),
                continuation_messages.clone(),
                completion_request.tools.clone(),
            );

            completion = provider.complete(&continuation).await.map_err(|e| {
                error!("Provider error during tool loop: {}", e);
                PipelineError::ProviderError(e.to_string())
            })?;
        }

        if iteration > 0 {
            info!(
                "Tool invocation loop completed after {} iterations",
                iteration
            );
        }

        // 10. Build response
        let response = Response {
            id: MessageId::new(),
            conversation_id: request.conversation_id.clone(),
            content: completion.content.clone(),
            tool_calls: all_tool_calls,
            model_used: completion.model.clone(),
            timestamp: Utc::now(),
        };

        // 11. Log to audit
        self.log_audit(
            ActorId::Operator,
            AuditAction::ResponseGenerated {
                model: completion.model.clone(),
                content_hash: blake3::hash(completion.content.as_bytes())
                    .to_hex()
                    .to_string(),
            },
            &request.conversation_id,
            &decision,
        );

        // 12. Store conversation history
        {
            let mut store = self.messages.write().await;
            let history = store.entry(request.conversation_id.clone()).or_default();
            history.push(Message {
                id: request.id.clone(),
                conversation_id: request.conversation_id.clone(),
                role: MessageRole::User,
                content: request.content.clone(),
                tool_calls: vec![],
                timestamp: request.timestamp,
            });
            history.push(Message {
                id: response.id.clone(),
                conversation_id: request.conversation_id.clone(),
                role: MessageRole::Operator,
                content: completion.content.clone(),
                tool_calls: vec![],
                timestamp: Utc::now(),
            });
        }

        // 13. Record episode (best-effort)
        self.record_episode(
            &request,
            &response,
            &decision,
            &skill_id_strings,
            &completion.model,
            start_time.elapsed().as_millis() as u64,
        );

        // 14. Forward receipt to mesh peers (best-effort, Phase 4)
        if let Some(bridge) = &self.mesh_bridge {
            let mesh_receipt = zp_receipt::Receipt::execution("zp-pipeline")
                .status(ReceiptStatus::Success)
                .trust_grade(zp_receipt::TrustGrade::C)
                .action(ReceiptAction::code_execution("pipeline", 0))
                .timing(
                    response.timestamp - chrono::Duration::milliseconds(
                        start_time.elapsed().as_millis() as i64
                    ),
                    response.timestamp,
                )
                .extension(
                    "dev.zeropoint.pipeline",
                    serde_json::json!({
                        "conversation_id": request.conversation_id.0,
                        "model_used": completion.model,
                        "tool_calls": response.tool_calls.len(),
                        "content_hash": blake3::hash(completion.content.as_bytes()).to_hex().to_string(),
                    }),
                )
                .finalize();

            if let Err(e) = bridge.forward_receipt(&mesh_receipt).await {
                warn!(error = %e, "Failed to forward receipt to mesh (non-fatal)");
            }

            // Log the mesh forwarding to audit
            self.log_audit(
                ActorId::System("mesh-bridge".to_string()),
                AuditAction::SystemEvent {
                    event: format!("receipt_forwarded: mesh_address={}", bridge.address(),),
                },
                &request.conversation_id,
                &decision,
            );
        }

        info!("Request processed successfully");
        Ok(response)
    }

    /// Execute a single tool call.
    ///
    /// Routes to the execution engine for code execution tools, or handles
    /// built-in tools directly. Returns (output_string, optional_receipt).
    async fn execute_tool_call(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(String, Option<execution_engine::ExecutionReceipt>), String> {
        debug!("Executing tool: {} with args: {}", tool_name, arguments);

        match tool_name {
            // Code execution tools — route to execution engine
            "execute_python" | "run_python" | "python" => {
                let code = arguments.get("code")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Missing 'code' argument for python execution".to_string())?;
                self.run_code(Runtime::Python, code).await
            }
            "execute_shell" | "run_shell" | "shell" | "bash" => {
                let code = arguments.get("code")
                    .or_else(|| arguments.get("command"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Missing 'code' or 'command' argument for shell execution".to_string())?;
                self.run_code(Runtime::Shell, code).await
            }
            "execute_node" | "run_node" | "node" | "javascript" => {
                let code = arguments.get("code")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Missing 'code' argument for node execution".to_string())?;
                self.run_code(Runtime::NodeJs, code).await
            }
            // Unknown tool — return descriptive error for LLM to handle
            _ => {
                Err(format!(
                    "Tool '{}' is not yet implemented. Available tools: execute_python, execute_shell, execute_node",
                    tool_name
                ))
            }
        }
    }

    /// Run code through the execution engine.
    async fn run_code(
        &self,
        runtime: Runtime,
        code: &str,
    ) -> Result<(String, Option<execution_engine::ExecutionReceipt>), String> {
        let engine = self
            .execution_engine
            .as_ref()
            .ok_or_else(|| "Execution engine not initialized".to_string())?;

        let exec_request = ExecRequest {
            runtime,
            code: code.to_string(),
            agent_id: "pipeline".to_string(),
            ..Default::default()
        };

        let outcome = engine
            .execute(exec_request)
            .await
            .map_err(|e| format!("Execution failed: {}", e))?;

        // Combine stdout and stderr for the tool result
        let mut output = outcome.stdout;
        if !outcome.stderr.is_empty() {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str("[stderr] ");
            output.push_str(&outcome.stderr);
        }
        if outcome.timed_out {
            output.push_str("\n[timed out]");
        }

        Ok((output, Some(outcome.receipt)))
    }

    /// Record an episode in the learning store (best-effort).
    fn record_episode(
        &self,
        request: &Request,
        response: &Response,
        decision: &PolicyDecision,
        active_skills: &[String],
        model_used: &str,
        duration_ms: u64,
    ) {
        let store_guard = match self.episode_store.lock() {
            Ok(guard) => guard,
            Err(e) => {
                warn!("Failed to lock episode store: {}", e);
                return;
            }
        };

        let store = match store_guard.as_ref() {
            Some(s) => s,
            None => return, // No episode store configured
        };

        let outcome = if response
            .tool_calls
            .iter()
            .all(|tc| tc.result.as_ref().is_none_or(|r| r.success))
        {
            Outcome::Success
        } else {
            let failed: Vec<String> = response
                .tool_calls
                .iter()
                .filter(|tc| tc.result.as_ref().is_some_and(|r| !r.success))
                .map(|tc| tc.tool_name.clone())
                .collect();
            let completed: Vec<String> = response
                .tool_calls
                .iter()
                .filter(|tc| tc.result.as_ref().is_some_and(|r| r.success))
                .map(|tc| tc.tool_name.clone())
                .collect();
            Outcome::Partial { completed, failed }
        };

        let episode = Episode {
            id: EpisodeId::new(),
            conversation_id: request.conversation_id.clone(),
            timestamp: Utc::now(),
            request_hash: blake3::hash(request.content.as_bytes())
                .to_hex()
                .to_string(),
            request_category: categorize_request(&request.content),
            tools_used: response.tool_calls.clone(),
            active_skills: active_skills.to_vec(),
            model_used: model_used.to_string(),
            outcome,
            feedback: None,
            duration_ms,
            policy_decisions: vec![decision.clone()],
        };

        if let Err(e) = store.record(&episode) {
            warn!("Failed to record episode: {}", e);
        } else {
            debug!("Recorded episode {} ({}ms)", episode.id.0, duration_ms);
        }
    }

    /// Get conversation history.
    pub async fn get_history(&self, conversation_id: &ConversationId) -> Vec<Message> {
        let store = self.messages.read().await;
        store.get(conversation_id).cloned().unwrap_or_default()
    }

    /// Create a new conversation.
    pub fn new_conversation(&self) -> ConversationId {
        ConversationId::new()
    }

    /// Log to audit trail (best-effort).
    fn log_audit(
        &self,
        actor: ActorId,
        action: AuditAction,
        conversation_id: &ConversationId,
        policy_decision: &PolicyDecision,
    ) {
        let mut store = match self.audit_store.lock() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to lock audit store: {}", e);
                return;
            }
        };
        // AUDIT-03: store seals atomically inside BEGIN IMMEDIATE.
        let unsealed = UnsealedEntry::new(
            actor,
            action,
            conversation_id.clone(),
            policy_decision.clone(),
            "default-gate",
        );
        if let Err(e) = store.append(unsealed) {
            warn!("Failed to write audit entry: {}", e);
        }
    }
}

/// Simple request categorization based on keywords.
/// This is a Phase 1 heuristic — the learning loop will refine this over time.
fn categorize_request(content: &str) -> String {
    let lower = content.to_lowercase();
    if lower.contains("code") || lower.contains("program") || lower.contains("function") {
        "coding".to_string()
    } else if lower.contains("analyze") || lower.contains("analysis") || lower.contains("data") {
        "analysis".to_string()
    } else if lower.contains("write") || lower.contains("draft") || lower.contains("edit") {
        "writing".to_string()
    } else if lower.contains("explain") || lower.contains("what is") || lower.contains("how") {
        "knowledge".to_string()
    } else {
        "general".to_string()
    }
}
