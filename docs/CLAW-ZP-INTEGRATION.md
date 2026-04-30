# Claw-Code-Rust ↔ ZeroPoint Integration Map

> **Purpose**: Pre-map every integration seam between claw-code-rust (agent runtime) and ZeroPoint (governance infrastructure) so that when implementations land, they plug in with minimal friction.
>
> **Date**: 2026-04-01
> **Status**: Phases 1–5 complete — all six integration seams implemented

---

## 1. Executive Summary

Claw-code-rust is a ~2,200-line Rust port of the Claude Code agent runtime, organized into 9 crates with clean trait boundaries. ZeroPoint provides cryptographic governance primitives: append-only audit chains, sovereignty-backed identity, capability verification, and execution receipts.

The integration thesis: **every agent decision becomes a governance event, every tool execution produces a receipt, and every session is sovereignty-rooted**. Claw's trait boundaries are the exact insertion points for ZP's governance layer.

**Six integration seams**, ordered by implementation priority:

| # | Seam | Claw Side | ZP Side | New Crate |
|---|------|-----------|---------|-----------|
| 1 | Permission → Governance | `PermissionPolicy` trait | `GovernanceEvent` + `AuditStore` | `agent-zp-permissions` |
| 2 | Tool Execution → Receipts | `Tool::execute()` + `ToolOrchestrator` | `ExecutionReceipt` + `AuditStore` | `agent-zp-tools` (wrapper) |
| 3 | Provider → Audit Trail | `ModelProvider` trait | `AuditStore` + `Capability` resolution | `agent-zp-provider` |
| 4 | Session → Sovereignty | `SessionState` + `ToolContext` | `SovereigntyProvider` + Genesis keys | `agent-zp-session` |
| 5 | Tool Registry → Capability Verification | `ToolRegistry` | `ToolManifest` + `VerificationConfig` | extend `agent-zp-tools` |
| 6 | Task Lifecycle → Tool Chain | `TaskManager` | `ToolChainState` + `emit_tool_receipt()` | `agent-zp-tasks` |

---

## 2. Seam 1: Permission → Governance

**The most natural seam.** Claw's `PermissionPolicy` is async and returns `Allow/Deny/Ask`. ZP's `GovernanceEvent` records every policy evaluation with actor, context, and decision — hash-linked into the audit chain.

### Claw interface
```rust
#[async_trait]
pub trait PermissionPolicy: Send + Sync {
    async fn check(&self, request: &PermissionRequest) -> PermissionDecision;
}

pub struct PermissionRequest {
    pub tool_name: String,
    pub resource: ResourceKind,  // FileRead, FileWrite, ShellExec, Network, Custom
    pub description: String,
    pub target: Option<String>,
}
```

### ZP interface
```rust
pub struct GovernanceEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: GovernanceEventType,
    pub actor: GovernanceActor,
    pub action_context: ActionContext,
    pub decision: GovernanceDecision,
    pub receipt_id: Option<String>,
    pub audit_hash: Option<String>,
}
```

### Integration: `ZpPermissionPolicy`

```rust
// crate: agent-zp-permissions
pub struct ZpPermissionPolicy {
    inner: Arc<dyn PermissionPolicy>,       // existing RuleBasedPolicy
    audit_store: Arc<Mutex<AuditStore>>,
    agent_id: String,                        // sovereignty-derived identity
}

#[async_trait]
impl PermissionPolicy for ZpPermissionPolicy {
    async fn check(&self, request: &PermissionRequest) -> PermissionDecision {
        // 1. Delegate to inner policy for actual decision
        let decision = self.inner.check(request).await;

        // 2. Map to GovernanceEvent
        let event = GovernanceEvent::policy_evaluation(
            GovernanceActor::Agent(self.agent_id.clone()),
            ActionContext::from_permission_request(request),
            match &decision {
                PermissionDecision::Allow => GovernanceDecision::Approved,
                PermissionDecision::Deny { reason } => GovernanceDecision::Denied(reason.clone()),
                PermissionDecision::Ask { .. } => GovernanceDecision::Deferred,
            },
        );

        // 3. Append to audit chain
        self.audit_store.lock().unwrap().append(event.into());

        decision
    }
}
```

### Mapping: ResourceKind → Capability

| Claw `ResourceKind` | ZP `Capability` | Notes |
|---------------------|-----------------|-------|
| `FileRead` | — (local resource) | Maps to `ActionContext::FileAccess` |
| `FileWrite` | — (local resource) | Maps to `ActionContext::FileAccess` |
| `ShellExec` | `CodeExecution` | ZP Guard integration point |
| `Network` | `WebSearch` / `AuthApi` | Depends on target |
| `Custom(String)` | Any `Capability` variant | Custom mapping table |

### Key decisions
- **Wrapper, not fork**: `ZpPermissionPolicy` wraps any existing `PermissionPolicy` impl. The inner policy makes the actual decision; ZP records it.
- **ZP Guard hook**: When `ResourceKind::ShellExec`, optionally run the command through `zp guard` evaluation before the inner policy. This connects Claw's permission layer to ZP's shell safety analysis.
- **Async audit**: The `AuditStore::append()` is currently synchronous (SQLite). For the hot path, consider a channel-based async writer (mpsc → dedicated writer thread) to avoid blocking the permission check.

---

## 3. Seam 2: Tool Execution → Receipts

Every tool invocation produces an `ExecutionReceipt` with input hash, output hash, timing, and resource metrics. This is the core audit trail for agent actions.

### Claw interface
```rust
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    async fn execute(&self, ctx: &ToolContext, input: serde_json::Value) -> Result<ToolOutput>;
    fn is_read_only(&self) -> bool;
}

pub struct ToolOutput {
    pub content: String,
    pub is_error: bool,
    pub metadata: Option<serde_json::Value>,
}
```

### ZP interface
```rust
pub struct ExecutionReceipt {
    pub receipt_id: Uuid,
    pub request_id: String,
    pub agent_id: String,
    pub runtime: String,
    pub input_hash: String,     // BLAKE3 of input
    pub output_hash: String,    // BLAKE3 of output
    pub exit_code: i32,
    pub success: bool,
    pub timing: ExecutionTiming,
    pub resources: ResourceUsage,
    pub receipt_hash: String,   // self-hash for chain integrity
}
```

### Integration: `ReceiptEmittingTool` wrapper

```rust
// crate: agent-zp-tools
pub struct ReceiptEmittingTool {
    inner: Arc<dyn Tool>,
    audit_store: Arc<Mutex<AuditStore>>,
    agent_id: String,
}

#[async_trait]
impl Tool for ReceiptEmittingTool {
    fn name(&self) -> &str { self.inner.name() }
    fn description(&self) -> &str { self.inner.description() }
    fn input_schema(&self) -> serde_json::Value { self.inner.input_schema() }
    fn is_read_only(&self) -> bool { self.inner.is_read_only() }

    async fn execute(&self, ctx: &ToolContext, input: serde_json::Value) -> Result<ToolOutput> {
        let request_id = Uuid::new_v4().to_string();
        let input_hash = blake3::hash(serde_json::to_vec(&input)?.as_slice()).to_hex().to_string();
        let start = Instant::now();

        // Execute the actual tool
        let result = self.inner.execute(ctx, input).await;
        let elapsed = start.elapsed();

        // Build receipt regardless of success/failure
        let (output_hash, exit_code, success) = match &result {
            Ok(output) => (
                blake3::hash(output.content.as_bytes()).to_hex().to_string(),
                if output.is_error { 1 } else { 0 },
                !output.is_error,
            ),
            Err(e) => (
                blake3::hash(e.to_string().as_bytes()).to_hex().to_string(),
                -1,
                false,
            ),
        };

        let receipt = ExecutionReceipt {
            receipt_id: Uuid::new_v4(),
            request_id,
            agent_id: self.agent_id.clone(),
            runtime: format!("claw/{}", self.inner.name()),
            input_hash,
            output_hash,
            exit_code,
            success,
            timing: ExecutionTiming {
                wall_ms: elapsed.as_millis() as u64,
                queue_ms: 0,
                first_output_ms: None,
            },
            resources: ResourceUsage {
                peak_memory_bytes: None,
                stdout_bytes: result.as_ref().map(|o| o.content.len()).unwrap_or(0),
                stderr_bytes: 0,
                files_written: 0,  // BashTool/FileWriteTool could populate this
                bytes_written: 0,
            },
            completed_at: Utc::now(),
            receipt_hash: String::new(), // computed below
        };

        let receipt = receipt.with_computed_hash();

        // Also emit as tool chain event
        emit_tool_receipt(
            &self.audit_store,
            &format!("tool.{}.executed", self.inner.name()),
            Some(&serde_json::to_string(&receipt)?),
        );

        result
    }
}
```

### ToolOrchestrator integration

The `ToolOrchestrator` already batches concurrent read-only tools and sequences write tools. The receipt wrapper goes **inside** the orchestrator's dispatch — each individual tool call gets its own receipt, not just the batch.

```rust
// In agent-zp-tools: wrap the entire registry
pub fn wrap_registry_with_receipts(
    registry: ToolRegistry,
    audit_store: Arc<Mutex<AuditStore>>,
    agent_id: String,
) -> ToolRegistry {
    let mut wrapped = ToolRegistry::new();
    for tool in registry.all() {
        wrapped.register(Arc::new(ReceiptEmittingTool {
            inner: Arc::clone(tool),
            audit_store: Arc::clone(&audit_store),
            agent_id: agent_id.clone(),
        }));
    }
    wrapped
}
```

### Resource tracking for specific tools

| Tool | Extra `ResourceUsage` fields |
|------|------------------------------|
| `BashTool` | `stdout_bytes`, `stderr_bytes`, `exit_code` from process |
| `FileWriteTool` | `files_written: 1`, `bytes_written` from content length |
| `FileReadTool` | Read-only, minimal resources |

Consider a `ReceiptEnrichment` trait that specific tools can implement to provide richer resource data beyond what the generic wrapper captures.

---

## 4. Seam 3: Provider → Audit Trail

LLM provider calls are the most expensive agent operations. Every request/response should be receipt-tracked for cost accounting, latency monitoring, and audit compliance.

### Claw interface
```rust
#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn complete(&self, request: ModelRequest) -> Result<ModelResponse>;
    async fn stream(&self, request: ModelRequest)
        -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>>>;
    fn name(&self) -> &str;
}
```

### Integration: `AuditedModelProvider`

```rust
pub struct AuditedModelProvider {
    inner: Arc<dyn ModelProvider>,
    audit_store: Arc<Mutex<AuditStore>>,
    agent_id: String,
}

#[async_trait]
impl ModelProvider for AuditedModelProvider {
    async fn complete(&self, request: ModelRequest) -> Result<ModelResponse> {
        let start = Instant::now();
        let model = request.model.clone();
        let input_hash = blake3::hash(
            serde_json::to_vec(&request)?.as_slice()
        ).to_hex().to_string();

        let result = self.inner.complete(request).await;
        let elapsed = start.elapsed();

        // Emit audit entry for the provider call
        let (output_hash, success) = match &result {
            Ok(resp) => (
                blake3::hash(serde_json::to_vec(resp)?.as_slice()).to_hex().to_string(),
                true,
            ),
            Err(e) => (blake3::hash(e.to_string().as_bytes()).to_hex().to_string(), false),
        };

        // Emit as governance event (capability usage)
        emit_tool_receipt(
            &self.audit_store,
            "provider.llm.complete",
            Some(&serde_json::json!({
                "model": model,
                "input_hash": input_hash,
                "output_hash": output_hash,
                "wall_ms": elapsed.as_millis(),
                "success": success,
                "input_tokens": result.as_ref().map(|r| r.usage.input_tokens).unwrap_or(0),
                "output_tokens": result.as_ref().map(|r| r.usage.output_tokens).unwrap_or(0),
            }).to_string()),
        );

        result
    }

    async fn stream(&self, request: ModelRequest)
        -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>>>
    {
        // Wrap the stream to capture the final MessageDone event for receipting
        let inner_stream = self.inner.stream(request).await?;
        Ok(Box::pin(ReceiptCapturingStream::new(
            inner_stream,
            Arc::clone(&self.audit_store),
            self.agent_id.clone(),
        )))
    }

    fn name(&self) -> &str { self.inner.name() }
}
```

### Capability resolution for provider selection

ZP's `Capability` enum maps to model selection:

| ZP `Capability` | Provider Resolution |
|-----------------|-------------------|
| `ReasoningLlm` | o3, Claude Opus 4, Gemini 2.5 Pro |
| `FastLlm` | GPT-4.1-mini, Claude Haiku, Gemini Flash |
| `CodeLlm` | Claude Sonnet 4, GPT-4.1 |
| `LongContextLlm` | Gemini 2.5 Pro (1M), Claude Sonnet 4 (200K) |
| `Vision` | Any vision-capable model |

This connects to Ember's `server-providers.yml` concept — the capability requirements of an agent task determine which provider gets selected, and ZP's `CapabilityResolution` verifies the provider actually satisfies the requirement.

---

## 5. Seam 4: Session → Sovereignty

The most architecturally significant seam. Agent sessions should be sovereignty-rooted: the agent's identity derives from the user's Genesis key, and session tokens are cryptographically signed.

### Current state

Claw's `SessionState` has a plain `String` id:
```rust
pub struct SessionState {
    pub id: String,           // currently: UUID
    pub config: SessionConfig,
    pub messages: Vec<Message>,
    pub cwd: PathBuf,
    // ...
}
```

Claw's `ToolContext` carries session_id:
```rust
pub struct ToolContext {
    pub cwd: PathBuf,
    pub permissions: Arc<dyn PermissionPolicy>,
    pub session_id: String,   // currently: same UUID
}
```

### Target state

```rust
pub struct ZpToolContext {
    pub cwd: PathBuf,
    pub permissions: Arc<dyn PermissionPolicy>,  // ZpPermissionPolicy wrapper
    pub session_id: String,                       // sovereignty-derived
    pub audit_store: Arc<Mutex<AuditStore>>,      // shared audit chain
    pub agent_identity: AgentIdentity,            // signed by Genesis key
}

pub struct AgentIdentity {
    pub agent_id: String,                         // derived from Genesis pubkey
    pub session_token: Vec<u8>,                   // Ed25519 signature over session params
    pub sovereignty_mode: SovereigntyMode,        // which provider authenticated
    pub created_at: DateTime<Utc>,
}
```

### Session creation flow

```
1. User launches agent session
2. SovereigntyProvider::verify_presence() → confirms user is present
3. SovereigntyProvider::load_secret() → unlocks Genesis seed
4. Derive session keypair: Ed25519::from_seed(blake3(genesis_seed + session_nonce))
5. Sign session token: sign(session_id + timestamp + agent_config_hash)
6. Create AgentIdentity with signed token
7. All subsequent receipts reference this agent_id
8. Receipt hashes chain back to sovereignty-verified identity
```

### Why this matters

Without sovereignty-rooted sessions, the audit chain proves "something happened" but not "who authorized it." With sovereignty, every receipt chain terminates at a biometric/hardware verification event. This is the core ZP value proposition for agent governance.

### Implementation notes
- **Don't break sessionless mode**: The sovereignty layer should be optional. `ToolContext` can carry `Option<AgentIdentity>` for ungoverned sessions.
- **Session rotation**: Long-running agent sessions should periodically re-verify sovereignty (configurable interval). This prevents "authenticate once, act forever" attacks.
- **Multi-agent**: When agents spawn sub-agents, the parent's `AgentIdentity` should be included as a delegation chain in the child's context.

---

## 6. Seam 5: Tool Registry → Capability Verification

When tools register with the agent, ZP should verify they satisfy declared capabilities through the existing preflight/verification pipeline.

### Current state

Claw's `ToolRegistry` is a simple HashMap:
```rust
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
}
```

### Target state

```rust
pub struct VerifiedToolRegistry {
    inner: ToolRegistry,
    manifests: HashMap<String, ToolManifest>,
    verification_results: HashMap<String, CapabilityResolution>,
}

impl VerifiedToolRegistry {
    pub fn register_and_verify(
        &mut self,
        tool: Arc<dyn Tool>,
        manifest: ToolManifest,
        audit_store: &Mutex<AuditStore>,
    ) -> Result<(), VerificationError> {
        // 1. Register the tool
        self.inner.register(Arc::clone(&tool));

        // 2. Run capability verification probes
        let resolution = resolve_capabilities(&manifest)?;

        // 3. Emit verification receipt
        emit_tool_receipt(
            audit_store,
            &format!("tool.{}.verified", tool.name()),
            Some(&serde_json::to_string(&resolution)?),
        );

        // 4. Store results
        self.manifests.insert(tool.name().to_string(), manifest);
        self.verification_results.insert(tool.name().to_string(), resolution);

        Ok(())
    }

    /// Only return tools that passed verification
    pub fn verified_tools(&self) -> Vec<&Arc<dyn Tool>> {
        self.inner.all().into_iter().filter(|t| {
            self.verification_results.get(t.name())
                .map(|r| r.is_satisfied())
                .unwrap_or(false)
        }).collect()
    }
}
```

### Mapping: Claw tools → ZP capabilities

| Claw Tool | Declared Capabilities | Verification Probe |
|-----------|----------------------|-------------------|
| `BashTool` | `CodeExecution` | `which bash` returns 0 |
| `FileReadTool` | — (local) | cwd exists and is readable |
| `FileWriteTool` | — (local) | cwd exists and is writable |
| Future: `WebSearchTool` | `WebSearch` | HTTP probe to search endpoint |
| Future: `McpTool` | Per-MCP manifest | MCP server responds to `initialize` |

This connects directly to ZP's existing `zp configure auto --path` flow. When Claw registers tools, ZP runs the same verification probes it uses for any managed tool.

---

## 7. Seam 6: Task Lifecycle → Tool Chain

Claw's `TaskManager` tracks background task state. ZP's `ToolChainState` tracks tool lifecycle through the audit chain. These should be unified.

### Mapping: TaskState → ToolPhase

| Claw `TaskState` | ZP `ToolPhase` | Chain Event |
|------------------|----------------|-------------|
| `Pending` | `Configured` | `task.{id}.configured` |
| `Running` | `Running` | `task.{id}.started` |
| `Completed` | `Ready` | `task.{id}.completed` |
| `Failed` | `Crashed` | `task.{id}.failed` |
| `Cancelled` | `Stopped` | `task.{id}.cancelled` |

### Integration

```rust
pub struct AuditedTaskManager {
    inner: TaskManager,
    audit_store: Arc<Mutex<AuditStore>>,
}

impl AuditedTaskManager {
    pub async fn register(&self, info: TaskInfo) {
        self.inner.register(info.clone()).await;
        emit_tool_receipt(
            &self.audit_store,
            &format!("task.{}.configured", info.id),
            Some(&info.name),
        );
    }

    pub async fn update_state(&self, task_id: &str, state: TaskState) {
        self.inner.update_state(task_id, state.clone()).await;
        let event = match state {
            TaskState::Running => "started",
            TaskState::Completed => "completed",
            TaskState::Failed => "failed",
            TaskState::Cancelled => "cancelled",
            _ => "updated",
        };
        emit_tool_receipt(
            &self.audit_store,
            &format!("task.{}.{}", task_id, event),
            None,
        );
    }
}
```

### `derive_system_state()` integration

ZP's `derive_system_state()` is a pure function that rebuilds the entire system state from the audit chain. When Claw tasks emit lifecycle events to the audit chain, they automatically appear in the ZP dashboard's system state view. No additional wiring needed — the audit chain is the source of truth.

---

## 8. Dependency Graph

### New crates

```
agent-zp-permissions  ← agent-permissions + zp-audit + zp-core (governance)
agent-zp-tools        ← agent-tools + zp-audit + execution-engine
agent-zp-provider     ← agent-provider + zp-audit + zp-engine (capability)
agent-zp-session      ← agent-core + zp-keys (sovereignty) + zp-audit
agent-zp-tasks        ← agent-tasks + zp-audit + zp-server (tool_chain)
```

### Layered architecture

```
┌──────────────────────────────────────────────────┐
│                   claude-cli                      │
│           (REPL + session orchestration)          │
├──────────────────────────────────────────────────┤
│                 agent-zp-session                  │
│      (sovereignty-rooted session creation)        │
├──────────┬───────────┬───────────┬───────────────┤
│ agent-zp │ agent-zp  │ agent-zp  │  agent-zp     │
│ -perms   │ -tools    │ -provider │  -tasks       │
│          │           │           │               │
│ wraps    │ wraps     │ wraps     │  wraps        │
│ perms    │ tools     │ provider  │  tasks        │
│ + audit  │ + receipt │ + audit   │  + chain      │
├──────────┴───────────┴───────────┴───────────────┤
│              ZeroPoint Governance                 │
│  ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │ AuditSt │ │ Executn  │ │ Sovereignty       │  │
│  │ ore     │ │ Receipt  │ │ Provider          │  │
│  └─────────┘ └──────────┘ └───────────────────┘  │
│  ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │ Govrnce │ │ Capablty │ │ Tool Chain        │  │
│  │ Event   │ │ Resoln   │ │ State             │  │
│  └─────────┘ └──────────┘ └───────────────────┘  │
└──────────────────────────────────────────────────┘
```

---

## 9. Implementation Order

### Phase 1: Audit Foundation ✅ COMPLETE
All implemented in a single `agent-zp` crate with `AuditSink` trait (dependency-inverted — no cross-workspace deps).

1. **`ReceiptEmittingTool`** — wraps any `Tool` impl, emits `ExecutionReceipt` + `GovernanceRecord` per call. ✅
2. **`ZpPermissionPolicy`** — wraps any `PermissionPolicy`, emits `GovernanceRecord` per decision. ✅
3. **`AuditSink` trait** — abstract audit interface with `NullAuditSink` (ungoverned) and `MemoryAuditSink` (testing). ✅
4. **`AgentIdentity`** — transient (UUID) or sovereignty-rooted. `GovernedSessionConfig` for wiring. ✅
5. **`ExecutionReceipt`** + `ReceiptBuilder` — self-contained receipt type with BLAKE3 hashing. ✅
6. **`wrap_registry()`** — bulk-wrap an entire `ToolRegistry` with receipt emission. ✅

### Phase 2: Provider + Session ✅ COMPLETE
7. **`AuditedModelProvider`** — wraps `ModelProvider` with **Option B + rolling hasher**: ✅
   - `complete()`: Single combined receipt (input hash, output hash, tokens, timing)
   - `stream()`: Start record on open → rolling BLAKE3 hasher feeds on `TextDelta`/`InputJsonDelta` → completion record on `MessageDone` → failure record (with partial output hash) on error/drop
   - Three failure paths covered: stream error, premature end (no `MessageDone`), stream dropped (cancellation)
   - `first_output_ms` captured for time-to-first-token latency tracking
8. **`SovereigntyBridge` trait + `GovernedSessionBuilder`** — dependency-inverted sovereignty interface: ✅
   - `SovereigntyBridge` trait: `detect_providers()`, `verify_presence()`, `create_identity()`, `reverify()`
   - `TransientSovereigntyBridge`: no-op fallback for ungoverned sessions
   - `GovernedSessionBuilder`: fluent builder that wires all wrappers (registry, permissions, provider, tasks, cost) from a single entry point
   - `GovernedSession` struct: holds all wrapped components + `cost_tracker.finalize()` for session end

### Phase 2.5: Session-Level Cost Summary ✅ COMPLETE
9. **`SessionCostTracker`** — real-time token aggregation wired into `AuditedModelProvider`: ✅
   - `record()`: called by both `complete()` and `stream()` on every provider call
   - `finalize()`: computes `SessionCostSummary` with per-model breakdown + estimated USD, emits governance record
   - `snapshot()`: mid-session view for live dashboards
   - `default_pricing()`: 14 models priced (Anthropic, OpenAI, Google) — configurable via `with_pricing()`
   - `ModelUsage`: per-model accumulator (input/output tokens, success/fail counts, wall time)
   - Not an accounting ledger — governance-grade approximation. Provider billing API is authoritative.

### Phase 3: Full Integration ✅ COMPLETE
10. **`AuditedTaskManager`** — task lifecycle → governance events: ✅
    - Wraps `TaskManager` with governance record emission on: register, update_state, cancel
    - `TaskState` → chain event mapping (Pending→configured, Running→started, Completed→completed, Failed→failed, Cancelled→cancelled)
    - Pass-through for non-lifecycle methods (get, list, set_output, notifications)
    - Events surface automatically in ZP dashboard via `derive_system_state()`
11. **`VerifiedToolRegistry`** — capability verification at registration: ✅
    - `ToolManifest`: declares tool capabilities (`CodeExecution`, `FileRead`, `FileWrite`, `Network`, `WebSearch`, `McpBridge`, `Custom`)
    - `VerificationProbe` async trait: pluggable probes (`ShellProbe`, `FileReadProbe`, `FileWriteProbe`)
    - `register_verified()`: runs probes, records results, emits governance record
    - `register_unverified()`: legacy path for tools without manifests
    - `verified_tools()` / `failed_tools()`: query verification status
    - Connects to ZP's `zp configure auto --path` preflight pipeline
12. **ZP Dashboard integration**: Via audit chain — `derive_system_state()` already sees all events. *No additional code needed.* ✅

### Phase 4: Bridge Crate — SUPERSEDED
> **`zp-agent-bridge` has been removed.** The compile-time bridge pattern (ZP depending
> on agent-zp via cross-workspace path) is replaced by the MCP governance surface in
> `zp-server`. Agents connect as MCP clients — no compile-time coupling required.
> The dependency arrow is now correct: agents depend on ZP, not the reverse.

### Phase 5: Advanced Governance ✅ COMPLETE
All three governance modules (delegation, quorum, mesh) are implemented in `agent-zp` (claw side). Agent integration now happens via MCP governance tools exposed by `zp-server`.

14. **Multi-agent delegation chains** — parent agents delegate scoped capabilities to child agents: ✅
    - `DelegationPolicy` async trait: `authorize_delegation()`, `validate_chain()`, `revoke()`
    - `DelegatedCapability` enum: ToolExecution, ProviderAccess, FileRead, FileWrite, Network, Custom
    - `DelegationConstraint` enum: MaxCost, RateLimit, ExpiresAt, MaxDuration, RequireReceipts, Custom
    - `DelegationGrant`: cryptographic grant with BLAKE3 hash, depth tracking, scope narrowing
    - `DelegationChainRef`: ordered grant chain with `is_valid()` integrity check and `covers()` scope validation
    - `ChildSessionSpec`: defines what capabilities a child session requests
    - `AuditedDelegationPolicy`: wrapper emitting `GovernanceRecord` for every delegation operation
    - `NoDelegationPolicy`: no-op fallback (denies all delegation)
    - **Bridge**: `ZpDelegationPolicy` maps to ZP's `DelegationChain` + `CapabilityGrant` with configurable max depth (default 3) and trust tier
15. **Quorum-based approval for agent actions** — M-of-N consensus for high-risk operations: ✅
    - `QuorumPolicy` async trait: `requires_quorum()`, `propose()`, `vote()`, `check_outcome()`, `cancel()`
    - `QuorumThreshold` enum: Unanimous, Majority, Threshold{required, total}
    - `VoterRef` enum: SovereigntyProvider, Human, Agent, MeshPeer — maps to mesh-addressable strings
    - `QuorumProposal`: tracks proposer, action, threshold, voters, deadline, BLAKE3 action hash
    - `ProposedAction`: describes the action needing approval with risk level and metadata
    - `QuorumOutcome` enum: Approved, Rejected, Pending, TimedOut — with vote counts
    - `AuditedQuorumPolicy`: wrapper emitting governance records
    - `NoQuorumPolicy`: no-op fallback (never requires quorum)
    - **Bridge**: `ZpQuorumPolicy` wraps ZP's `ConsensusCoordinator` with risk-level-based threshold triggering and configurable default voters/deadline (5 min default)
16. **MCP ↔ ZP mesh peer integration** — agent sessions participate in ZP peer network: ✅
    - `MeshTransport` async trait: `address()`, `announce()`, `discover_peers()`, `establish_link()`, `forward_receipt()`, `broadcast_receipt()`, `is_reachable()`, `known_peers()`
    - `AgentCapabilities`: name, version, receipt types, skills, actor type, trust tier
    - `MeshPeerInfo`: address, hops, last seen, capabilities, link status
    - `MeshCapability`: capability type, scope, constraints for link negotiation
    - `NegotiationResult`: accepted/rejected/partial with granted capabilities and conditions
    - `AuditedMeshTransport`: wrapper emitting governance records
    - `NoMeshTransport`: no-op fallback (offline mode)
    - **Bridge**: `ZpMeshTransport` wraps `Arc<MeshNode>` — maps capabilities bidirectionally, converts `ExecutionReceipt` → `zp_receipt::Receipt` for mesh forwarding
    - **Known limitation**: `establish_link()` requires full peer identity resolution (not yet wired — returns descriptive error)
17. **`GovernedSessionBuilder` integration** — all Phase 5 traits wired into session builder: ✅
    - Added `delegation`, `quorum`, `mesh` fields to `GovernedSession`
    - Builder methods: `.delegation()`, `.quorum()`, `.mesh()`, `.parent_chain()`
    - Build steps 8-10: wrap with `AuditedDelegationPolicy`, `AuditedQuorumPolicy`, `AuditedMeshTransport`
    - Defaults to `NoDelegationPolicy`, `NoQuorumPolicy`, `NoMeshTransport` when not configured
    - **Compiles clean with zero errors, zero warnings** in both workspaces

---

## 10. Key Design Decisions

### Wrappers, not forks
Every integration is a **wrapper** that implements the same trait as the inner component. This means:
- Claw-code-rust works standalone without ZP (inner components only)
- ZP governance is opt-in per component
- Testing is straightforward: test inner component alone, then test wrapper behavior

### Audit chain as single source of truth
ZP's `derive_system_state()` rebuilds system state purely from the audit chain. This means Claw doesn't need to maintain separate governance state — it just emits events, and ZP derives everything from the chain. This is the correct architecture because:
- No state synchronization bugs
- System state is always consistent with the audit trail
- Dashboard views are always fresh (re-derive on request)

### Sovereignty is optional but recommended
An ungoverned Claw session works fine — `ToolContext` carries `Option<AgentIdentity>`. But a governed session provides:
- Cryptographic proof of who authorized every action
- Receipt chains that terminate at biometric/hardware verification
- The foundation for multi-agent trust (delegated capabilities)

### Blake3 everywhere
Both codebases already use hash-linked chains. Standardize on BLAKE3 for all hashing:
- Input hashes for tool calls and provider requests
- Output hashes for tool results and provider responses
- Receipt self-hashes for chain integrity
- Session token derivation from Genesis seed

---

## 11. Concrete Code Paths

### Path A: User types a prompt → Tool is executed → Receipt emitted

```
1. claude-cli: user input → SessionState.push_message()
2. agent-core: query() → provider.complete(request)
   └─ agent-zp-provider: AuditedModelProvider logs the LLM call
3. agent-core: response contains ToolUse → ToolOrchestrator.execute_batch()
4. agent-zp-tools: ReceiptEmittingTool.execute()
   ├─ agent-zp-permissions: ZpPermissionPolicy.check() → GovernanceEvent
   ├─ inner Tool.execute() runs
   └─ ExecutionReceipt emitted to AuditStore
5. agent-core: ToolResult → back to step 2 (recursive loop)
6. agent-core: TurnComplete → QueryEvent::TurnComplete emitted
```

### Path B: Session creation with sovereignty

```
1. claude-cli: user starts session
2. agent-zp-session: check SovereigntyProvider::verify_presence()
3. SovereigntyProvider::load_secret() → Genesis seed unlocked
4. Derive AgentIdentity (session keypair + signed token)
5. Create ZpToolContext with identity + audit_store
6. Wrap ToolRegistry with ReceiptEmittingTool wrappers
7. Wrap PermissionPolicy with ZpPermissionPolicy
8. Wrap ModelProvider with AuditedModelProvider
9. Proceed to normal query() loop — all actions are now governed
```

### Path C: ZP Dashboard sees agent state

```
1. Agent session emits events to AuditStore (all seams above)
2. Dashboard requests system state
3. derive_system_state() reads audit chain
4. Agent tasks appear as tool entries with ToolPhase states
5. Tool executions appear in receipt timeline
6. Permission decisions appear in governance event log
7. Provider calls appear with cost/latency metrics
```

---

## 12. What Claw Needs Before Integration

| Item | Status | Blocking? |
|------|--------|-----------|
| `agent-mcp` implementation | Stub only | No — Phase 3 |
| BLAKE3 dependency | ✅ Added to workspace | — |
| `chrono` with `serde` | ✅ Already in workspace | — |
| `uuid` with `v4` + `serde` | ✅ In `agent-zp` Cargo.toml | — |
| `agent-zp` crate | ✅ Created, compiles clean | — |
| Richer `ToolOutput.metadata` | Currently `Option<Value>` | No — receipts capture externally |
| `ToolContext` extensibility | ✅ `Extensions` type-map added | — |
| Cross-workspace ZP deps | Not needed | — `AuditSink` trait inversion eliminates this |

### Changes already made to `Cargo.toml`

```toml
# Added to [workspace.members]
"crates/agent-zp"

# Added to [workspace.dependencies]
agent-zp = { path = "crates/agent-zp" }
blake3 = "1"
```

---

## 13. Resolved Decisions

1. **Where do the `agent-zp-*` crates live?** → **Single `agent-zp` crate in `claw-code-rust/crates/`**. Uses `AuditSink` trait (dependency-inverted) so zero cross-workspace deps. The bridge adapter (`impl AuditSink for ZpAuditStore`) lives in whatever binary links both workspaces.

2. **Audit chain per-session or shared?** → **Shared store** with `conversation_id` scoping. Unified timeline for dashboard, per-session isolation via existing `AuditStore::get_entries(conversation_id, limit)`.

3. **Receipt signing** → **Plain BLAKE3 for receipts, Ed25519 for session tokens**. Session identity tokens now carry real Ed25519 signatures. Receipt signing upgrade to HMAC (keyed by session-derived key) is a one-line change in `ReceiptBuilder::build()`.

4. **Stream receipting granularity** → **Option B with rolling hasher**. Start record on stream open, completion record on `MessageDone`, failure record (with partial output hash) on error/drop. Checkpoints rejected — they solve a problem that doesn't exist in the current execution model (Claw doesn't dispatch tool calls mid-stream). If the architecture changes to streaming dispatch, revisit holistically. Session-level cost summary (Phase 2.5) covers the costing use case without checkpoint overhead.

## 14. Resolved & Open Questions

### Resolved

1. **Bridge crate location**: Removed. Agent integration now via MCP governance surface in `zp-server`.

2. **ToolContext extensibility**: → `Extensions` type-map in `agent-tools`. ✅
   - `Extensions` struct: `HashMap<TypeId, Box<dyn Any + Send + Sync>>` with `insert<T>()`, `get<T>()`, `remove<T>()`
   - Added `extensions: Extensions` field to `ToolContext`
   - `GovernedSession::tool_context(cwd)` stashes `AuditSink`, `AgentIdentity`, `DelegationPolicy`, `QuorumPolicy`, `MeshTransport`, `SessionCostTracker`, and `DelegationChainRef` into extensions
   - Tools retrieve via typed lookup: `ctx.extensions.get::<Arc<dyn AuditSink>>()`
   - Ungoverned sessions: empty extensions, `get()` returns `None`

3. **Ed25519 session signing**: → Real Ed25519 signatures via `ed25519-dalek`. ✅
   - `create_identity()` derives `SigningKey::from_bytes(blake3(genesis_seed || nonce))`
   - `agent_id` = hex of first 16 bytes of Ed25519 public key (deterministic, derived from Genesis)
   - `session_token` = hex(Ed25519 signature || public key) — 96 bytes, 192 hex chars
   - Signed message: `agent_id || timestamp_rfc3339 || session_nonce`
   - Verifiers extract pubkey from token tail, verify signature over reconstructed message

### Open

1. **Async audit emission**: `AuditStore::append()` is synchronous (SQLite). The `ZpAuditSink` uses `Mutex<AuditStore>` which blocks briefly on each append. For high-throughput scenarios, consider a channel-based async writer (mpsc → dedicated writer thread). Current implementation is correct for single-agent sessions.

2. **Mesh link completion**: `establish_link_by_address()` sends the LinkRequest packet and stores a Pending link, but the handshake completes asynchronously when the responder's LinkProof arrives via the mesh runtime's packet dispatcher. Capability negotiation happens post-handshake. The bridge returns a partial `NegotiationResult` with empty grants. Full grant population requires wiring the runtime's inbound proof handler to the bridge's result channel.
