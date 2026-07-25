# Regent Orchestration Architecture

**Date:** 2026-07-04
**Status:** Design document
**Author:** Ken Romero, with synthesis assistance from Claude.
**Companion to:** `docs/ARCHITECTURE-2026-07.md` (north star), `docs/GOVERNANCE-IMPLEMENTATION-PRINCIPLES-2026-06.md` (implementation heuristics), `docs/design/TOOL-OPACITY-AND-CAPABILITY-CLASSES-2026-07.md` (capability classes)
**Scope:** Evolution of the Regent from a single-model cognitive loop to a chain-anchored orchestration layer — ZeroPoint's answer to the planner-router-executor pattern emerging in production agent systems.

**Multi-device operation note (per Decision C, July 2026):** The seven-layer orchestration model described here runs on the device currently hosting active Regent presence. The Regent's home is the operator, not any specific device; state is chain-anchored and replicated across all authorized devices; only one active instance at a time; transitions between devices happen via explicit chain-anchored handoff. Layer 5 (Memory and Context) and Layer 6 (Background Execution and Workflows) both carry state that participates in replication; WorkArc checkpoints are chain-anchored so a workflow started on one device can resume on another after handoff. Cloud rally and fleet rally per Layer 3 (Model Router) work from wherever the Regent currently is — the routing decision doesn't change based on which device hosts active presence, only the specific device paths change.

---

## 1. The shift

The Regent as currently scaffolded is a single cognitive loop: perceive chain state, reason with one local model, emit one intent. This is correct for the first empirical test — it proves the loop runs, receipts land, officers observe. But it is not the target architecture.

The target is an orchestration layer that decomposes operator goals into subtask graphs, routes subtasks to appropriate models and tools, executes them under delegated authority, and assembles deliverables — all chain-anchored, all officer-observed, all within the operator's sovereign compute boundary unless explicitly mandated otherwise.

The reference point is Perplexity Computer's planner-router-executor system: goal decomposition, model selection across 20+ models, subagent dispatch, tool integration, persistent context, background execution, output synthesis. Their system optimizes for getting work done. ZeroPoint's optimizes for knowing what was done, by whom, under which policy, with which receipts, and whether the resulting state is canonical.

The architectural question is not "how do we build Perplexity Computer" but "how does a chain-anchored substrate express the same capability pattern without surrendering provenance, policy enforcement, or operator sovereignty."

---

## 2. Current state (Phase 0 — shipped)

The Regent today:

- **Single model**: one Ollama endpoint, one reasoning model (qwen3:8b), one routing model (qwen3:1.7b)
- **Single loop**: perceive → reason → emit Intent
- **Seven intent types**: Respond, Delegate, Execute, Remember, RequestApproval, Observe, Escalate
- **No task decomposition**: the Regent processes one input and emits one intent per cycle
- **No tool invocation**: Execute intent is receipted but not wired to tool dispatch
- **No background execution**: the loop is synchronous per-cycle
- **Cloud mandate exists as a type**: CloudMandate struct with token budget, but no cloud backend wired
- **Memory**: MVP keyword-based, JSON-backed persistent store

What works: the loop runs, intents are receipted, officers observe the Regent's receipts, findings flow back to the Regent, config is operator-controllable via `[regent]` in config.toml.

What doesn't: the Regent can observe and respond but cannot *do* anything. It has no hands.

---

## 3. Target architecture

Seven layers, each chain-anchored. The layers compose vertically — each one produces receipts that the layer above can reason about and the officers can observe.

### Layer 1: Intent Reception

**What it does:** Receives operator goals from any cockpit surface.

**Current state:** Already works. `RegentHandle.send_input()` accepts content + `CockpitSource` (Regent, CLI, Browser, Autonomous). Officer findings arrive via `send_findings()`.

**What changes:** Nothing structurally. The input contract is correct. What changes is what the Regent *does* with the input — it stops being a single-inference-call responder and starts being a planner.

### Layer 2: Task Decomposition (Planner)

**What it does:** Breaks an operator goal into a directed acyclic graph of subtasks with dependencies, estimated costs, and capability requirements.

**New types:**

```
TaskGraph {
    id: TaskGraphId,           // content-addressed from goal + timestamp
    goal: String,              // operator's original intent
    subtasks: Vec<Subtask>,    // ordered, with dependency edges
    created_at: DateTime,
    status: GraphStatus,       // Planning | Executing | Completed | Failed | Cancelled
}

Subtask {
    id: SubtaskId,
    description: String,
    capability_class: CapabilityClass,  // from tool-opacity doc
    model_tier: ModelTier,     // which class of model this needs
    estimated_tokens: u64,     // for mandate budgeting
    depends_on: Vec<SubtaskId>,
    status: SubtaskStatus,
    result: Option<SubtaskResult>,
}

ModelTier {
    Routing,      // fast classification, <2B params, ~100 tok/s
    Reasoning,    // general reasoning, 7-14B params
    Deep,         // complex analysis, 30B+ or cloud escalation
    Specialized,  // domain-specific (code, math, vision)
}
```

**Receipt:** `regent:plan:created` with task graph hash, subtask count, estimated total tokens. This receipt is the chain's record that the Regent decomposed a goal — before any execution begins. If the operator kills the workflow, the chain shows what was planned but not executed.

**Inference call:** The planner itself is an inference call to the reasoning model. The prompt includes the operator's goal, the Regent's current delegations (what it's allowed to do), and the available tool vocabulary (what it *can* do). The model outputs a structured task graph. The routing model can handle simple single-step goals without invoking the reasoning model.

**The governance constraint that makes this different from Perplexity:** The planner cannot plan subtasks that exceed the Regent's current delegation. If the goal requires capabilities the Regent doesn't hold, the planner emits a `RequestApproval` subtask as the first node in the graph — the workflow blocks until the operator grants the delegation. The chain records both the request and the grant (or denial). No silent capability assumption.

### Layer 3: Model Router

**What it does:** Assigns a specific model to each subtask based on the subtask's `ModelTier`, the available local models, and the cloud mandate budget.

**Routing logic:**

```
fn route(subtask: &Subtask, local_models: &[Model], mandate: &Option<CloudMandate>) -> RoutingDecision {
    // 1. Can a local model handle this tier?
    if let Some(model) = local_models.best_for(subtask.model_tier) {
        return RoutingDecision::Local { model }
    }

    // 2. Is there an active cloud mandate with sufficient budget?
    if let Some(m) = mandate && m.is_active() && m.remaining() >= subtask.estimated_tokens {
        return RoutingDecision::Cloud { 
            provider: m.provider,
            model: m.model,
            estimated_cost: subtask.estimated_tokens,
        }
    }

    // 3. Neither — escalate to operator
    RoutingDecision::NeedsMandate { 
        reason: format!("subtask requires {} tier, no local model available", subtask.model_tier),
        estimated_tokens: subtask.estimated_tokens,
    }
}
```

**Receipt:** `regent:route:assigned` per subtask — records which model was selected and why. This is the "what was asked vs what actually happened" principle from the governance implementation notes: the chain captures both the tier requested and the model assigned.

**The local-first constraint:** Unlike Perplexity, which routes freely across 20+ cloud models, the Regent's default is local. Cloud is an escalation that burns mandate budget. The operator sees exactly how many tokens were spent on cloud inference because every cloud call is a receipted mandate-spend event. The Regent cannot silently decide "this needs GPT-4" — it either has a mandate or it asks for one.

**Model registry:** The Regent maintains awareness of locally available models via Ollama's `/api/tags` endpoint (already implemented in `InferenceBackend::model_available()`). The registry maps models to tiers based on parameter count and capability tags. This is not a new system — it's a structured interpretation of what Ollama already reports.

### Layer 4: Subtask Execution

**What it does:** Executes individual subtasks. This is where the Regent gets hands.

**Three execution modes:**

1. **Inference**: Run a model call and capture the output. The simplest mode — prompt in, text out. Used for reasoning, analysis, summarization, classification.

2. **Tool invocation**: Call a governed tool through the gate. The Regent constructs tool parameters, the gate evaluates the delegation, produces a `gate:allowed` or `gate:denied` receipt, and the tool executes. The Regent receives the `ToolCompletionResponse` including the tool's self-report. This is the existing tool dispatch path — the Regent is just another actor invoking tools, subject to the same gate that governs any other tenant tool.

3. **Sub-agent delegation**: Spawn a scoped sub-agent for multi-step subtasks. The sub-agent receives a narrowed delegation (the Regent can only delegate authority it holds, per the eight delegation invariants), executes its steps, and returns results. Each sub-agent step is independently receipted. This is the `Intent::Delegate` variant already defined — what changes is that it gets wired to actual execution rather than being receipt-only.

**Receipt per execution step:**
- `regent:exec:started` — subtask ID, execution mode, model or tool
- `regent:exec:completed` — subtask ID, result summary, tokens consumed
- `regent:exec:failed` — subtask ID, error, whether retryable

**The gate constraint:** Tool invocations go through P3 (the gate). The Regent does not bypass the gate. The Regent does not get a special gate path. If the Regent lacks delegation for a tool, the gate denies it, the denial is receipted, and the Regent can escalate to `RequestApproval`. This is the "keeping governance out of the agent's business logic" principle — the Regent is the agent, the gate is the governance, they don't merge.

**Transparent vs opaque tools:** The tool-opacity classification matters here. When the Regent invokes a transparent tool (chain_query, governance_posture), the receipt captures both authorization and outcome. When it invokes an opaque tool (shell, file_write, http), the receipt captures authorization and the tool's self-report. The Regent's planner should prefer transparent tools when both can achieve the goal, because the chain's record is stronger. This preference is structural, not a policy — the planner's system prompt encodes it.

### Layer 5: Memory and Context

**What it does:** Maintains persistent cross-session context that informs planning and execution.

**Current state:** MVP keyword-based `MemoryStore` with JSON persistence. The value is in what the Regent remembers, not the storage engine.

**Evolution path:**

The memory system grows along three axes without changing its fundamental shape:

**Operator preferences.** What the operator has told the Regent about how they work, what they care about, what formats they prefer. Captured via `Intent::Remember` receipts, queryable by the planner. "Ken prefers concise output" is a memory fragment that shapes every response the Regent generates.

**Task history.** Completed task graphs and their outcomes. The planner consults history to avoid repeating failed approaches and to reuse successful decomposition patterns. "Last time the operator asked for a competitive analysis, the graph had five subtasks and the shell tool failed on the third" is a structural memory that improves future planning.

**Delegation context.** Which delegations the Regent has held, which were used, which were revoked. This is chain-derivable (the chain is the source of truth), but caching recent delegation state in memory avoids re-scanning the chain every cycle.

**Receipt:** `regent:memory:stored` and `regent:memory:recalled` — the chain records what the Regent remembered and what it retrieved, so the officer cadre can observe whether memory is being used appropriately. A Regent that never recalls memories is wasting storage. A Regent that recalls stale memories is reasoning from outdated context.

### Layer 6: Background Execution and Workflows

**What it does:** Runs task graphs that take longer than a single cognitive cycle — minutes, hours, or recurring schedules.

**New types:**

```
Workflow {
    id: WorkflowId,
    task_graph: TaskGraph,
    checkpoint: WorkflowCheckpoint,  // serializable resume point
    started_at: DateTime,
    schedule: Option<Schedule>,      // for recurring workflows
    cancellation_token: CancellationToken,
}

WorkflowCheckpoint {
    completed_subtasks: Vec<SubtaskId>,
    pending_subtasks: Vec<SubtaskId>,
    accumulated_results: Vec<SubtaskResult>,
    tokens_consumed: u64,
    last_checkpoint_at: DateTime,
}
```

**Receipt cadence:**
- `regent:workflow:started` — workflow ID, task graph hash, estimated duration
- `regent:workflow:checkpoint` — periodic (configurable interval), records progress
- `regent:workflow:completed` — final results, total tokens, total wall time
- `regent:workflow:cancelled` — who cancelled (operator or Regent), why

**The kill switch:** The operator can cancel any workflow at any point. Cancellation is a receipt. The chain shows exactly what was done before cancellation and what was planned but not executed. This is the Perplexity "kill switch" equivalent, except the chain makes it auditable — you can prove what the agent did and didn't do.

**Recurring workflows:** Some task graphs are meant to run on a schedule — "every morning, check the chain for anomalies and summarize findings." The Regent's autonomous wake cycle (already implemented in `loop_runner.rs`) is the primitive. What changes is that the wake cycle can trigger a stored workflow rather than just running a generic perceive-reason cycle.

### Layer 7: Deliverable Synthesis

**What it does:** Assembles final artifacts from subtask results.

**Connection to existing primitives:** This is the "substrate proposes; operators sign" heuristic applied to Regent output. The Regent produces a *candidate* artifact — a report, analysis, code change, configuration recommendation. The candidate lands in the artifact library (proposed in `docs/ARTIFACT-LIBRARY-2026-05.md`). The operator reviews. On approval, the substrate signs the artifact with the operator's Genesis-rooted key. The signed artifact becomes citable as canonical reference.

**Receipt:**
- `regent:artifact:proposed` — artifact hash, source task graph, content summary
- `regent:artifact:signed` — operator endorsement, becomes canonical
- `regent:artifact:superseded` — new version replaces a previously-signed artifact

**The provenance chain:** A signed Regent artifact traces end-to-end: operator signature → artifact (source task graph) → subtask results → execution receipts → gate decisions → tool completions → chain → Genesis. A third party can verify by retracing the receipt chain. This is what makes ZP's deliverable synthesis structurally different from "an agent wrote a document" — the document's entire production history is chain-verifiable.

---

## 4. The governance overlay

Every layer above produces receipts. The officer cadre observes them.

**Steward** verifies chain integrity across Regent receipts — hash linkage, signature validity, no gaps. A Regent that produces broken receipt chains is a Regent with a structural problem.

**Sentinel** watches for security-relevant patterns — a Regent invoking opaque tools at unusual frequency, a workflow that escalates to cloud without obvious need, a subtask graph that requests capabilities far beyond what the goal requires. Sentinel doesn't block (that's the gate's job) — it flags.

**Forge** monitors operational health — inference latency, model availability, workflow completion rates, token consumption trends. A Regent whose inference calls are timing out is an operational problem Forge surfaces.

**Cleo** narrates — turns the Regent's receipt trail into a governance story. "The Regent decomposed the operator's competitive analysis request into five subtasks, routed three to local qwen3:8b and escalated two to cloud under mandate #47, completed in 12 minutes with 3,400 tokens consumed." This is the chain storytelling primitive applied to Regent activity.

**The officers do not govern the Regent specially.** They observe Regent receipts the same way they observe any other actor's receipts. The Regent is a first-class actor in the substrate — governed, not governing. The Regent's cognitive superiority (it reasons, plans, routes) does not give it governance superiority. The gate is still the gate. The chain is still the chain. The officers are still the officers.

---

## 5. Cloud model registry and mandate integration

### 5.1 The problem with single-model mandates

The current `CloudMandate` type is provider+model (singular): "use claude-sonnet-4-6 on Anthropic with 50k tokens." That's a keyhole. A Perplexity-class router selects from 20+ models per workflow — code generation routes to one model, summarization to another, vision tasks to a third. The Regent needs the same routing freedom, but under governance.

The structural gap: the Regent can't select the best cloud model per subtask because the mandate authorizes exactly one model. And the Regent can't even know what cloud models are *available* because provider API keys live in the vault with no capability metadata attached.

### 5.2 Cloud model registry — vault as the source of truth

The vault already holds cloud provider API keys. What's missing is structured metadata that tells the router what each key unlocks. The cloud model registry bridges that gap: vault entries for provider credentials, paired with a capability manifest that maps each provider to its available models with routing-relevant metadata.

**New type:**

```
CloudModelEntry {
    provider: String,           // "anthropic", "openai", "google", etc.
    model: String,              // "claude-sonnet-4-6", "gpt-4o", "gemini-2.5-pro"
    vault_credential: String,   // vault key for the API credential
    capabilities: ModelCapabilities,
    cost: ModelCost,
}

ModelCapabilities {
    context_window: u64,        // max tokens
    strengths: Vec<String>,     // ["code", "reasoning", "vision", "long_context", "fast"]
    tier: ModelTier,            // maps to subtask routing
    supports_structured: bool,  // native JSON output
    supports_vision: bool,
    supports_streaming: bool,
}

ModelCost {
    input_per_million: f64,     // USD per 1M input tokens
    output_per_million: f64,    // USD per 1M output tokens
    cached_input_per_million: Option<f64>,
}
```

**Where the registry lives:** A TOML file at `~/ZeroPoint/cloud-models.toml`, operator-maintained. The Regent reads it; the Regent does not write it. The operator controls what cloud models are available the same way they control what tools are installed — by explicit provisioning.

```toml
[[model]]
provider = "anthropic"
model = "claude-sonnet-4-6"
vault_credential = "anthropic_api_key"
tier = "reasoning"
context_window = 200000
strengths = ["reasoning", "code", "long_context"]
supports_structured = true
supports_vision = true
input_per_million = 3.0
output_per_million = 15.0

[[model]]
provider = "anthropic"
model = "claude-haiku-4-5"
vault_credential = "anthropic_api_key"
tier = "routing"
context_window = 200000
strengths = ["fast", "classification", "extraction"]
supports_structured = true
supports_vision = true
input_per_million = 0.80
output_per_million = 4.0

[[model]]
provider = "openai"
model = "gpt-4o"
vault_credential = "openai_api_key"
tier = "reasoning"
context_window = 128000
strengths = ["reasoning", "code", "vision"]
supports_structured = true
supports_vision = true
input_per_million = 2.5
output_per_million = 10.0

[[model]]
provider = "openai"
model = "o3-mini"
vault_credential = "openai_api_key"
tier = "deep"
context_window = 200000
strengths = ["reasoning", "math", "code"]
supports_structured = true
supports_vision = false
input_per_million = 1.1
output_per_million = 4.4
```

**Vault integration:** The registry references vault credentials by key name, never by value. At inference time, the Regent resolves `vault_credential` through the vault API to get the actual API key. The API key never appears in the registry, in logs, or in receipts. The vault is the credential boundary; the registry is the capability boundary. They compose without merging.

**Validation at startup:** When the Regent starts, it loads `cloud-models.toml` and validates that every referenced `vault_credential` exists in the vault. Missing credentials produce a Forge-observable warning (not a hard failure — the Regent runs local-only if no cloud credentials are available). Models with missing credentials are excluded from the routing pool.

### 5.3 Mandate revision — budget across the registry, not per model

The mandate evolves from single-model authorization to registry-scoped budget authorization:

**Old shape (retired):**
```
CloudMandate { provider, model, token_budget, tokens_spent, expires_at }
```

**New shape:**
```
CloudMandate {
    id: MandateId,
    token_budget: u64,          // total tokens authorized
    tokens_spent: u64,          // running total across all models
    cost_budget_usd: Option<f64>,  // optional dollar cap
    cost_spent_usd: f64,       // running dollar total
    expires_at: DateTime<Utc>,
    scope: MandateScope,       // what the mandate authorizes
}

MandateScope {
    /// Which providers are authorized. Empty = all registered providers.
    providers: Vec<String>,
    /// Which tiers are authorized. Empty = all tiers.
    tiers: Vec<ModelTier>,
    /// Specific model exclusions. Operator can say "use anything except o3"
    /// to control cost without micromanaging routing.
    excluded_models: Vec<String>,
}
```

The mandate authorizes a *budget across the registry*, scoped by provider and tier. The router selects the best model per subtask from the authorized pool. Each cloud call burns from the shared budget proportional to the model's actual cost.

**Mandate lifecycle:**

1. Operator issues a mandate:
   `zp regent mandate --budget 100000 --cost-cap 5.00 --expires 24h`
   or scoped:
   `zp regent mandate --budget 50000 --providers anthropic --tiers reasoning,deep --expires 8h`
2. Receipt: `regent:mandate:issued` with budget, scope, expiry
3. Router selects from the authorized pool per subtask (see §5.4)
4. Each cloud call: `regent:mandate:spent` with model used, tokens consumed, cost incurred, running totals
5. Budget exhausted (tokens or dollars): `regent:mandate:exhausted` — Regent falls back to local-only
6. Expiry: `regent:mandate:expired` — same fallback

**Dollar budgeting:** Token budgets alone are misleading when models have 10x cost differences. A 50k-token budget spent on claude-sonnet-4-6 costs ~$0.90; spent on o3 it costs ~$0.28. The optional `cost_budget_usd` field lets the operator cap actual spend. The Regent tracks both dimensions; whichever limit is hit first triggers exhaustion.

### 5.4 Router integration — best model for the job

The router gains access to the full cloud model registry and selects per-subtask:

```
fn route_cloud(
    subtask: &Subtask,
    registry: &CloudModelRegistry,
    mandate: &CloudMandate,
) -> Option<CloudRoutingDecision> {
    // 1. Filter to models authorized by mandate scope
    let authorized = registry.models_matching(&mandate.scope);

    // 2. Filter to models whose capabilities match subtask requirements
    let capable = authorized.filter(|m| {
        m.capabilities.tier >= subtask.model_tier
        && subtask.required_strengths.iter().all(|s| m.capabilities.strengths.contains(s))
        && (!subtask.needs_vision || m.capabilities.supports_vision)
        && (!subtask.needs_structured || m.capabilities.supports_structured)
    });

    // 3. Rank by fit: prefer cheapest model that meets all requirements
    // (operator can override ranking strategy via mandate or config)
    let best = capable.min_by(|a, b| {
        a.cost.output_per_million.partial_cmp(&b.cost.output_per_million)
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;

    // 4. Check budget
    let estimated_cost = estimate_cost(best, subtask.estimated_tokens);
    if mandate.tokens_spent + subtask.estimated_tokens > mandate.token_budget {
        return None; // Budget exceeded
    }
    if let Some(cap) = mandate.cost_budget_usd {
        if mandate.cost_spent_usd + estimated_cost > cap {
            return None; // Dollar cap exceeded
        }
    }

    Some(CloudRoutingDecision {
        model: best.clone(),
        estimated_tokens: subtask.estimated_tokens,
        estimated_cost_usd: estimated_cost,
    })
}
```

**Default routing strategy: cheapest-capable.** The router picks the least expensive model that meets all capability requirements. This aligns with P4 (every bit counts) — no waste. The operator can override this via config to prefer speed (lowest-latency model), quality (highest-tier model), or a specific provider.

**Receipt per routing decision:** `regent:route:cloud` records which model was selected, which alternatives were considered, why this one won (cheapest, fastest, only-capable), and the estimated vs actual cost. The chain captures the routing rationale, not just the outcome. This is the "what was asked vs what actually happened" principle applied to model selection.

### 5.5 The local-first constraint remains

Cloud is never the default. The routing order is:

1. **Local model that meets the tier requirement** → use it, no mandate needed
2. **No local model, mandate active, cloud model available** → route through registry
3. **No local model, no mandate** → escalate to operator via `RequestApproval`

The Regent cannot silently decide "this needs claude-sonnet-4-6." It either has a mandate that authorizes Anthropic reasoning-tier models, or it asks for one. The registry makes cloud *available*; the mandate makes cloud *authorized*; the vault makes cloud *credentialed*. All three must align for a cloud call to happen.

### 5.6 No implicit cloud access

The Regent never calls a cloud model without an active mandate. This is a structural constraint, not a policy preference. The `InferenceBackend::validate_mandate()` method enforces it before any cloud call. The receipt chain makes enforcement verifiable — if a `regent:mandate:spent` receipt exists without a preceding `regent:mandate:issued` receipt, the chain is structurally broken.

The registry is read-only to the Regent. The vault credentials are read-only to the Regent. The mandate budget is write-only (spend) to the Regent. The operator controls provisioning (registry), credentialing (vault), and authorization (mandate) through three independent surfaces. The Regent controls only selection (routing) — which model from the authorized pool best fits this subtask. That's the separation of concerns: the operator defines the menu; the Regent orders from it.

---

## 6. Implementation phases

### Phase 1: Hands — Tool invocation through the gate

Wire `Intent::Execute` to actual tool dispatch. The Regent constructs tool parameters, the `ServerIntentExecutor` routes through the gate, the tool executes, the result returns to the Regent's cognitive context. This is the minimum viable "the Regent can do things."

**Requires:** Access to `ToolDispatcher` (or equivalent gate-fronted dispatch) from `ServerIntentExecutor`. The Regent needs a delegation grant for the tools it wants to invoke.

**Receipt chain:** `regent:intent:execute` → `gate:allowed:tool_name` → `tool:completed:tool_name` → result flows back to Regent.

**Test:** Operator says "what's the current governance posture?" Regent invokes `governance_posture` tool through gate, reads result, responds with summary. Three receipts on chain: intent, gate, tool completion.

### Phase 2: Planning — Task decomposition

Add `TaskGraph` and `Subtask` types. The Regent's `reason()` method gains a planning mode: when the operator's goal is multi-step, emit a task graph instead of a single intent. The planner is an inference call with structured output (the `format` parameter already supported by Ollama).

**Requires:** Structured output parsing for task graphs. The routing model (qwen3:1.7b) classifies whether a goal needs planning or is single-step.

**Receipt chain:** `regent:plan:created` → per-subtask `regent:exec:*` receipts.

**Test:** Operator says "check the chain for anomalies and summarize what the officers found in the last hour." Regent decomposes into two subtasks (chain query + summarize findings), executes sequentially, assembles response.

### Phase 3: Model routing and cloud registry

Add the unified model registry: local models discovered via Ollama `/api/tags`, cloud models from `~/ZeroPoint/cloud-models.toml` with vault-backed credentials. Router selects per-subtask across the full pool — local first, cloud under mandate.

**Requires:** `CloudModelRegistry` type that loads and validates `cloud-models.toml` at startup. Vault credential resolution for cloud entries. Revised `CloudMandate` with `MandateScope` (provider/tier/exclusion filtering). Cost tracking in both tokens and USD.

**Receipt chain:** `regent:route:assigned` per subtask — records model selected, alternatives considered, routing rationale (cheapest-capable, only-capable, operator-preferred).

**Test:** A goal that requires both fast classification (local routing model) and deep analysis (cloud reasoning model under mandate). Two subtasks route to different models across the local/cloud boundary. Receipts show both routing decisions with cost estimates.

### Phase 4: Background workflows

Add `Workflow` and `WorkflowCheckpoint` types. The loop runner gains workflow awareness — it can resume an in-progress workflow across cognitive cycles rather than treating each cycle as independent.

**Requires:** Workflow serialization for checkpoint/resume. Cancellation token plumbing from operator cockpits.

**Receipt chain:** `regent:workflow:started` → periodic `regent:workflow:checkpoint` → `regent:workflow:completed`.

**Test:** A multi-minute workflow (research + analysis + summary) that spans multiple cognitive cycles. Operator can query progress mid-workflow. Operator can cancel mid-workflow.

### Phase 5: Deliverable synthesis and artifact library

Wire the "substrate proposes; operators sign" lifecycle for Regent-produced artifacts. The Regent proposes; the operator reviews and signs; the signed artifact is canonical and citable.

**Requires:** Artifact library infrastructure (content-addressed storage, operator signing flow). This connects to the broader artifact library design (`docs/ARTIFACT-LIBRARY-2026-05.md`).

**Receipt chain:** `regent:artifact:proposed` → operator review → `regent:artifact:signed`.

### Phase 6: Cloud inference backends

Wire the cloud inference path for each provider in the registry. Each backend implements the same `InferenceBackend` trait but speaks a different API protocol (Anthropic messages API, OpenAI chat completions, Google Gemini).

**Requires:** Per-provider HTTP clients. Vault credential resolution at call time (never cached). Mandate validation and cost accounting before every call. CLI for mandate issuance (`zp regent mandate`) and registry inspection (`zp regent models`).

**Receipt chain:** `regent:mandate:issued` → per-call `regent:mandate:spent` with model, tokens, cost → `regent:mandate:exhausted` or `regent:mandate:expired`.

**Test:** Operator issues a mandate scoped to Anthropic reasoning-tier with a $2.00 cap. Regent routes a deep-analysis subtask to claude-sonnet-4-6, a fast-classification subtask to claude-haiku-4-5. Receipts show per-model spend. Dollar cap fires before token cap on the expensive model. Regent falls back to local for remaining subtasks.

---

## 7. What this is not

**Not a Perplexity clone.** Perplexity Computer is a cloud-native productivity tool. ZeroPoint is a sovereignty substrate. The orchestration pattern is the same; the trust model is inverted. Perplexity trusts its own cloud; ZeroPoint trusts the operator's chain.

**Not multi-tenant.** The Regent serves one operator. There is no shared workspace, no multi-user routing, no platform-level resource allocation. The Regent is the operator's agent — singular, accountable, non-shared.

**Not an agent framework.** ZeroPoint does not provide a general-purpose agent SDK. The Regent is the substrate's own cognitive layer, not a framework for building arbitrary agents. Tenant tools interact with the substrate through delegated tool invocation — they don't build on the Regent's internals.

**Not a model marketplace.** The model router selects from what the operator has provisioned — local Ollama models discovered at runtime, cloud models declared in `cloud-models.toml` with vault-backed credentials. The Regent does not discover, download, benchmark, or subscribe to models. Model provisioning and credentialing are the operator's responsibility. The Regent routes from the menu; it does not write the menu.

---

## 8. Design principles applied

Every layer in this architecture should be testable against the nine design principles from `ARCHITECTURE-2026-07.md`:

**P1 (Signing is gravity):** Every orchestration step is receipted. An unreceipted subtask execution is structurally meaningless — the chain doesn't know it happened, so it didn't happen governably.

**P2 (Identity is a key, not a location):** The Regent's identity is its actor ID (`ActorId::System("regent")`), not its inference endpoint. Switching the Regent's model or endpoint doesn't change its identity or its delegation grants.

**P3 (There is no center):** The Regent is an actor in the substrate, not a privileged controller. It goes through the gate like any other actor. Its authority is delegated, not inherent.

**P4 (Every bit counts):** Task graphs are DAGs with explicit dependencies, not sprawling trees with redundant paths. The planner's system prompt encodes preference for minimal decomposition — the fewest subtasks that achieve the goal.

**P5 (Store-and-forward is primary):** Workflow checkpoints are durable. A Regent restart resumes from the last checkpoint, not from scratch. The chain survives the Regent's outage.

**P6 (A tool is intent, crystallized):** Each subtask type maps to a concrete execution mode. Planning, routing, and execution are structural — their semantics live in the types, not in prompt engineering.

**P7 (Constitutional rules are conservation laws):** From the governance implementation principles — the gate evaluates the Regent's tool calls the same way it evaluates any actor's. No special path.

**P8 (One canonical path per substrate concern):** From CLAUDE.md working principles — tool dispatch goes through `ToolDispatcher`, not a Regent-specific shortcut. Memory goes through `MemoryStore`, not inline state. Cloud calls go through mandate validation, not a raw HTTP client.

---

## 9. The structural difference

Perplexity Computer's value proposition: "give it a goal, it does the work."

ZeroPoint's value proposition: "give it a goal, it does the work, and the chain proves what it did, under which authority, with which models, at what cost, and whether the operator endorsed the result."

The orchestration pattern is identical. The trust model is the differentiator. Every layer in this architecture exists twice — once as a capability (it can plan, route, execute, synthesize) and once as a governance surface (every plan is receipted, every route is receipted, every execution is gate-evaluated, every deliverable is a candidate until signed). The second existence is what makes this ZeroPoint rather than another agent orchestrator.

The Regent is the operator's cognitive extension. The chain is the operator's memory of what that extension did. The officers are the operator's independent verification that what the extension claims to have done is what actually happened. The mandate is the operator's budget control over what the extension is allowed to spend. These four things together — delegation, receipting, observation, budgeting — are the substrate's answer to "how do you trust an agent that can plan and execute autonomously."

The answer is: you don't trust it. You verify it. The chain makes verification structural.
