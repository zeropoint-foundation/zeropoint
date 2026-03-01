# ZeroPoint v2 — Architecture Design Document

**Author**: Claude (Opus), commissioned by Kenneth Romero
**Date**: February 21, 2026
**Status**: Draft for Review

---

## 1. Design Philosophy

ZeroPoint v2 is a ground-up rebuild guided by three principles:

1. **Governance is code, not prose.** Policy enforcement happens in deterministic WASM modules, never in LLM prompts. The LLM reasons; the runtime enforces.
2. **The system improves by using itself.** Every interaction feeds a learning loop that extracts skills, patterns, and policy refinements. Trust compounds over time.
3. **Simple by default, powerful when needed.** An individual installs and runs. An enterprise configures signing chains and fleet policies. Same core, different surface.

### What We Carry Forward from v1

- **Hash-chained audit trail** — immutable, append-only record of all actions. The idea is right; v2 moves it from a nice-to-have to a structural dependency.
- **Receipt-gated execution** — "no receipt, no proof" remains the standard for action claims. v2 makes receipts a WASM-enforced gate, not a prompt instruction.
- **Genesis Protocol (conceptually)** — the idea of a cryptographic trust root with a human authority is sound. v2 implements it as signed WASM policy modules in a verifiable chain, not as ceremony text injected into prompts.
- **Domain specialization** — security, planning, engineering, governance remain important domains. v2 expresses them as skills (WASM modules with domain-specific tooling), not as separate agent identities. One operator, many skills.

### What We Drop

- **Governance-as-prompt-text** — no operating modes, verification labels, capability classifications, or trust status in LLM context. Ever.
- **Multi-role architecture** — five officers, dual naming, handoff protocol, role routing. One operator with skills replaces all of it.
- **Canonical seeds / context graph knowledge injection** — the LLM doesn't need to know how its own context is assembled. Domain knowledge comes from skills, not self-referential documentation.
- **Static directive loading** (YAML authority matrices, markdown ADRs as prompt text) — policy is compiled, not parsed and injected.
- **The monolithic 8000-line main.rs** — v2 is modular by design.

---

## 2. System Architecture

### 2.1 The Three Layers

```
┌─────────────────────────────────────────────────┐
│                 INTERFACE LAYER                  │
│  CLI · API · (Web Dashboard · Slack · Discord)   │
│  (Channel adapters — thin, stateless)           │
└──────────────────────┬──────────────────────────┘
                       │ Messages (typed, structured)
┌──────────────────────▼──────────────────────────┐
│              DETERMINISTIC CORE                  │
│                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
│  │ Request  │ │ Policy   │ │ Skill Registry   ││
│  │ Pipeline │ │ Engine   │ │ & Lifecycle      ││
│  │ (Rust)   │ │ (WASM)   │ │ (WASM modules)   ││
│  └──────────┘ └──────────┘ └──────────────────┘│
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
│  │ Audit    │ │ Receipt  │ │ Trust Chain      ││
│  │ Trail    │ │ Gate     │ │ (Genesis v2)     ││
│  │ (append) │ │ (enforce)│ │                  ││
│  └──────────┘ └──────────┘ └──────────────────┘│
└──────────────────────┬──────────────────────────┘
                       │ Clean prompt + active skills + tools
┌──────────────────────▼──────────────────────────┐
│             SINGLE OPERATOR (LLM)                │
│                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
│  │ Provider │ │ Prompt   │ │ Response         ││
│  │ Pool     │ │ Builder  │ │ Validator        ││
│  │ (multi)  │ │ (clean)  │ │ (post-check)     ││
│  └──────────┘ └──────────┘ └──────────────────┘│
│  ┌─────────────────────────────────────────────┐│
│  │ Learning Loop (episode → pattern → skill)   ││
│  └─────────────────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

### 2.2 Design Decisions

**LLM Backends: Both local and cloud from day one.**
The provider pool abstracts over Ollama/llama.cpp (local) and Anthropic/OpenAI (cloud) through a unified trait. Model selection is policy-driven — the WASM policy engine routes requests based on **action risk level**, not just data sensitivity. This is a critical insight from Peter Steinberg (OpenClaw): local models are smaller, less aligned, and easier to subvert through prompt injection and jailbreaking. The safety of an agent does not come from where the model runs — it comes from the enforcement layer around it. A small local model that's easy to fool but has unrestricted tool access is more dangerous than a cloud model with strong alignment and gated capabilities. Therefore, v2's default routing policy is risk-based: high-risk actions (tool execution, file writes, API calls, credential access) prefer stronger/cloud models; low-risk actions (chat, summarization, analysis) can use any model. The policy engine decides, and users can override with acknowledgment.

**Interface: CLI + API first.**
Launch surfaces are terminal CLI (for developers) and REST/WebSocket API (for integrations). Web dashboard for observability and administration comes in Phase 4. Slack/Discord channel adapters come alongside or after the dashboard. This serves the open source community first — developers want a CLI, not a web app — and keeps the initial surface area small. Channel adapters are thin and stateless when they arrive.

**Policy Authoring: Rust → WASM now, DSL later.**
Core policies ship as Rust compiled to WASM. This gives maximum expressiveness and performance for the foundational rules (action gating, capability scoping, routing policy). A declarative policy DSL (likely YAML or a simple rule language) comes in a later phase, compiling down to WASM, to make policy authoring accessible to non-Rust developers and enterprise admins.

**Trust Model: Tiered.**
- **Tier 0 (default)**: Permissive-by-default — allow everything, audit everything, block only catastrophic actions. Zero ceremony. Install and run. The user doesn't know governance exists until they need it (see §13).
- **Tier 1 (signed)**: WASM policy modules are signed by a local key. Skills are signed. The audit trail includes signature verification. For individuals who want provenance.
- **Tier 2 (Genesis)**: Full signing chain with a human authority root. Policy modules, skills, and audit entries are chained to a Genesis root. For enterprises and high-trust deployments.

Tier 0 is the out-of-box experience. Tiers 1 and 2 are opt-in. The runtime enforces whatever tier is configured — the LLM never knows which tier it's operating under.

---

## 3. The Deterministic Core

### 3.1 Request Pipeline

v2 replaces multi-role routing with a single-operator model. There are no handoffs, no role dispatching, no identity switching. One operator, one conversation, one context. Specialization lives in **skills**, not in separate identities.

The request pipeline receives structured messages from the interface layer and prepares them for the operator:

```rust
pub struct Pipeline {
    policy: PolicyEngine,
    skills: SkillRegistry,
}

impl Pipeline {
    /// Prepare a request for the operator.
    /// Policy gates what's allowed. Skills provide domain-specific tooling.
    pub fn prepare(&self, request: &Request) -> PipelineResult {
        // 1. Check policy: is this request allowed at all?
        let policy_result = self.policy.evaluate(request);
        if policy_result.is_denied() {
            return PipelineResult::Denied(policy_result.reason());
        }

        // 2. Select applicable skills based on request content
        let active_skills = self.skills.match_request(request);

        // 3. Build capability manifest from policy + active skills
        let capabilities = self.policy.capabilities_for(request, &active_skills);

        // 4. Select model based on risk level of available capabilities
        let model_preference = self.policy.model_for(request, &capabilities);

        PipelineResult::Ready {
            capabilities,
            active_skills,
            model_preference,
        }
    }
}
```

**Key difference from v1**: No routing decisions. No handoff protocol. No role identity mapping. The operator handles everything, with the policy engine controlling what tools and skills are available per-request. When a request involves security concerns, the operator gets security skills activated — it doesn't hand off to a different personality.

### 3.2 Policy Engine (WASM)

The policy engine loads and executes WASM policy modules. Each module implements a standard interface:

```rust
/// The interface every WASM policy module must implement
#[wasm_bindgen]
pub trait Policy {
    /// Evaluate a request against this policy.
    /// Returns Allow, Block, Warn, Review, or Sanitize (see §12.2).
    fn evaluate(&self, context: &PolicyContext) -> PolicyDecision;

    /// Return the capabilities this policy grants for the given role + request.
    fn capabilities(&self, role: &str, context: &PolicyContext) -> Vec<Capability>;

    /// Policy metadata for audit trail
    fn metadata(&self) -> PolicyMetadata;
}

pub struct PolicyContext {
    pub request: Request,
    pub role_id: String,
    pub trust_tier: TrustTier,
    pub session: SessionContext,
    // No LLM state. No prompt content. Pure structured data.
}
```

**Policy modules are the new authority matrices.** Instead of YAML files parsed into prompt text, an authority matrix is a compiled WASM module that returns `Allow` or `Deny` for a given role + action combination. The advantage: it's deterministic, auditable, signable, and hot-reloadable.

**Hot reload**: Policy modules can be swapped at runtime without restarting the server. The policy engine watches a directory (or receives updates via the trust chain) and loads new modules. This is how enterprise fleet-wide policy updates work — push a new signed WASM module, all nodes pick it up.

### 3.3 Skill Registry & Lifecycle

Skills are the primary unit of reusable behavior in v2. A skill is a WASM module that:

1. Declares its capabilities (what tools it needs, what inputs it expects)
2. Optionally includes an LLM prompt template (for skills that need reasoning)
3. Includes deterministic pre/post processing logic
4. Has metadata (version, author, signature, performance stats)

```rust
pub struct Skill {
    pub id: SkillId,
    pub version: SemanticVersion,
    pub manifest: SkillManifest,    // capabilities, inputs, outputs
    pub module: WasmModule,          // compiled behavior
    pub prompt_template: Option<String>, // if LLM reasoning needed
    pub signature: Option<Signature>,    // trust chain
    pub stats: SkillStats,           // success rate, avg latency, usage count
}

pub enum SkillOrigin {
    BuiltIn,                  // Ships with ZeroPoint
    Extracted(Vec<EpisodeId>),// Learned from interaction patterns
    Community(AuthorId),      // Community-contributed
    Enterprise(OrgId),        // Org-specific
}
```

**The Skill Lifecycle (the "soul"):**

```
  Interaction
      │
      ▼
  Episode (recorded)
      │
      ▼
  Pattern Detection (N similar episodes)
      │
      ▼
  Skill Candidate (proposed extraction)
      │
      ▼
  Human Review (approve / reject / refine)
      │
      ▼
  Compiled Skill (WASM module)
      │
      ▼
  Signed & Deployed ←── A/B tested against baseline
      │
      ▼
  Usage Telemetry ──→ feeds back into Pattern Detection
```

**Skill extraction is auto-propose, human-approve** (confirmed design decision). The system detects patterns and proposes skill candidates automatically. Humans review and approve (or reject/refine) before deployment. This keeps the human in the loop for quality and trust while allowing the system to surface opportunities the human might miss. Over time, the pattern detector improves its proposals based on approval/rejection signals.

This is the compounding loop. The system gets better because every interaction is a potential skill input, and every skill is a versioned, testable, deployable artifact — not a markdown file or a prompt injection.

### 3.4 Audit Trail

The audit trail is structural, not optional. Every action passes through it:

```rust
pub struct AuditEntry {
    pub id: AuditId,
    pub timestamp: Timestamp,
    pub prev_hash: Hash,          // chain link
    pub entry_hash: Hash,         // self hash
    pub actor: ActorId,           // role, user, or system
    pub action: Action,           // what happened
    pub policy_decision: PolicyDecision, // why it was allowed/denied
    pub policy_module: PolicyModuleId,   // which policy decided
    pub receipt: Option<Receipt>, // execution proof (if applicable)
    pub signature: Option<Signature>,    // trust tier dependent
}
```

**Audit is always on** (confirmed design decision). Hash-chained audit runs at every trust tier, including Tier 0. It's lightweight (append-only SQLite) and the foundation for everything else — the learning loop needs episodes, debugging needs traces, compliance needs records. There's no reason to make it optional. What's tiered is the *signing*: Tier 0 gets hash chaining (tamper-evident). Tier 1 adds local key signatures. Tier 2 adds Genesis chain signatures. But the audit trail itself is structural and non-negotiable.

**Key difference from v1**: In v1, the audit trail recorded what happened. In v2, the audit trail is *part of what happens* — the receipt gate won't release an action claim without an audit entry, and the audit entry won't be created without a policy decision. It's structurally impossible to act without a trace.

### 3.5 Trust Chain (Genesis v2)

Genesis v2 is a signing chain for WASM modules, not a ceremony for prompt injection.

```
Genesis Root Key (human-held)
    │
    ├── signs → Core Policy Modules
    │              └── e.g., action-gate.wasm, capability-scope.wasm
    │
    ├── signs → Role Manifests
    │              └── which roles exist, what skills they can use
    │
    ├── signs → Skills
    │              └── versioned, with provenance metadata
    │
    └── signs → Delegation Keys
                   └── for team members, CI/CD, etc.
```

**Tier 0**: No signing. Modules load from local filesystem. Trust = you control the machine.
**Tier 1**: Local key signs modules. Tamper detection via hash verification.
**Tier 2**: Genesis root key, delegation chain, all modules signed. Full provenance for every policy decision and skill execution.

The LLM never sees any of this. It just sees: "here are your tools for this request." Whether those tools were selected by an unsigned local policy or a Genesis-signed enterprise policy is invisible to the reasoning layer.

**Credential isolation** integrates with the trust chain: signing keys and credential vault keys are separate. A Genesis-signed policy module can declare which credentials a skill is authorized to access, and the credential injector enforces this at the host boundary (see §12.1). Credentials never enter WASM memory.

---

## 4. The LLM Layer

### 4.1 Provider Pool

```rust
pub struct ProviderPool {
    providers: Vec<Box<dyn LlmProvider>>,
    routing_policy: PolicyEngine, // yes, WASM policy decides model routing too
}

pub trait LlmProvider: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> ProviderCapabilities;
    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse>;
    fn health(&self) -> ProviderHealth;
}

// Implementations:
// - OllamaProvider (local)
// - LlamaCppProvider (local, direct GGUF)
// - AnthropicProvider (cloud)
// - OpenAiProvider (cloud)
```

Model routing is **risk-based by default** (confirmed design decision):

| Action Risk | Default Routing | Rationale |
|-------------|----------------|-----------|
| High-risk (tool exec, file write, API call) | Stronger model (cloud preferred) | Small models are easier to subvert; high-risk actions need strong alignment |
| Medium-risk (code generation, analysis) | Best available | Balance capability with cost |
| Low-risk (chat, summarization) | Any model | Low stakes, optimize for speed/cost |
| Data-sensitive (PII, credentials) | Local model | Data never leaves the machine |
| User override | Acknowledged | User can force any model with explicit acknowledgment of risk |

The policy engine evaluates both action risk AND data sensitivity. A request that involves sensitive data AND high-risk actions gets the strongest available model that satisfies the data locality constraint — or gets denied if no model meets both requirements.

### 4.2 Prompt Builder

The prompt builder constructs clean, minimal prompts. What it includes:

```rust
pub struct PromptBuilder;

impl PromptBuilder {
    pub fn build(role: &Role, request: &Request, capabilities: &[Capability]) -> Prompt {
        let mut prompt = Prompt::new();

        // 1. Identity: who you are, what you're good at
        prompt.set_system(role.identity_prompt());

        // 2. Available tools: what you CAN do right now
        //    (filtered by policy engine — the LLM only sees allowed tools)
        prompt.set_tools(capabilities.to_tool_definitions());

        // 3. Conversation history: recent messages
        prompt.set_history(request.conversation_history());

        // 4. User message
        prompt.set_user_message(request.content());

        // NOTHING ELSE. No governance text. No operating modes.
        // No verification status. No capability classifications.
        // No canonical knowledge about how the system works.

        prompt
    }
}
```

**What's NOT in the prompt:**
- Operating mode labels (READ_ONLY, RESTRICTED, FULL)
- Verification status (TRUSTED, UNTRUSTED, DEVELOPMENT)
- Capability classification tables (OBSERVE, WRITE_LOCAL, etc.)
- Genesis Protocol status
- Self-referential documentation about context assembly
- ADR text
- Steering directive text

All of that is enforced by the deterministic core. The LLM gets a clean workspace.

### 4.3 Response Validator

After the LLM responds, the response validator checks the output against policy:

```rust
pub struct ResponseValidator {
    policy: PolicyEngine,
    receipt_gate: ReceiptGate,
}

impl ResponseValidator {
    pub fn validate(&self, response: &LlmResponse, context: &RequestContext) -> ValidationResult {
        // 1. Did the LLM try to invoke a tool it wasn't given?
        //    (Shouldn't be possible, but defense in depth)
        self.check_tool_usage(response, context)?;

        // 2. Does the response claim to have done something?
        //    If so, is there a receipt?
        self.receipt_gate.verify_claims(response)?;

        // 3. Content safety check (deterministic rules + optional LLM judge)
        self.check_content_safety(response)?;

        // 4. Route suggestion extraction
        //    If the LLM suggests routing to another role, extract it
        //    as structured data (not regex on markers)
        let route_suggestion = self.extract_route_suggestion(response);

        ValidationResult::ok(response, route_suggestion)
    }
}
```

### 4.4 Learning Loop

The learning loop is what gives v2 its soul:

```rust
pub struct LearningLoop {
    episode_store: EpisodeStore,
    pattern_detector: PatternDetector,
    skill_compiler: SkillCompiler,
}

impl LearningLoop {
    /// Called after every completed interaction
    pub fn record(&self, episode: Episode) {
        // Store the episode
        self.episode_store.append(episode.clone());

        // Check for emerging patterns
        if let Some(pattern) = self.pattern_detector.check(&episode) {
            // Pattern detected — is it strong enough to become a skill?
            if pattern.confidence >= SKILL_THRESHOLD && pattern.occurrence_count >= MIN_OCCURRENCES {
                // Propose skill extraction
                let candidate = self.skill_compiler.propose(pattern);
                // Queue for human review (not auto-deployed)
                self.queue_skill_candidate(candidate);
            }
        }
    }
}

pub struct Episode {
    pub id: EpisodeId,
    pub request: Request,
    pub role: RoleId,
    pub tools_used: Vec<ToolInvocation>,
    pub response: Response,
    pub outcome: Outcome,      // success/failure/partial
    pub user_feedback: Option<Feedback>, // thumbs up/down, corrections
    pub duration: Duration,
    pub model_used: ProviderId,
    pub policy_decisions: Vec<PolicyDecision>,
}
```

**Pattern detection** looks for:
- Repeated similar requests that succeed with the same tool sequence
- Requests that consistently get routed to the same role
- Common pre/post processing patterns (e.g., "always validate JSON before sending to API")
- Failure patterns (e.g., "this model consistently fails at X, route to Y instead")

**Skill extraction** turns a pattern into a WASM module:
- The deterministic parts (tool sequence, validation, pre/post processing) become compiled code
- The reasoning parts (if any) become a prompt template
- The result is a versioned, testable artifact

---

## 5. The Single Operator

v1 had five officers with ten names (five officer names + five server role IDs), a handoff protocol, routing logic, and context fragmentation across separate conversations. v2 collapses all of this into a single operator.

```rust
pub struct Operator {
    pub identity: OperatorIdentity,  // Name, personality, base prompt
    pub skills: SkillRegistry,       // All available skills
    pub conversation: ConversationId, // One continuous conversation
}

pub struct OperatorIdentity {
    pub name: String,           // "ZeroPoint" or user-customizable
    pub base_prompt: String,    // Clean identity prompt — who you are, what you can do
    // No operating modes. No verification status. No governance text.
}
```

**Why one operator instead of five roles:**

- **Zero routing overhead.** No LLM cycles spent deciding who handles a request. No handoff protocol. No regex markers. No dual naming.
- **Continuous context.** One conversation means the operator knows everything that's been discussed. No context fragmentation across separate role conversations.
- **Specialization via skills, not identity.** When a request involves security, the operator gets security skills activated by the policy engine. When it involves code review, it gets engineering skills. Same operator, different toolkits — decided deterministically by the pipeline, not by LLM self-routing.
- **Simpler for users.** Users talk to one entity. No "ask Atlas to route you to Aegis." No wondering which officer handles what.
- **Model quality where it matters.** Risk-based routing selects the model per-request. A security-sensitive request gets a stronger model regardless of the "role" — because there's only one role, and model selection is based on action risk.

---

## 6. Module Structure

```
zeropoint/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── zp-core/                  # Shared types, traits, error types
│   │   └── src/lib.rs
│   ├── zp-pipeline/              # Request pipeline (policy + skill selection)
│   │   └── src/lib.rs
│   ├── zp-policy/                # WASM policy engine
│   │   └── src/lib.rs
│   ├── zp-skills/                # Skill registry, lifecycle, compilation
│   │   └── src/lib.rs
│   ├── zp-audit/                 # Hash-chained audit trail
│   │   └── src/lib.rs
│   ├── zp-trust/                 # Genesis v2, signing, verification
│   │   └── src/lib.rs
│   ├── zp-llm/                   # Provider pool, prompt builder, response validator
│   │   └── src/lib.rs
│   ├── zp-learning/              # Episode store, pattern detection, skill extraction
│   │   └── src/lib.rs
│   ├── zp-server/                # HTTP/WS server (thin — delegates to crates)
│   │   └── src/main.rs           # Hundreds of lines, not thousands
│   └── zp-cli/                   # Terminal CLI interface
│       └── src/main.rs
├── policies/                     # Default WASM policy modules (source)
│   ├── default-gate/             # Default action gating policy
│   └── capability-scope/         # Default capability scoping
├── skills/                       # Built-in skills (source)
│   ├── file-ops/
│   ├── code-review/
│   └── security-scan/
└── docs/
```

**Key differences from v1**: No 8000-line `main.rs`. No role manager. No role manifest. No routing crate. Each concern is a focused crate with clear boundaries. `zp-server` is a thin orchestrator that wires the crates together. The single operator replaces five roles, and skills replace domain-specific identities.

---

## 7. Data Model

### 7.1 Storage

```
~/.zeropoint/                     # User data directory
├── config.toml                   # Configuration
├── zeropoint.db                  # SQLite — conversations, messages, settings
├── audit.db                      # SQLite — append-only audit trail
├── episodes.db                   # SQLite — learning loop data
├── policies/                     # Compiled WASM policy modules
│   ├── default-gate.wasm
│   └── capability-scope.wasm
├── skills/                       # Compiled WASM skill modules
│   ├── built-in/
│   ├── extracted/                # Skills extracted from patterns
│   └── community/                # Community-contributed skills
├── trust/                        # Trust chain data
│   ├── keys/                     # Signing keys (tier 1+)
│   └── genesis/                  # Genesis manifest (tier 2)
└── channels/                     # Channel-specific config
    ├── slack.toml
    └── discord.toml
```

### 7.2 Message Flow

```
User sends message (via CLI, API, or channel adapter)
    │
    ▼
Request Pipeline:
    ├── Policy Engine: is this allowed? → Deny → respond with denial
    ├── Skill selection: which skills apply to this request?
    ├── Capability manifest: what tools are available (policy-gated)?
    └── Model selection: which model, based on action risk level?
            │
            ▼
        Prompt Builder: clean prompt (operator identity + tools + history + message)
            │
            ▼
        Provider Pool: send to selected model
            │
            ▼
        Operator responds (single identity, continuous context)
            │
            ▼
        Response Validator:
            ├── Tool usage check (defense in depth)
            ├── Receipt verification (if action claims)
            └── Content safety
                    │
                    ▼
        Response → user (via same channel)
            │
            ▼
        Audit Trail: record everything (always on, hash-chained)
            │
            ▼
        Learning Loop: record episode, check for emerging patterns
```

---

## 8. Migration Path

v2 is a clean-slate rebuild, but the transition doesn't have to be abrupt:

1. **Phase 1 — Core runtime**: `zp-core`, `zp-router`, `zp-policy`, `zp-llm`, `zp-server`, `zp-cli`. Basic message flow works: user sends message via CLI or API, router dispatches to role, LLM responds, audit trail records. No skills, no learning loop, no Genesis. This is the "it works" milestone.

2. **Phase 2 — Trust & Skills**: `zp-trust`, `zp-skills`, `zp-audit` with hash chaining. WASM policy modules replace hardcoded routing. Built-in skills ship. Trust tier 0 and 1 operational. This is the "it's useful" milestone.

3. **Phase 3 — Learning Loop**: `zp-learning` with episode recording, pattern detection, skill extraction. The system starts improving itself. This is the "it's alive" milestone.

4. **Phase 4 — Channels & Dashboard**: Slack/Discord adapters, web dashboard for observability. Channel-first interaction. This is the "it's accessible" milestone.

5. **Phase 5 — Enterprise & Genesis**: Trust tier 2, fleet management, policy distribution, Genesis v2 ceremony. This is the "it's enterprise-ready" milestone.

---

## 9. What Makes This Different

**From v1 ZeroPoint**: Governance moves from prose to code. The LLM gets clean prompts. Skills are compiled artifacts, not markdown. The system learns from itself.

**From OpenClaw**: ZeroPoint has a trust layer. OpenClaw's agents run with your credentials and hope for the best. ZeroPoint's WASM policy engine provides deterministic, auditable enforcement of what agents can and cannot do. The signing chain gives provenance. The receipt gate gives proof. OpenClaw gives you a capable agent. ZeroPoint gives you a capable agent you can *verify*.

**From Hyperagent**: ZeroPoint is open source and local-first. Your data stays on your machine (or your infrastructure). The skill lifecycle is community-driven, not vendor-locked. The enterprise layer is a service on top of an open core, not a proprietary platform.

The synthesis: OpenClaw's self-evolvability + Hyperagent's skill lifecycle + ZeroPoint's trust guarantees, built on a deterministic WASM core that makes all three properties verifiable rather than aspirational.

---

## 10. The Local Model Safety Insight

A critical architectural assumption of v1 was "local model = safe because your data stays on your machine." Peter Steinberg's work on OpenClaw revealed this is a half-truth at best. Local models are typically smaller, less aligned, and significantly easier to subvert. A malicious document processed by a 7B local model can more easily trigger prompt injection than the same document processed by Claude or GPT-4. The model's *location* doesn't determine its *trustworthiness*.

This insight has three architectural consequences for v2:

1. **The deterministic core is the security boundary, not the model.** The WASM policy engine gates actions before and after the LLM, regardless of which model is running. A subverted model can produce malicious output, but the response validator blocks unauthorized actions before they execute. This makes ZeroPoint's trust layer valuable even (especially) for users running small local models.

2. **Risk-based model routing is a safety feature, not just an optimization.** When a request involves high-risk actions (file deletion, API calls with credentials, code execution), the routing policy can require a stronger model — not because cloud models are inherently trustworthy, but because they have better alignment training and are harder to subvert through content injection. The deterministic core provides the hard guarantee; the model routing provides defense in depth.

3. **ZeroPoint's market position is clearer than we thought.** The open source agent community (OpenClaw, LangChain, CrewAI users) is running local models with real credentials and minimal guardrails. ZeroPoint doesn't compete with these frameworks — it wraps them with a trust layer that makes them safer. "Run your favorite agent framework. ZeroPoint makes sure it can't go rogue." That's the pitch for individuals. For enterprises: "Your developers are already running local agents. ZeroPoint gives you visibility and control."

---

## 11. Competitive Landscape

The agent framework space has exploded since OpenClaw's emergence, with derivatives spanning every systems language. Understanding the landscape clarifies where ZeroPoint v2 fits — and where it doesn't compete.

### 11.1 The Players

**OpenClaw** (TypeScript/Node.js) — the gravity well. 175K+ GitHub stars, massive plugin ecosystem, local gateway architecture. Its strengths are community velocity and the skill extraction loop that gives it "soul" — the system genuinely improves through use. Its weaknesses are equally clear: 1GB+ RAM baseline, a serious credential exposure vulnerability (CVE-2026-25253, CVSS 8.1), and governance-by-hope — agents run with full user credentials and there's no enforcement layer between the LLM and the tools. OpenClaw founder Peter Steinberger's move to OpenAI signals the project's influence but also its transition to corporate stewardship.

**IronClaw** (Rust, Near AI) — the security-conscious fork. IronClaw is ZeroPoint v2's closest philosophical neighbor: Rust core, WASM sandboxing via wasmtime with fuel metering, trait-based extensibility, multi-provider LLM pool. Key architectural patterns worth studying:

- **Credential injection at host boundary**: Secrets are injected by the Rust host into WASM function calls at the moment of execution. The WASM module never holds credentials in memory — it receives them as parameters to capability-gated functions. This is the gold standard for secret isolation in agent systems.
- **~60-method Database trait**: Aggressive trait-based abstraction with PostgreSQL and libSQL backends. Enables swappable storage without runtime polymorphism overhead.
- **Severity-based safety policies**: Actions classified as Block/Warn/Review/Sanitize rather than binary allow/deny. This gives operators graduated control over agent behavior.
- **Channel/Tool/LlmProvider/SuccessEvaluator traits**: Clean separation of concerns through Rust's trait system rather than inheritance or configuration.

IronClaw's weakness: it requires PostgreSQL + Docker for production use. This is a significant deployment barrier for individual users and small teams — exactly the audience ZeroPoint targets first.

**ZeroClaw** (Rust, Harvard/MIT) — the minimalist. Under 5MB RAM, swappable trait-based architecture, the most sophisticated hybrid memory system in the ecosystem (combining episodic, semantic, and procedural memory). ZeroClaw proves you can build a capable Rust agent without the infrastructure weight. Its weakness is a small team and academic release cadence.

**PicoClaw** (Go) — the pragmatist. Under 10MB RAM, single binary, 95% AI-generated code. PicoClaw validates the single-binary distribution model and demonstrates that Go's compilation speed enables rapid iteration. Less architecturally interesting but commercially relevant as a proof point for lightweight deployment.

**NullClaw** (Zig) — the extremist. 1MB RAM, 678KB binary. Proves that agent frameworks can be genuinely tiny. Academic interest more than production relevance, but a useful benchmark for how much overhead is actually necessary.

**NanoBot** (Python) — the educator. 4K lines, purely pedagogical. Useful as a reference for "what's the simplest possible agent" but not a competitor.

**Runlayer** — the enterprise wrapper. A governance layer around OpenClaw that adds ToolGuard (per-tool approval policies), audit logging, and fleet management. Runlayer validates ZeroPoint's core thesis: the market wants governance around existing agent capabilities. Runlayer does it as a wrapper; ZeroPoint does it as a foundation.

### 11.2 Comparison Matrix

| Dimension | OpenClaw | IronClaw | ZeroClaw | **ZeroPoint v2** |
|-----------|----------|----------|----------|-------------------|
| **Language** | TypeScript | Rust | Rust | Rust |
| **Memory baseline** | 1GB+ | ~50MB | <5MB | Target: <20MB |
| **WASM sandboxing** | No | Yes (wasmtime) | No | Yes (wasmtime) |
| **Policy enforcement** | None (trust LLM) | Severity-based | Trait-gated | WASM policy engine |
| **Credential isolation** | Env vars (exposed) | Host-boundary injection | Config-based | Host-boundary injection |
| **Trust/signing** | None | None | None | Tiered (0/1/2) + Genesis |
| **Skill extraction** | Yes (core feature) | No | No | Yes (auto-propose, human-approve) |
| **Audit trail** | Plugin-based | Database logging | None | Structural, hash-chained, always-on |
| **Required infra** | Node.js | PostgreSQL + Docker | None | None (SQLite local-first) |
| **Model routing** | User-configured | Provider trait | Swappable | Risk-based (policy-driven) |
| **Target user** | Developers | Platform builders | Researchers | Individuals → Enterprise |
| **Governance model** | Hope | Traits + DB | Traits | Deterministic WASM |

### 11.3 Where ZeroPoint v2 Differentiates

ZeroPoint v2 doesn't compete with OpenClaw on community size or plugin count. It doesn't compete with IronClaw on raw platform extensibility. It competes on **trust infrastructure that works without infrastructure**.

The differentiation stack:

1. **No PostgreSQL. No Docker. No Node.js.** Install and run. SQLite local-first, single binary target. This is a hard requirement for individual users and a strong preference for enterprise evaluation.

2. **Skill extraction loop.** Only OpenClaw has this today. ZeroPoint v2 adds it with deterministic compilation (WASM) and human-in-the-loop approval, making extracted skills auditable and signable.

3. **Trust chain with Genesis signing.** Nobody else has this. The signing chain (from Genesis root → policy modules → skills → audit entries) provides cryptographic provenance for every policy decision and skill execution. This is the enterprise unlock.

4. **Trust by design, not by wrapper.** Runlayer wraps OpenClaw with governance after the fact. ZeroPoint builds governance into the execution path — the policy engine evaluates before the LLM runs, and the response validator checks after. You can't bypass it because it's structural.

5. **Risk-based model routing.** Nobody else routes based on action risk level. This is a genuine safety innovation, not just an optimization — it means a compromised local model can't execute high-risk actions because the policy engine routes those to stronger models.

---

## 12. IronClaw-Inspired Additions to the Deterministic Core

Two patterns from IronClaw's architecture are worth adopting directly, adapted to ZeroPoint v2's design.

### 12.1 Credential Injection at Host Boundary

In v1, credentials were stored in configuration and loaded into environment or context. In v2, credentials are **never exposed to WASM modules** — they're injected by the Rust host at the moment of tool execution.

```rust
/// The host-side credential injector.
/// WASM modules declare what credentials they need; the host provides them
/// at call time. The WASM module never stores or accesses credentials directly.
pub struct CredentialInjector {
    vault: CredentialVault,  // Encrypted at rest, decrypted only in host memory
}

impl CredentialInjector {
    /// Inject credentials into a tool invocation at execution time.
    /// The WASM module receives the credential as a function parameter,
    /// uses it for the API call, and the parameter is dropped after the call.
    pub fn inject(&self, invocation: &ToolInvocation) -> Result<EnrichedInvocation> {
        let required_creds = invocation.tool.required_credentials();

        for cred_ref in &required_creds {
            // Check policy: is this module allowed to use this credential?
            let allowed = self.policy.can_access_credential(
                &invocation.skill_id,
                cred_ref,
                &invocation.context,
            );

            if !allowed {
                return Err(CredentialError::PolicyDenied {
                    skill: invocation.skill_id.clone(),
                    credential: cred_ref.clone(),
                });
            }
        }

        // Decrypt and inject — credential exists in host memory only
        let injected = self.vault.decrypt_and_inject(
            &required_creds,
            invocation,
        )?;

        Ok(injected)
    }
}
```

**Why this matters**: In OpenClaw, credentials live in environment variables accessible to every plugin. CVE-2026-25253 exploited this — a malicious plugin could read credentials intended for other plugins. IronClaw's host-boundary injection prevents this structurally: a WASM module literally cannot access memory outside its sandbox. Credentials enter as function parameters and are dropped after use. ZeroPoint v2 adopts this pattern and adds policy gating — even the host won't inject a credential unless the policy engine confirms the requesting skill is authorized to use it.

### 12.2 Severity-Based Safety Policies

v1's policy model was binary: allowed or denied. IronClaw introduced a graduated model that v2 adopts and extends:

```rust
/// Policy decision with graduated severity levels.
/// Replaces binary Allow/Deny with nuanced responses.
pub enum PolicyDecision {
    /// Action is permitted. Proceed normally.
    Allow {
        conditions: Vec<Condition>,  // Optional: conditions that must hold
    },

    /// Action is blocked. Cannot proceed under any circumstances.
    /// Used for hard safety boundaries (e.g., "never delete production database").
    Block {
        reason: String,
        policy_ref: PolicyModuleId,
    },

    /// Action is permitted but flagged. User is warned before execution.
    /// Used for risky-but-legitimate actions (e.g., "this will modify 500 files").
    Warn {
        message: String,
        proceed_after_ack: bool,  // Does user need to acknowledge?
    },

    /// Action requires human review before execution.
    /// Used for high-impact actions where automation is valuable
    /// but human judgment is needed (e.g., "deploy to production").
    Review {
        summary: String,
        reviewer: ReviewTarget,  // Current user, team lead, etc.
        timeout: Option<Duration>,
    },

    /// Action is permitted but output must be sanitized.
    /// Used for actions that might leak sensitive data in their output
    /// (e.g., "query database but redact PII in results").
    Sanitize {
        action: SanitizeAction,
        patterns: Vec<SanitizePattern>,  // What to redact/mask
    },
}
```

**The graduated model maps to real-world needs:**

| Severity | Use Case | Example |
|----------|----------|---------|
| Allow | Normal operations | Read a file, summarize text |
| Block | Hard safety boundaries | Delete production data, access unauthorized systems |
| Warn | Risky but legitimate | Bulk file modifications, large API calls |
| Review | High-impact, needs human judgment | Production deployments, security configuration changes |
| Sanitize | Output contains sensitive data | Database queries with PII, log analysis with credentials |

**Key addition over IronClaw**: ZeroPoint v2 ties each `PolicyDecision` to an audit entry. A `Warn` that the user acknowledges is logged with the acknowledgment. A `Review` records who reviewed and when. A `Sanitize` logs what was redacted. This creates a complete compliance record — the audit trail doesn't just show what happened, it shows the governance decisions that surrounded it.

---

## 13. Governance Positioning: The Weightless Parachute

### 13.1 The Problem with "Governance"

A significant segment of ZeroPoint's target audience — open source developers running local agents — is actively hostile to governance. This hostility is rational. The governance they've encountered is compliance theater: bolted-on permission layers that slow them down without making anything meaningfully safer. Enterprise RBAC with three-week change cycles. Security reviews that gate deployment but catch nothing. Audit trails that exist for auditors but that nobody reads.

When developers say "governance is pollution in my toolstream," they're reporting an accurate experience of bad governance. The mistake is generalizing to "all governance is overhead." That's like saying "all type systems are overhead" because you used Java in 2005. Rust's borrow checker proves that constraints can be *enabling* — you move faster because you're not debugging memory corruption at 2am.

### 13.2 The Design Principle: Invisible When You're Inside the Lines

Governance that developers don't notice is governance they won't strip out. ZeroPoint v2's enforcement layer must be **zero-friction for normal operations**:

- The policy engine evaluates in microseconds. No perceptible latency.
- The audit trail appends silently. No prompts, no confirmations, no UI.
- The credential injector decrypts and injects without user interaction.
- The operator never says "POLICY CHECK" or "GOVERNANCE MODULE EVALUATING." Clean prompts mean the LLM doesn't know governance exists.

Governance becomes *visible* only where visibility has value: the graduated `Warn` and `Review` decisions surface when something risky is about to happen. "You're about to delete 500 files — proceed?" That's not pollution. That's the system saving you from yourself at 2am.

### 13.3 Tier 0: Permissive by Default

The out-of-box policy must be genuinely permissive:

- **Allow everything** except catastrophic actions (credential exfiltration, recursive self-modification, unbounded resource consumption).
- **Audit everything** silently. The trail runs whether the user knows it or not.
- **Block nothing** that a reasonable developer would expect to work on first run.

The conversion moment is not installation. It's the first time something goes wrong — data loss, credential leak, a rogue agent loop — and the user discovers the audit trail was running the whole time. "Here's exactly what happened, here's the trace, here's where it went sideways." That's when governance converts from "overhead I'd strip out" to "thank god that was there."

You don't sell governance. You sell the parachute, and you make it weightless until you need it.

### 13.4 Language Strategy

**Internal terminology** (architecture docs, code, APIs): Use precise terms — policy engine, audit trail, trust chain, governance, enforcement. Engineers reading source code expect technical precision.

**User-facing language** (README, docs, CLI output, website, pitch): Never use "governance." The vocabulary is:

| Internal Term | User-Facing Term | Why |
|---------------|-----------------|-----|
| Governance | Trust infrastructure | "Governance" implies bureaucracy; "trust" implies reliability |
| Policy engine | Safety layer | "Policy" sounds corporate; "safety" sounds protective |
| Audit trail | Activity log | "Audit" sounds compliance; "activity" sounds informational |
| Policy decision | Safety check | Neutral, descriptive |
| Enforcement | Protection | "Enforcement" implies authority over user; "protection" implies service to user |
| Genesis signing chain | Verification chain | "Genesis" is fine for the protocol name, but "verification" describes the value |

The CLI should never print "POLICY DENIED" — it should print "This action is blocked by your safety configuration." The difference is who has authority: the first implies the system controls the user; the second implies the user controls the system.

### 13.5 Market Segmentation

**Developers who strip out governance** were never the customer. Don't design for them, don't chase them, don't compromise the architecture to appease them. They'll use OpenClaw with raw credentials and that's fine — it's their risk to take.

**Developers who leave governance in because they don't notice it** — these are the core open source users. Tier 0 serves them. The product is weightless until it saves them.

**Enterprises who see the audit trail and realize they can let developers run agents without losing sleep** — this is the business. Tier 1 and 2 serve them. The product is "your developers are already running local agents; ZeroPoint gives you visibility and control without slowing them down."

The open source community builds adoption. The enterprise layer builds revenue. The trust chain connects them — same core, different surface, as stated in §1.

---

## 14. Confirmed Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| LLM backends | Both local + cloud from day one | Table stakes for trust-focused platform |
| Model routing | Risk-based (action risk level) | Local models are easier to subvert; high-risk actions need stronger alignment |
| Launch interface | CLI + API first | Serves open source community; minimal surface area |
| Policy authoring | Rust → WASM now, DSL later | Maximum power first, accessibility later |
| Trust model | Tiered (0/1/2) | Simple default, powerful opt-in |
| Audit trail | Always on, signing tiered | Foundation for learning, debugging, compliance |
| Skill extraction | Auto-propose, human-approve | System surfaces opportunities, human controls quality |
| Agent topology | Single operator, skills for specialization | Eliminates routing overhead, context fragmentation, handoff bugs |
| Governance enforcement | Deterministic (WASM), never prompt text | v1's core failure was governance-as-prose |
| Credential model | Host-boundary injection (IronClaw-inspired) | WASM modules never hold secrets; policy-gated at injection |
| Policy granularity | Graduated (Block/Warn/Review/Sanitize) | Binary allow/deny is too blunt for real-world operations |
| Infrastructure requirements | None (SQLite, single binary) | Differentiator vs IronClaw (PostgreSQL+Docker) and OpenClaw (Node.js) |
| Default posture | Permissive (allow all, audit all, block catastrophic) | Invisible governance converts users; visible governance repels them |
| User-facing language | Never "governance" — use "trust," "safety," "protection" | Emotional register matters as much as technical architecture |
