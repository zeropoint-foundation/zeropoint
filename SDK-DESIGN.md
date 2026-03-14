# ZeroPoint Governance SDK

## Design Document — v0.1

**Author:** Ken Romero, ThinkStream Labs
**Date:** March 2026
**Status:** Draft

---

## 1. What ZeroPoint Is

ZeroPoint is a governance SDK that provides cryptographic primitives for securing autonomous agent systems. It gives agent developers identity, policy enforcement, capability delegation, tamper-evident audit chains, and signed receipts — all built on a constitutional alignment bedrock that custom governance layers cannot weaken.

ZeroPoint is not an agent framework. It does not orchestrate agents, manage conversations, or provide a runtime. It secures whatever runtime the developer is already using — OpenClaw, Agent Zero, LangGraph, CrewAI, or custom systems — by sitting underneath as trust infrastructure.

Once the environment is secured, ZeroPoint becomes a silent guardian. It surfaces only when governance requires human attention: policy violations, approval requests, anomalous behavior, or administrative changes.

---

## 2. Design Principles

**Infrastructure, not framework.** ZeroPoint provides primitives that other systems consume. It never competes with the developer's chosen agent orchestration layer.

**Constitutional immutability.** The governance bedrock — harm prevention, sovereignty, catastrophic action prevention — is compiled into the binary, not configurable. Custom policy layers compose on top but can never weaken the foundation.

**Familiar vocabulary.** Every ZeroPoint concept maps to something developers already know: middleware, scoped credentials, certificate chains, signed audit logs. No new mental models required.

**Silent by default.** After initial setup, ZeroPoint operates through API calls with zero UI overhead. Diagnostic and administrative surfaces exist but are not part of the runtime path.

**Trust the math, not the code.** Custom governance gates run in WASM sandboxes. They cannot access the filesystem, make network calls, or escape their boundary. ZeroPoint does not trust policy code — it constrains it.

---

## 3. Core Concepts

### 3.1 Governance Gate (Policy Middleware)

A governance gate is a function that evaluates whether an agent action should proceed. Gates receive a policy context and return a decision: allow, block, or require human approval.

Gates are the primary extension point. Developers write custom gates to express domain-specific rules — spending limits, data classification, geographic restrictions, rate limiting — and ZeroPoint executes them within a sandboxed WASM runtime.

**Developer mental model:** Express/Koa middleware, Axum extractors, Rails before_action, NestJS guards.

### 3.2 Constitutional Bedrock (Built-in Middleware)

The constitutional gates are native Rust code compiled into the ZeroPoint binary. They enforce foundational safety properties:

- **HarmPrincipleRule** — Blocks actions that could cause direct harm
- **SovereigntyRule** — Prevents unauthorized control transfers
- **CatastrophicActionRule** — Requires approval for irreversible high-impact operations
- **BulkOperationRule** — Rate-limits mass operations
- **ReputationGateRule** — Evaluates actor trust history

These gates always run first. Custom gates cannot override a constitutional block — they can only add restrictions on top.

**Developer mental model:** HTTPS enforcement, CSRF protection, framework-level security that always runs regardless of application code.

### 3.3 Capability Grant (Scoped Credentials)

A capability grant defines what an agent is authorized to do. Grants are cryptographically signed by the issuing operator and scoped by:

- **Capability type** — Read, Write, Execute, ApiCall, ConfigChange
- **Scope** — Which resources or endpoints the capability covers
- **Trust tier** — The clearance level (Tier 0: read-only, Tier 1: standard, Tier 2: sensitive)
- **Expiration** — Time-bound validity
- **Issuer** — The operator or delegating agent who signed the grant

**Developer mental model:** IAM roles, OAuth scopes, scoped API keys.

### 3.4 Delegation Chain (Certificate Chain)

Operators issue capability grants to agents. Agents can delegate subsets of their capabilities to sub-agents. Each delegation is signed, creating a verifiable chain back to the root operator identity.

Delegation rules:

- A delegate can never exceed the delegator's capabilities
- Scope can only narrow, never widen
- Trust tier can only decrease, never increase
- The full chain is verified at evaluation time

**Developer mental model:** TLS certificate chains, code signing chains, X.509 PKI.

### 3.5 Receipt (Signed Audit Entry)

Every governance evaluation produces a receipt — a signed, timestamped record of the decision. Receipts contain:

- The action that was evaluated
- The policy context (actor, trust tier, channel, capabilities)
- Which gates fired and their individual decisions
- The final outcome (allowed, blocked, escalated)
- A cryptographic signature from the evaluating node

**Developer mental model:** Ethereum transaction receipts, Stripe webhook events, signed audit log entries.

### 3.6 Audit Chain (Append-only Log)

Receipts are chained together using BLAKE3 hashing. Each entry references the hash of the previous entry, creating a tamper-evident log. If any entry is modified after the fact, the chain breaks and verification fails.

**Developer mental model:** Git commit history, blockchain without consensus, Merkle chains.

### 3.7 Trust Tier (Permission Level)

Trust tiers provide a simple, hierarchical authorization model:

| Tier | Name | Scope |
|------|------|-------|
| Tier 0 | Observer | Read-only access, no mutations |
| Tier 1 | Operator | Standard operations within granted capabilities |
| Tier 2 | Elevated | Sensitive operations, may require human approval |

Constitutional gates reference trust tiers when evaluating actions. Custom gates can enforce tier requirements for domain-specific operations.

**Developer mental model:** Unix permission levels, AWS IAM tiers, security clearance levels.

---

## 4. WASM Gate Architecture

### 4.1 Overview

Custom governance gates are compiled to WebAssembly and loaded by ZeroPoint at startup. The WASM runtime (Wasmtime) provides:

- **Memory isolation** — Each gate has its own linear memory, no shared state
- **No system access** — No filesystem, no network, no environment variables
- **Deterministic execution** — Same input always produces same output
- **Resource limits** — Bounded execution time and memory consumption

### 4.2 Guest Interface

A gate implements a single function that receives a serialized policy context and returns a serialized decision:

```
// Conceptual interface (language-agnostic)
function evaluate(context: PolicyContext) -> Decision

PolicyContext {
    action: ActionType        // What the agent wants to do
    actor: ActorId            // Who is requesting
    trust_tier: TrustTier     // Their clearance level
    channel: Channel          // Where the request came from
    capabilities: []          // What they're authorized to do
    metadata: {}              // Domain-specific context
}

Decision {
    outcome: Allow | Block | RequireApproval
    reason: string            // Human-readable explanation
    conditions: []            // Optional conditions for approval
}
```

### 4.3 Gate Authoring (Rust)

```rust
use zeropoint_gate::prelude::*;

#[zeropoint::gate(
    name = "spending-limit",
    description = "Blocks API calls over $100 without Tier 2 clearance",
    version = "1.0.0"
)]
fn evaluate(ctx: &PolicyContext) -> Decision {
    let cost = ctx.metadata.get_f64("estimated_cost_usd").unwrap_or(0.0);

    if ctx.action == ActionType::ApiCall && cost > 100.0 && ctx.trust_tier < TrustTier::Tier2 {
        Decision::block(format!(
            "API call estimated at ${:.2} exceeds $100 limit for Tier {} agents",
            cost, ctx.trust_tier
        ))
    } else {
        Decision::allow()
    }
}
```

Compile: `cargo build --target wasm32-wasi --release`

The resulting `.wasm` file is placed in the policy directory and referenced in configuration.

### 4.4 Gate Authoring (Other Languages)

Any language that compiles to WASM can implement gates: Go, AssemblyScript, C/C++, Zig. ZeroPoint provides a thin SDK crate/package for each supported language that handles serialization of the policy context and decision types.

### 4.5 Evaluation Pipeline

```
Request arrives
    │
    ▼
┌─────────────────────────────┐
│  Constitutional Bedrock     │  Native Rust, immutable
│  (Harm, Sovereignty, etc.)  │  Can block, cannot be overridden
└─────────┬───────────────────┘
          │ if not blocked
          ▼
┌─────────────────────────────┐
│  Operator Gates (WASM)      │  Custom policy, sandboxed
│  (Spending, PII, Rate, etc.)│  Can block or escalate
└─────────┬───────────────────┘
          │ if not blocked
          ▼
┌─────────────────────────────┐
│  DefaultAllowRule           │  Fallback: allow if no gate blocked
└─────────┬───────────────────┘
          │
          ▼
    Receipt generated
    Chain extended
    Decision returned
```

---

## 5. SDK Surface

### 5.1 CLI — `zp`

The CLI handles bootstrapping, key management, and diagnostics.

```
zp init                           Bootstrap a new ZeroPoint environment
                                  (generates operator key, constitutional
                                  bedrock, writes zeropoint.toml)

zp keys issue                     Issue a new agent key
    --agent <name>                Agent identifier
    --capabilities <list>         Comma-separated capabilities
    --trust-tier <0|1|2>          Trust tier assignment
    --expires <duration>          Optional TTL

zp keys list                      List all issued keys and grants
zp keys revoke <key-id>           Revoke an agent key

zp gate add <path.wasm>           Install a custom governance gate
zp gate list                      List installed gates with status
zp gate test <path.wasm>          Test a gate against sample contexts
    --context <json>              Custom test context

zp audit log                      View recent audit chain entries
zp audit verify                   Verify chain integrity
zp audit export                   Export audit chain for compliance

zp status                         Show system health and posture
zp serve                          Start the ZeroPoint server
    --bridge-dir <path>           Serve admin console from dist dir
```

### 5.2 Client Library

The runtime integration library. Available as a Rust crate, with FFI bindings for Python, TypeScript, and Go.

```rust
use zeropoint_client::ZeroPoint;

// Initialize with server URL
let zp = ZeroPoint::connect("http://localhost:3000").await?;

// Evaluate an action before executing it
let decision = zp.evaluate(EvaluateRequest {
    action: ActionType::ApiCall,
    actor: agent_id,
    metadata: json!({
        "endpoint": "https://api.openai.com/v1/chat",
        "estimated_cost_usd": 0.05,
    }),
}).await?;

match decision.outcome {
    Outcome::Allow => {
        // Proceed with the action
        // Receipt is automatically recorded
    }
    Outcome::Block { reason } => {
        // Action denied — reason explains why
        log::warn!("Blocked: {}", reason);
    }
    Outcome::RequireApproval { request_id } => {
        // Human approval needed
        // Poll or subscribe for decision
        let approved = zp.await_approval(request_id).await?;
    }
}
```

### 5.3 MCP Tools

For agent frameworks that support the Model Context Protocol, ZeroPoint exposes its primitives as MCP tools:

- `zeropoint_evaluate` — Evaluate an action against the governance gate stack
- `zeropoint_grant` — Request a capability grant
- `zeropoint_audit` — Query the audit chain
- `zeropoint_status` — Check system health and security posture

This allows LLM-based agents to call ZeroPoint directly as part of their tool-use loop, without the developer writing explicit integration code.

---

## 6. Walkthrough: The Governance Gate Loop

This section walks through the core ZeroPoint loop by hand, so you can feel the mechanics before writing any integration code. Then we show the same flow automated.

### 6.1 By Hand: Securing an Agent's First Action

Imagine you have a research agent that needs to call an external API. Before ZeroPoint, it just calls the API. After ZeroPoint, every call passes through the governance gate. Here's what that looks like step by step.

**Step 1: Bootstrap your environment.**

```
$ zp init

  ZeroPoint Genesis
  ─────────────────
  Generating operator keypair...        ✓ Ed25519
  Sealing constitutional bedrock...     ✓ 5 gates installed
  Writing genesis record...             ✓ ~/.zeropoint/genesis.json

  Operator identity: a7c3e9f0...
  Constitutional hash: 8b2d41...

  Your environment is ready.
  Run `zp keys issue` to create your first agent key.
```

That's it. You now have a cryptographic identity, five constitutional governance gates compiled into the runtime, and a genesis record that anchors your trust chain. The whole thing took seconds and created two things: a `~/.zeropoint/` directory (your keyring and genesis record) and a `zeropoint.toml` in your project.

**Where does ZeroPoint live?**

By default, keys and governance state live at `~/.zeropoint/` in your home directory — one identity per machine, shared across projects. But ZeroPoint resolves its home through a three-step chain, and the first match wins:

1. **`ZP_HOME` env var** — explicit override. Set this in CI, Docker, or production where you don't want to touch the user's home directory. `ZP_HOME=/opt/zeropoint zp keys list` just works.

2. **`zeropoint.toml` key_path** — project-level config. ZeroPoint walks up from your working directory looking for a `zeropoint.toml`. If it finds one with a `key_path` under `[identity]`, it uses that. This lets you isolate keys per project if you need to.

3. **`~/.zeropoint/`** — the sensible default for local development.

This means the same CLI works unchanged across every environment:

```
# Local dev — uses ~/.zeropoint/ automatically
zp gate eval "tool:filesystem:read"

# CI pipeline — keys come from a mounted secret
ZP_HOME=/run/secrets/zeropoint zp gate eval "tool:filesystem:read"

# Multi-project — each project can point to its own keyring
# (set key_path in that project's zeropoint.toml)
```

You don't have to think about this until you need it. The default is right for 90% of cases.

**Step 2: Issue a key for your agent.**

```
$ zp keys issue --agent "research-bot" --capabilities read,api --trust-tier 1

  Agent key issued
  ────────────────
  Agent:         research-bot
  Key ID:        k-3f8a...
  Capabilities:  read, api
  Trust tier:    1 (Operator)
  Delegated by:  a7c3e9f0... (you)
  Expires:       never

  Export: ZP_AGENT_KEY=k-3f8a...
```

Your agent now has a scoped credential. It can read data and call APIs, but it can't write files, execute code, or change configuration. The delegation chain links this key back to your operator identity from genesis.

**Step 3: Evaluate an action manually.**

Before your agent calls that external API, let's see what the governance gate thinks. You can test this without writing any code:

```
$ zp gate eval \
    --action api_call \
    --actor research-bot \
    --metadata '{"endpoint": "https://api.example.com/search", "estimated_cost_usd": 0.02}'

  Gate Evaluation
  ───────────────
  Action:     ApiCall
  Actor:      research-bot (Tier 1)
  Channel:    Cli

  Constitutional gates:
    ✓ HarmPrincipleRule         → allow
    ✓ SovereigntyRule           → allow
    ✓ CatastrophicActionRule    → allow
    ✓ BulkOperationRule         → allow
    ✓ ReputationGateRule        → allow

  Custom gates:
    (none installed)

  Fallback:
    ✓ DefaultAllowRule          → allow

  ═══════════════════════════════
  Decision: ALLOW
  Receipt:  rcpt-7f2b...
  Chain:    ...4a1d → ...8e3f (2 entries)
```

Every gate in the stack evaluated the action and returned its decision. The constitutional bedrock ran first — all five gates allowed the action. No custom gates are installed yet, so the fallback allowed it. A receipt was generated and appended to the audit chain.

**Step 4: Now try something the gates should catch.**

```
$ zp gate eval \
    --action execute \
    --actor research-bot \
    --metadata '{"command": "rm -rf /data", "scope": "filesystem"}'

  Gate Evaluation
  ───────────────
  Action:     Execute
  Actor:      research-bot (Tier 1)

  Constitutional gates:
    ✗ CatastrophicActionRule    → BLOCK
      "Destructive filesystem operation requires Tier 2
       clearance and human approval"

  ═══════════════════════════════
  Decision: BLOCK
  Reason:   Destructive filesystem operation requires
            Tier 2 clearance and human approval
  Receipt:  rcpt-9d4c...
  Chain:    ...8e3f → ...b12a (3 entries)
```

The constitutional bedrock caught it. The agent has `read` and `api` capabilities — not `execute`. And even if it did, a destructive filesystem operation would require Tier 2 clearance. The block was receipted and chained. Nobody had to configure this — it's the bedrock.

**Step 5: Add a custom gate.**

Now let's say you want to enforce a spending limit. Write a gate (or use a prebuilt one):

```
$ zp gate add policies/spending-limit.wasm

  Gate installed
  ──────────────
  Name:     spending-limit
  Version:  1.0.0
  Position: after constitutional, before fallback
  Status:   active
```

Test it:

```
$ zp gate eval \
    --action api_call \
    --actor research-bot \
    --metadata '{"endpoint": "https://api.openai.com/v1/chat", "estimated_cost_usd": 250.00}'

  Gate Evaluation
  ───────────────
  Action:     ApiCall
  Actor:      research-bot (Tier 1)

  Constitutional gates:
    ✓ HarmPrincipleRule         → allow
    ✓ SovereigntyRule           → allow
    ✓ CatastrophicActionRule    → allow
    ✓ BulkOperationRule         → allow
    ✓ ReputationGateRule        → allow

  Custom gates:
    ✗ spending-limit            → BLOCK
      "API call estimated at $250.00 exceeds $100
       limit for Tier 1 agents"

  ═══════════════════════════════
  Decision: BLOCK
  Reason:   API call estimated at $250.00 exceeds
            $100 limit for Tier 1 agents
  Receipt:  rcpt-e51a...
  Chain:    ...b12a → ...c7f3 (4 entries)
```

Your custom gate blocked a $250 API call. The constitutional gates allowed it (no safety issue), but your business rule caught it. The WASM sandbox ran your gate in isolation — it couldn't see the filesystem, the network, or any other gate's state. It just received the context and returned a decision.

**Step 6: Verify the audit trail.**

```
$ zp audit log --last 4

  Audit Chain (4 entries, chain valid ✓)
  ──────────────────────────────────────
  #4  rcpt-e51a  BLOCK   research-bot  ApiCall   spending-limit
  #3  rcpt-9d4c  BLOCK   research-bot  Execute   CatastrophicActionRule
  #2  rcpt-7f2b  ALLOW   research-bot  ApiCall   (all gates passed)
  #1  genesis    SEALED  operator      Genesis   constitutional bedrock

$ zp audit verify

  Chain integrity: ✓ valid
  4 entries, 0 gaps, 0 tampered
  Genesis → ...c7f3 (unbroken)
```

Every decision is recorded, signed, and chained. If anyone modifies an entry, the chain breaks and `zp audit verify` catches it.

### 6.2 Now Automate It

That was the loop by hand. In production, your agent does the same thing programmatically with a single function call:

```python
from zeropoint import ZeroPoint

zp = ZeroPoint.connect("http://localhost:3000", key="k-3f8a...")

# Before every consequential action:
decision = zp.evaluate(
    action="api_call",
    metadata={
        "endpoint": "https://api.openai.com/v1/chat",
        "estimated_cost_usd": 0.05,
    }
)

if decision.allowed:
    # Proceed — receipt already recorded
    response = call_openai(prompt)
elif decision.blocked:
    # Stop — log the reason, try something else
    logger.warn(f"Blocked: {decision.reason}")
elif decision.requires_approval:
    # Pause — wait for human
    approval = zp.await_approval(decision.request_id, timeout=300)
    if approval.granted:
        response = call_openai(prompt)
```

That's the entire integration. One call before each action. The gate stack runs, the receipt is generated, the chain extends. Your agent doesn't know or care about the constitutional bedrock, the WASM sandbox, or the audit chain — it just asks "can I do this?" and gets back yes, no, or ask a human.

### 6.3 Scaling It

When you go from one agent to ten, or a hundred:

```
$ zp keys issue --agent "analyst-1" --capabilities read,api --trust-tier 1
$ zp keys issue --agent "analyst-2" --capabilities read,api --trust-tier 1
$ zp keys issue --agent "writer-bot" --capabilities read,write --trust-tier 1
$ zp keys issue --agent "admin-bot" --capabilities read,write,execute,config --trust-tier 2
```

Each agent gets its own key with scoped capabilities. The same governance gate stack evaluates all of them. The audit chain captures every decision from every agent in a single, verifiable log.

Your admin-bot has Tier 2 clearance and broader capabilities — it can pass through gates that block the others. But even it can't override the constitutional bedrock. The hierarchy is enforced cryptographically, not by convention.

Add more gates as your needs evolve. Remove gates you don't need. The constitutional bedrock stays. The audit chain keeps growing. Trust is infrastructure.

---

## 7. Security Model

### 6.1 Threat Model

ZeroPoint assumes:

- **Agents are untrusted.** Any agent can be compromised, hallucinate, or act outside its intended scope. Governance gates evaluate every action, regardless of the agent's stated intent.
- **Policy code is untrusted.** Custom WASM gates run in sandboxes with no system access. A malicious gate can return incorrect decisions but cannot exfiltrate data, modify the audit chain, or affect other gates.
- **The network is untrusted.** All API communication can be authenticated via Ed25519 signatures. Receipts are self-verifying — a receipt's validity can be checked without trusting the server that issued it.
- **The operator is trusted but bounded.** Operators have full authority within their domain but cannot weaken the constitutional bedrock. The genesis ceremony establishes the root of trust.

### 6.2 Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Identity keys | Ed25519 | Operator and agent identity, receipt signing |
| Audit chain | BLAKE3 | Tamper-evident hash chaining |
| Biometric binding | BLAKE3 | Facial embedding to cryptographic fingerprint |
| Receipt signatures | Ed25519 | Non-repudiation of governance decisions |
| Capability delegation | Ed25519 chain | Verifiable authority chain |

### 6.3 Genesis Ceremony

The genesis ceremony is the initial trust establishment event. It:

1. Generates the operator's Ed25519 keypair
2. Optionally binds biometric identity (facial embedding via BLAKE3)
3. Optionally binds hardware wallet signature (Trezor/Ledger)
4. Seals the constitutional rules with the operator's signature
5. Writes the genesis record — immutable, never modified

All subsequent keys, grants, and delegations chain back to this genesis event.

### 6.4 Compute Surface Canonicalization

Before agents operate in an environment, ZeroPoint canonicalizes the compute surface — taking a cryptographic snapshot of all files, configurations, and dependencies. This establishes a baseline that can detect unauthorized modifications.

Surface canonicalization produces a Merkle tree of the environment, with a root hash that can be verified at any point. Changes to the surface are detected by comparing the current state against the canonical snapshot.

---

## 8. Admin Console

The admin console is a lightweight diagnostic and management interface served by the ZeroPoint server. It is not part of the runtime path — it exists for operators who need to:

- **Manage keys** — Issue, inspect, and revoke operator and agent keys. View delegation chains.
- **Configure policy** — Install, order, enable/disable custom WASM gates. View constitutional bedrock status.
- **Inspect audits** — Browse the audit chain, verify integrity, search by actor/action/time range. Visualize the chain structure.
- **View topology** — See the trust relationships between operators, agents, capabilities, and delegation chains as an interactive graph.
- **Monitor posture** — Security posture dashboard showing current threat assessment, gate health, chain integrity, and active capability grants.

The console reuses visualization components from the Bridge prototype (topology maps, audit chain viewer, security posture graphs) within a simplified, non-agentic interface.

---

## 9. Integration Patterns

### 8.1 Sidecar Pattern

ZeroPoint runs as a sidecar process alongside the agent system. The agent calls ZeroPoint's HTTP API at decision points. This is the simplest integration — no library dependency, any language can call HTTP.

```
┌──────────────┐     HTTP      ┌──────────────┐
│  Agent       │ ──────────▶   │  ZeroPoint   │
│  Framework   │ ◀──────────   │  Server      │
│  (any)       │   evaluate    │  (sidecar)   │
└──────────────┘   receipts    └──────────────┘
```

### 8.2 Embedded Library

For tighter integration, the ZeroPoint client library runs in-process. Policy evaluation happens without a network round-trip. The library syncs with a ZeroPoint server for audit chain persistence and multi-agent coordination.

### 8.3 MCP Integration

Agent frameworks that support MCP (Claude, compatible LLM systems) can use ZeroPoint's MCP tools directly. The agent evaluates its own actions through ZeroPoint as part of its reasoning loop.

### 8.4 Webhook / Event-Driven

ZeroPoint can emit events (via WebSocket or webhooks) when governance requires attention: HCS approval requests, policy violations, anomaly detection. This allows integration with existing alerting and incident response systems.

---

## 10. Developer Journey

1. **Install** — `cargo install zeropoint` or download the binary.

2. **Bootstrap** — `zp init` in the project directory. Generates operator key, constitutional bedrock, `zeropoint.toml`. Thirty seconds.

3. **Configure gates** — Write custom WASM gates for domain-specific rules. Drop `.wasm` files in the policy directory, reference in config. Or use built-in constitutional gates only for immediate security coverage.

4. **Issue agent keys** — `zp keys issue --agent "research-bot" --capabilities read,api --trust-tier 1`. Each agent gets a cryptographic identity with scoped capabilities.

5. **Integrate** — Add `zp.evaluate()` calls at decision points in agent code. One function call per action. ZeroPoint handles policy evaluation, receipt generation, and audit chain extension.

6. **Run** — `zp serve` starts the server. Agents call the API. Constitutional and custom gates evaluate every action. Audit chain grows automatically.

7. **Inspect** — When needed, open the admin console to view audit history, manage keys, adjust policy, or investigate incidents.

---

## 11. What We're Building vs. What We're Not

**We are building:**

- Cryptographic identity for operators and agents
- A constitutional governance gate that cannot be weakened
- WASM-sandboxed custom policy gates that compose safely
- Capability-based authorization with delegation chains
- Tamper-evident audit chains with signed receipts
- A CLI for bootstrapping and administration
- Client libraries for runtime integration
- An admin console for diagnostics and key management
- MCP tools for native LLM agent integration

**We are not building:**

- An agent orchestration framework
- A chat interface or conversational UI
- A prompt engineering system
- An LLM provider or model router
- A deployment platform
- A monitoring/observability stack (we produce audit data; others visualize it)

---

## Appendix A: Configuration

```toml
# zeropoint.toml

[server]
bind = "127.0.0.1"
port = 3000

[identity]
# Generated by `zp init`
key_path = ".zeropoint/identity.key"

[policy]
# Custom gates, evaluated in order after constitutional bedrock
gates = [
    "policies/spending-limit.wasm",
    "policies/pii-detection.wasm",
    "policies/rate-limiter.wasm",
]

[audit]
data_dir = ".zeropoint/data"
# Optional: forward audit entries to external systems
# export_webhook = "https://your-siem.example.com/ingest"

[llm]
enabled = false  # Enable for pipeline-backed responses
# provider = "anthropic"
# model = "claude-sonnet-4-5-20250929"
```

## Appendix B: Governance Gate Evaluation Contract

```
Input:  PolicyContext (serialized as MessagePack)
Output: Decision (serialized as MessagePack)

PolicyContext:
  action:          ActionType enum
  actor_id:        string (hex-encoded Ed25519 public key)
  trust_tier:      u8 (0, 1, or 2)
  channel:         Channel enum (Cli, Api, WebDashboard, Slack, Discord)
  conversation_id: UUID v7
  capabilities:    [GrantedCapability]
  metadata:        Map<string, Value>

Decision:
  outcome:    Allow | Block | RequireApproval
  reason:     string
  conditions: [string]  (optional, for RequireApproval)

ActionType enum:
  Chat, Read, Write, Execute, ApiCall, ConfigChange,
  ToolInvocation, MeshForward, Custom(string)

The gate function must return within 100ms.
Memory limit: 16MB per gate instance.
No WASI capabilities granted (no fs, no net, no env).
```
