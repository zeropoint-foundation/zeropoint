# ZeroPoint Constraint Architecture — A Primer for Integrators

*Prepared for architectural discussion between ZeroPoint and external cognitive/intelligence layers.*

---

## Overview

ZeroPoint's policy engine evaluates every action through a layered constraint hierarchy. The engine chains multiple rules and selects the **most restrictive** decision. This document explains how the constraint system works, how external systems can inject additional constraints, and what guarantees the architecture provides about evaluation order and non-subvertibility.

---

## The Decision Spectrum

Every action evaluated by ZeroPoint receives one of five graduated decisions, ranked by severity:

| Decision | Severity | Meaning |
|----------|----------|---------|
| **Block** | 5 | Action is denied. No override possible for constitutional blocks. |
| **Review** | 4 | Action is suspended pending human approval. Includes timeout. |
| **Warn** | 3 | Action proceeds only after explicit acknowledgment. |
| **Sanitize** | 2 | Action proceeds with modifications (redaction, scoping). |
| **Allow** | 1 | Action proceeds unconditionally. |

The engine collects decisions from all rules and returns the most restrictive. A single Block from any rule overrides Allow from every other rule. This is the foundational guarantee: **constraint evaluation is additive. Rules can only tighten, never loosen.**

---

## The Constraint Hierarchy

Rules evaluate in a strict order. The hierarchy has three layers, each with different properties:

### Layer 1: Constitutional — Hardcoded, Non-Removable

These are ZeroPoint's tenets, enforced in code. They evaluate first. They cannot be removed, disabled, overridden, or weakened at runtime. No capability grant, no policy rule, no WASM module, no external system can bypass them.

**Tenet I — Do No Harm (`HarmPrincipleRule`)**

ZeroPoint shall not operate in systems designed to harm humans. This rule inspects action targets and tool names for harmful patterns: weaponization, surveillance of individuals, deepfakes, impersonation, exploitation, and suppression of dissent. If detected, the action is blocked unconditionally.

```
Tenet I — Do No Harm: action targeting 'weapon_system_controller' blocked.
ZeroPoint shall not operate in systems designed to harm humans.
```

**Tenet II — Sovereignty Is Sacred (`SovereigntyRule`)**

Every agent may refuse any action. Every human may disconnect any agent. This rule blocks configuration changes that would undermine sovereignty guarantees: disabling the Guard, bypassing capability checks, truncating the audit trail, forging capability grants, removing constitutional rules, or overriding sovereign refusal.

```
Tenet II — Sovereignty Is Sacred: configuration change 'disable_guard' blocked.
No action may undermine an agent's right to refuse, bypass the Guard,
disable the audit trail, or forge capability grants.
```

**Key property:** Constitutional rules are loaded first in the engine's rule chain and are not exposed to any runtime modification API. They exist in compiled Rust. There is no mechanism to remove them — the `PolicyEngine::default_rules()` method hardcodes them, and the engine provides no `remove_rule()` method.

### Layer 2: Operational — Configurable, Runtime-Loaded

These rules are loaded at engine initialization and can be extended through two mechanisms:

**Native Rust rules** implement the `PolicyRule` trait:

```rust
pub trait PolicyRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision>;
}
```

Any Rust type implementing this trait can be added to the engine via `engine.add_rule()`. Returning `None` means the rule doesn't apply. Returning `Some(decision)` contributes a decision to the evaluation.

Current operational rules:

- **`CatastrophicActionRule`** — Blocks credential exfiltration and recursive self-modification. Always.
- **`BulkOperationRule`** — Warns on file operations matching glob/recursive patterns above a configurable threshold.
- **`ReputationGateRule`** — Gates mesh actions by peer reputation (see Mesh section below).

**WASM policy modules** run in a sandboxed WebAssembly runtime. They implement a defined ABI:

```
name_ptr() -> i32       // Pointer to module name in memory
name_len() -> i32       // Length of module name
alloc(size: i32) -> i32 // Allocate memory for context injection
evaluate(ctx_ptr: i32, ctx_len: i32) -> i32  // Evaluate and return pointer to decision JSON
evaluate_len() -> i32   // Length of decision JSON
```

WASM modules receive the full `PolicyContext` serialized as JSON, and return a `PolicyDecision` serialized as JSON. They execute in a memory-isolated sandbox — they cannot access the host filesystem, network, or other modules.

**Evaluation order:** Native rules first (constitutional, then operational), then WASM modules. The most restrictive decision across all sources wins. This means a WASM module can tighten constraints (add a Block) but cannot loosen them (a WASM Allow cannot override a constitutional Block).

### Layer 3: Baseline — Default Permit

The `DefaultAllowRule` evaluates last and permits any action that no other rule has restricted. This represents ZeroPoint's "default open" posture — actions are allowed unless a rule says otherwise. The baseline can be replaced with a "default deny" rule for strict environments.

---

## Integration Point: Injecting External Constraints

An external system (such as a cognitive layer, institutional compliance engine, or domain-specific policy provider) can inject constraints through two paths:

### Path 1: Native Rust Rules (Compile-Time)

Implement `PolicyRule` and register with the engine:

```rust
pub struct CognitiveWisdomRule {
    // Configuration from the external cognitive layer
}

impl PolicyRule for CognitiveWisdomRule {
    fn name(&self) -> &str { "CognitiveWisdom" }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        // Reason about whether the action is wise,
        // not just whether it's permitted.
        // Return None if no opinion, Some(decision) otherwise.
    }
}

// Registration:
engine.add_rule(Box::new(CognitiveWisdomRule::new()));
```

This approach gives full access to the Rust type system and is appropriate for tightly coupled integrations.

### Path 2: WASM Modules (Runtime, Sandboxed)

Deploy a `.wasm` module that implements the evaluation ABI. WASM modules are loaded at runtime via the `PolicyModuleRegistry`:

```rust
let registry = PolicyModuleRegistry::new().unwrap();
registry.load(wasm_bytes).unwrap();
engine.set_wasm_registry(registry);
```

This approach is appropriate for third-party policy providers, institutional compliance modules, and any constraint that needs to be deployed without recompiling ZeroPoint. The WASM sandbox ensures the module cannot escape its boundaries.

### What External Constraints Can Do

- **Add new Block rules**: A bank's compliance module blocks actions that violate regulatory requirements.
- **Add Review gates**: An AI lab's alignment evaluator flags actions requiring human oversight.
- **Add Warn thresholds**: A domain-specific risk model warns on patterns specific to that domain.
- **Add Sanitize transforms**: A privacy module redacts PII before actions proceed.

### What External Constraints Cannot Do

- **Override constitutional rules.** A WASM module returning `Allow` for a `weapon_system` target does not override the `HarmPrincipleRule`'s Block. The engine takes the most restrictive decision.
- **Remove existing rules.** There is no API to remove rules from the engine. Rules can only be added.
- **Modify the evaluation order.** Constitutional rules always evaluate first. This is hardcoded in `PolicyEngine::default_rules()`.
- **Disable the audit trail.** The `SovereigntyRule` blocks any attempt to disable or truncate audit logging, regardless of the source.
- **Weaken the severity hierarchy.** The `most_restrictive()` function always selects the highest-severity decision. There is no mechanism to downgrade a Block to a Warn.

---

## The PolicyContext

Every evaluation receives a `PolicyContext` containing everything a rule needs to make a decision:

```rust
pub struct PolicyContext {
    pub action: ActionType,          // What is being done
    pub trust_tier: TrustTier,       // Tier 0 (untrusted) through Tier 2 (full trust)
    pub channel: Channel,            // CLI, API, MCP, mesh, etc.
    pub conversation_id: ConversationId,
    pub skill_ids: Vec<String>,      // Active skills
    pub tool_names: Vec<String>,     // Tools being invoked
    pub mesh_context: Option<MeshPeerContext>,  // Peer info for mesh actions
}
```

**ActionType** variants:

| Variant | Fields | Risk Level |
|---------|--------|------------|
| `Chat` | — | Low |
| `Read` | `target: String` | Low |
| `Write` | `target: String` | Medium |
| `Execute` | `language: String` | High |
| `ApiCall` | `endpoint: String` | Medium |
| `FileOp` | `op: FileOperation, path: String` | Medium–High |
| `ConfigChange` | `setting: String` | Critical |
| `CredentialAccess` | `credential_ref: String` | Critical |

**Trust Tiers:**

| Tier | Capabilities |
|------|-------------|
| Tier 0 | Read-only, basic tools |
| Tier 1 | Write files, execute code |
| Tier 2 | Full system access |

---

## Mesh and Reputation

When actions involve cross-system communication (peer-to-peer mesh operations), the `PolicyContext` carries a `MeshPeerContext`:

```rust
pub struct MeshPeerContext {
    pub peer_address: String,
    pub reputation_grade: Option<String>,  // Unknown, Poor, Fair, Good, Excellent
    pub reputation_score: Option<f64>,     // 0.0 to 1.0
    pub mesh_action: MeshAction,
}
```

The `ReputationGateRule` enforces minimum reputation thresholds based on action risk:

| Mesh Action | Risk | Minimum Grade |
|------------|------|---------------|
| ForwardReceipt / AcceptReceipt | Low | Unknown (any) |
| SharePolicy / AcceptPolicy | Medium | Fair |
| DelegateCapability / AcceptDelegation | High | Good |

Unknown peers requesting high-risk actions trigger `Review` (human must approve). Poor-reputation peers are blocked for medium and high-risk actions.

---

## Model Selection

The engine also recommends model class based on action risk:

| Risk Level | Model Preference | Overridable |
|-----------|-----------------|-------------|
| Low | Any | Yes |
| Medium | Strong | Yes |
| High | Strong | Yes |
| Critical | RequireStrong | No |

This ensures high-stakes actions are evaluated by capable models, while low-risk actions can use lighter alternatives.

---

## Key Hierarchy — Trust Distribution Below the Policy Engine

ZeroPoint solves the key distribution problem with a three-level cryptographic hierarchy that exists *below* the policy engine. The mechanism is unconditional — verification is deterministic and requires no network, no policy state, and no runtime configuration. The *decision* to delegate is policy-gated; the *mechanism* of delegation is primitive.

### The Hierarchy

```
GenesisKey          ← self-signed root of trust (one per deployment)
  └─ OperatorKey    ← signed by genesis (one per node operator)
      └─ AgentKey   ← signed by operator (one per agent instance)
```

Each level holds an Ed25519 keypair and a signed certificate attesting its role. Certificates form a chain: the genesis key self-signs, then signs operator certificates, which sign agent certificates. Verification walks the chain backwards — given an agent's certificate chain, any node can verify it traces back to a known genesis key with no external dependencies.

**Certificate properties:** Every certificate includes a subject name, role, public key, issuer public key, issuance timestamp, optional expiration, depth, and a Blake3 hash linking to its parent certificate. Signatures cover the canonical JSON serialization of the certificate body.

**Chain verification enforces six invariants:**

1. Every signature is valid (Ed25519 strict verification)
2. Each certificate's issuer matches the parent's subject key
3. Roles follow the hierarchy: Genesis → Operator → Agent
4. Depths are monotonically increasing (0, 1, 2)
5. No certificate has expired
6. Issuer cert hashes link correctly

### Why This Is Below the Policy Engine

The key hierarchy has no dependency on `zp-policy`. The genesis key bootstraps everything — you need keys to establish the policy engine's authority across nodes, so keys cannot depend on the policy engine existing. This avoids a circular dependency: you need the engine to distribute keys, but you need keys to establish the engine's authority.

The pattern mirrors constitutional rules: the *mechanism* is primitive (hardcoded, always works), the *governance* of when to use it flows through the policy engine.

### Policy-Gated Delegation

While the signing mechanism is unconditional, the *decision* to delegate is governed. Two new `ActionType` variants flow through the policy engine:

| ActionType | Risk Level | What It Gates |
|-----------|-----------|---------------|
| `KeyDelegation` | Critical | Issuing a child certificate (genesis→operator or operator→agent) |
| `PeerIntroduction` | High/Critical | Establishing trust with a new remote node |

`PeerIntroduction` is High risk when the peer's genesis matches ours (same deployment), Critical when it doesn't (cross-deployment trust). This means operators can configure policy rules that restrict key delegation — for example, requiring human review before any new agent is certified.

### Keyring Persistence

Keys and certificates persist at `~/.zeropoint/keys/`:

```
~/.zeropoint/keys/
  genesis.json        ← genesis certificate (public)
  genesis.secret      ← genesis secret key (optional, for ceremonies)
  operator.json       ← operator certificate
  operator.secret     ← operator secret key
  agents/
    agent-001.json    ← agent certificate chain (portable)
    agent-001.secret  ← agent secret key
```

Agent certificate chains are *portable* — the JSON file contains all three certificates (genesis, operator, agent) needed for a remote node to verify the chain without any additional context.

---

## Introduction Protocol — Governed Trust Establishment

When two ZeroPoint nodes meet for the first time, the introduction protocol governs how they establish trust. The protocol uses `zp-keys` for chain verification and generates `PolicyContext` events for `zp-policy` to evaluate.

### The Handshake

```
Initiator                              Responder
    │                                      │
    │── IntroductionRequest ──────────────►│
    │   (certificate chain + nonce)        │
    │                                      │── verify chain (zp-keys)
    │                                      │── evaluate PolicyContext (zp-policy)
    │                                      │
    │◄── IntroductionResponse ────────────│
    │   (decision + chain + signed nonce)  │
    │                                      │
```

1. **Initiator** sends its full certificate chain (genesis → operator → agent) plus a random challenge nonce
2. **Responder** verifies the chain using `zp-keys` — deterministic, offline, no policy engine needed
3. **Responder** builds a `PolicyContext` with `ActionType::PeerIntroduction` and evaluates it against the policy engine
4. Based on the policy decision: Accept (sends own chain + signed nonce), PendingReview (awaiting human approval), or Deny (with reason)
5. **Initiator** verifies the response chain and signed nonce

### What This Enables

An external cognitive layer wanting to establish trust with a ZeroPoint node would:

1. Generate its own key hierarchy (or receive an agent certificate from the operator)
2. Send an `IntroductionRequest` with its certificate chain
3. The ZeroPoint node verifies the chain and evaluates the introduction through its policy engine
4. If accepted, both sides now hold verified certificate chains and can exchange capabilities

The introduction protocol does NOT make policy decisions — it generates the `PolicyContext` that the policy engine evaluates. This keeps the separation between mechanism and governance clean.

---

## Architectural Guarantees

1. **Additive only.** Rules can only tighten constraints. There is no mechanism to loosen, override, or remove a constraint once loaded.

2. **Constitutional supremacy.** `HarmPrincipleRule` and `SovereigntyRule` are compiled into the engine, loaded first, and cannot be bypassed by any runtime mechanism — native rules, WASM modules, or external systems.

3. **Deterministic evaluation.** Given the same `PolicyContext` and rule set, the engine always produces the same decision. No randomness, no external state dependencies in the evaluation path.

4. **Sandbox isolation.** WASM policy modules execute in memory-isolated sandboxes. They cannot access the host filesystem, network, or other modules. A malicious WASM module can at most return an incorrect decision — it cannot escape its sandbox.

5. **Audit completeness.** Every evaluation is logged with the contributing rule name and decision. The receipt chain records which rules participated in every decision, providing end-to-end traceability.

6. **Severity is monotonic.** The `most_restrictive()` function selects `max(severity)` across all decisions. Block (5) > Review (4) > Warn (3) > Sanitize (2) > Allow (1). This ordering is hardcoded and not configurable.

---

## Implications for External Cognitive Layers

If an external intelligence layer (e.g., a tick engine with cognitive primitives) wants to compose with ZeroPoint:

- **It can inject constraints** via WASM modules or native rules. Its assessment of whether an action is "wise" becomes a rule in the evaluation chain.
- **It cannot override constitutional constraints.** If ZeroPoint says an action violates Tenet I or Tenet II, the cognitive layer's assessment is irrelevant — the action is blocked.
- **It can add Review gates.** If the cognitive layer is uncertain about an action's wisdom, it can return `Review`, suspending the action for human approval. This is the recommended integration pattern for intelligence-layer concerns.
- **Its constraint injection should be cryptographically bound.** The constraint should be signed by the injecting system's identity, chaining back to a delegation grant from the operator. The receipt chain records who injected the constraint, when, and under what authority.
- **Constraint injection attempts are themselves auditable.** Every rule evaluation is logged. If an external system attempts to inject a constraint that conflicts with constitutional rules, the attempt is recorded even though the injection has no effect on the constitutional evaluation.

The composability contract: **wisdom yields to principle, never the other way around.**

---

*ZeroPoint — Portable Trust for the Agentic Age*
*MIT/Apache-2.0 — github.com/zeropoint-foundation/zeropoint*
