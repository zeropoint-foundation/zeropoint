# zp-policy

Graduated policy decision engine for ZeroPoint v2.

This crate evaluates whether agent actions should be allowed, warned about, sanitized, reviewed, or blocked. It combines native Rust rules — including two constitutional rules that cannot be removed — with a WASM runtime for peer-exchanged policy modules. Multiple rules are evaluated for every action; the most restrictive decision wins.

## Decision Severity Hierarchy

```
Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1)
```

Every policy evaluation collects decisions from all applicable rules and returns the most restrictive one. A single `Block` from any rule — native or WASM — overrides all other `Allow` decisions.

## Modules

### engine.rs — PolicyEngine

The evaluation pipeline. `PolicyEngine::evaluate()` runs all native rules in order, then all active WASM modules, and returns the most restrictive decision.

Additional methods: `capabilities_for()` determines available capabilities by trust tier (Tier 0 gets read + basic tools; Tier 1 adds write + execute; Tier 2 adds system commands). `model_for()` recommends an LLM class based on risk level (Low → Any, Medium/High → Strong, Critical → RequireStrong and non-overridable).

### rules.rs — Policy Rules

The `PolicyRule` trait is the core abstraction: `evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision>`. Return `Some(decision)` if the rule applies, `None` if it doesn't care.

**Constitutional rules** (always loaded first, cannot be removed):

`HarmPrincipleRule` enforces Tenet I: Do No Harm. Blocks actions targeting weaponization, surveillance, deception (deepfakes, impersonation), and suppression of dissent. The block message always cites "Tenet I — Do No Harm."

`SovereigntyRule` enforces Tenet II: Sovereignty Is Sacred. Blocks config changes that would disable the guard, disable or truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override agent refusal. The block message always cites "Tenet II — Sovereignty Is Sacred."

**Operational rules:**

`CatastrophicActionRule` blocks credential exfiltration and self-modification (changes to operator instructions, policy rules, trust tier, base capabilities, or model override settings).

`BulkOperationRule` warns on large-scale file operations with glob patterns or recursive deletes.

`ReputationGateRule` enforces reputation-based access control for mesh actions. High-risk actions (delegation) require Good reputation. Medium-risk (policy sharing) requires Fair. Low-risk (receipt forwarding) allows Unknown peers. Unknown peers attempting high-risk actions trigger Review; below-threshold peers are Blocked.

`DefaultAllowRule` is the permissive baseline evaluated last — returns Allow for everything not caught by other rules.

### gate.rs — GovernanceGate

Integrates Guard, Policy, and Audit into a single evaluation pipeline. `GovernanceGate::evaluate()` runs the policy engine, creates a hash-chained `AuditEntry` linking to the previous entry via Blake3, and returns a `GateResult` containing the decision, risk level, trust tier, audit entry, and the names of all rules that were evaluated.

### wasm_runtime.rs — WASM Policy Modules

Loads and executes policy rules as WebAssembly modules using wasmtime. Modules export a standard ABI: `name_ptr/name_len` for identification, `alloc` for guest memory allocation, and `evaluate/evaluate_len` for policy evaluation. The host serializes `PolicyContext` as JSON, writes it into guest memory, calls `evaluate`, and reads back a JSON `PolicyDecision`. Fuel-limited execution (1,000,000 instructions per evaluation) prevents runaway modules.

### policy_registry.rs — Module Lifecycle

`PolicyModuleRegistry` manages WASM module lifecycle: `load()` compiles and registers, `unload()` removes, `enable()`/`disable()` toggle evaluation, `evaluate_all()` runs all active modules. For mesh exchange: `advertise()` publishes metadata, `get_module_bytes()` provides raw WASM for transfer, `load_from_peer()` loads received modules with Blake3 hash verification, and `verify_integrity()` checks all modules match their stored hashes.

## Rule Evaluation Order

```
1. HarmPrincipleRule      ← Constitutional (always first)
2. SovereigntyRule        ← Constitutional
3. CatastrophicActionRule ← Operational
4. BulkOperationRule      ← Operational
5. ReputationGateRule     ← Mesh-aware
6. DefaultAllowRule       ← Permissive baseline (always last)
7. WASM modules           ← Peer-exchanged (in priority order)
```

Constitutional rules evaluate first and win over everything. WASM modules can override DefaultAllowRule but cannot override constitutional rules.
