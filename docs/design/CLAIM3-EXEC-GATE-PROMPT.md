# CLIC Prompt: Wire GovernanceGate into exec_ws.rs (Close Claim 3)

## Context

Claim 3 of the ZeroPoint architecture states: "System-wide coherence from local evaluation — every side effect passes through the GovernanceGate (P3)." The falsifier is: "any side effect that did not pass through P3."

Currently, `crates/zp-server/src/exec_ws.rs` performs input validation (safe_path, shell metacharacter rejection, program allowlist via `validate_command()`) and emits audit receipts — but it **never calls `state.0.gate.evaluate()`**. This means `/ws/exec` bypasses the formal governance gate, making Claim 3 false.

The proxy handler (`crates/zp-server/src/proxy.rs`, lines 332–368) already demonstrates the correct pattern. Your job is to replicate that pattern in exec_ws.rs.

## Task

Wire `GovernanceGate::evaluate()` into `exec_ws.rs` so that every command execution passes through the governance gate before spawning. This closes Claim 3 for the last remaining ungated code path.

## Exact Changes

### 1. In `execute_and_stream()` (exec_ws.rs), after the `validate_command()` block (line 207) and before the `tracing::info!` on line 209:

Add a governance gate evaluation following the same pattern as proxy.rs lines 332–368:

```rust
// ── Governance gate (P3 — Claim 3 invariant) ─────────────────────
// Every side effect must pass through the GovernanceGate. The input
// validation above (safe_path, metachar, allowlist) is defense-in-depth;
// the gate is the formal policy decision point.
let gate_context = zp_core::PolicyContext {
    action: zp_core::ActionType::Execute {
        command: cmd.to_string(),
    },
    trust_tier: zp_core::TrustTier::Tier1,
    channel: zp_core::Channel::Api,
    conversation_id: zp_core::ConversationId::new(),
    skill_ids: vec![],
    tool_names: vec![format!("exec/{}", validated_cmd.program())],
    mesh_context: None,
};
let actor = zp_core::ActorId::System("exec_ws".to_string());

let gate_result = app_state.0.gate.evaluate(&gate_context, actor);

if gate_result.is_blocked() {
    let reason = match &gate_result.decision {
        zp_core::PolicyDecision::Block { reason, .. } => reason.clone(),
        _ => "Policy denied".to_string(),
    };
    tracing::warn!("exec_ws: BLOCKED by governance gate — {}", reason);
    let _ = tx.send(WsMessage::Text(
        serde_json::json!({
            "type": "error",
            "message": format!("🛡 Governance gate blocked execution: {}", reason)
        }).to_string()
    )).await;
    tool_chain::emit_tool_receipt(
        &app_state.0.audit_store,
        "tool:cmd:gate_blocked",
        Some(&format!("reason={}, cmd_program={}", reason, validated_cmd.program())),
    );
    return None;
}

if gate_result.needs_interaction() {
    tracing::info!("exec_ws: command flagged for review — allowing");
}
```

### 2. Check the `ActionType` enum

In `crates/zp-core/src/` (likely `types.rs` or `lib.rs`), check whether `ActionType::Execute { command: String }` exists. If not, add it. The existing variants likely include `ApiCall`, `ToolUse`, etc. — `Execute` should be a peer variant for command execution. If `Execute` already exists but with different fields, adapt the gate_context construction to match.

### 3. Check `validated_cmd.program()`

The `ValidatedCommand` struct is in `crates/zp-server/src/auth.rs`. Verify it exposes a `program()` method that returns the executable name. If not, add a simple getter:

```rust
pub fn program(&self) -> &str {
    &self.program
}
```

### 4. Add the `zp_core` import if needed

`exec_ws.rs` currently imports from `crate::{auth, tool_chain, AppState}`. If `zp_core` types aren't already in scope via re-exports, add:

```rust
use zp_core::{ActionType, ActorId, PolicyContext, TrustTier, Channel, ConversationId};
```

Or use fully qualified paths as proxy.rs does.

### 5. Update ARCHITECTURE-2026-04.md

In `docs/ARCHITECTURE-2026-04.md`, find the Claim 3 status line:

```
*Status:* EXEC-01..04 prove that the gate is not enforced for `/ws/exec`. Currently false.
```

Replace with:

```
*Status:* EXEC-01..04 originally proved the gate was not enforced for `/ws/exec`. Fixed: gate.evaluate() now called before every spawn. Currently true.
```

### 6. Update Claim 1 status too (while you're in the file)

Find:
```
*Status:* AUDIT-01 found four such breaks. Currently false.
```

Replace with:
```
*Status:* AUDIT-01 found four such breaks (concurrent-append race). Fixed: transactional append with BEGIN IMMEDIATE, UNIQUE(prev_hash) index, atomic chain-tip computation. Currently true.
```

## Verification

After making changes:

1. `cargo check --workspace` must pass
2. `cargo test --workspace` must pass (all existing tests, no regressions)
3. Grep for `gate.evaluate` in exec_ws.rs to confirm it's present
4. Grep for "Currently false" in ARCHITECTURE-2026-04.md to confirm no remaining false claims for Claims 1 and 3

## Commit Message

```
fix(exec_ws): wire GovernanceGate into /ws/exec — close Claim 3

The WebSocket exec handler performed input validation (safe_path,
metacharacter rejection, program allowlist) but never consulted the
GovernanceGate, making Claim 3 ("every side effect passes through P3")
false for this code path.

Wire gate.evaluate() into execute_and_stream() before spawn, following
the same pattern as proxy.rs. Blocked executions emit a
tool:cmd:gate_blocked receipt. Update ARCHITECTURE-2026-04.md to mark
Claims 1 and 3 as true.

Closes the last Claim 3 falsifier. All governance-significant code
paths now route through the formal policy gate.
```

## Do NOT

- Do not remove existing input validation (safe_path, metachar, allowlist) — those are defense-in-depth and stay
- Do not change the gate evaluation pattern from what proxy.rs uses — follow the established convention
- Do not add new dependencies — all required types are already in zp_core and zp_policy
