# GOOSE INTEGRATION — Where the Gate Actually Goes

**Draft for discussion** · 2026-08-13 · Follows `HARNESS-SURVEY-2026-08.md`
**Verified against** `aaif-goose/goose` @ `55c6228`, full clone, source read.

> **Correction to the survey:** I scored Goose 3/5 on criterion 1 for having a blocking hook that fails open. That was too generous. Goose's `PreToolUse` hook has **three verified bypasses**, one of them the same class of defect that disqualified OpenCode and Kilo Code. It should score **1/5**.
>
> The recommendation does not change — it gets stronger. We were never going to use the hook, and now there is a precise, cited reason why not, plus an exact integration point that closes all three bypasses at once.

---

## 1. The three bypasses

### 1.1 Subagents run with no hook manager at all

`crates/goose/src/agents/agent.rs:438-445`:

```rust
hook_manager: if is_subagent {
    crate::hooks::HookManager::default()   // empty: has_hooks() == false
} else {
    crate::hooks::HookManager::load(
        std::env::current_dir().ok().as_deref(),
        use_login_shell_path,
    )
},
```

`is_subagent` comes from `AgentConfig` (`agent.rs:204`, default `false`, read at `:411`). `subagent_handler.rs:140` constructs subagents as `Arc::new(Agent::with_config(config))` and drives them through the normal `.reply(...)` loop (`:196`).

So every tool call made by a delegated sub-agent skips `PreToolUse` entirely — not by a routing accident, but by construction. This is **the same defect as OpenCode #5894**, which I used to disqualify OpenCode and Kilo from consideration. Consistency requires naming it here.

It is arguably worse than OpenCode's version, because it is deliberate: someone decided subagents should not pay hook cost. That reads as a performance decision made without a threat model, which means a patch is likely to be welcomed rather than argued.

### 1.2 The ACP server dispatches around the hook

`crates/goose/src/acp/server/tools.rs:107-110` calls `agent.extension_manager.dispatch_tool_call(&ctx, tool_call, …)` directly. Nothing in that path consults `hook_manager`. When Goose runs as an ACP agent — i.e. driven by an editor, or by us — tool calls issued over ACP are ungoverned.

This one matters directly for Regent coding mode, since ACP over stdio is one of the two ways we'd drive Goose.

### 1.3 The code-execution platform extension dispatches around the hook

`crates/goose/src/agents/platform_extensions/code_execution.rs:382` — same pattern, `manager.dispatch_tool_call(&ctx, tool_call, cancellation_token)`, no hook consultation. Tools invoked from generated code bypass the gate.

### 1.4 And on the paths that *do* consult it, it fails open

`crates/goose/src/hooks/mod.rs:479-534`. Three distinct fail-open routes in one function:

- Context serialization failure → `return HookDecision::Allow` for **all** rules (`:486-492`).
- `run_action` error — spawn failure, timeout (default 30s) — → `continue`, skipping to the next action (`:505-516`).
- `deny_reason` (`:553-576`) returns `Some` only for exit code 2 or `{"decision":"block"}` on stdout. **Every other exit code is an allow.** A hook that panics, that is not executable, or that exits 1 does not deny.

The source is candid about it: *"a misbehaving hook MUST NOT block."* That is a defensible position for a plugin ecosystem and an indefensible one for a policy gate.

Also worth noting: `LoadedAction` is a single-variant enum destructured with an irrefutable `let` (`:502`). Hooks are **subprocess-only** — there is no in-process registration path today. So a library-level gate is not something we can bolt on through existing extension points; it needs a patch.

---

## 2. The choke point

All five dispatch paths funnel through one `pub` method:

**`ExtensionManager::dispatch_tool_call`** — `crates/goose/src/agents/extension_manager.rs:1833`

```rust
pub async fn dispatch_tool_call(
    &self,
    ctx: &super::tool_execution::ToolCallContext,
    tool_call: CallToolRequestParams,
    cancellation_token: CancellationToken,
) -> std::result::Result<ToolCallResult, ErrorData>
```

Callers:

| Call site | Consults `PreToolUse`? |
|---|---|
| `state_machine/ops_toolcalling.rs:263` (state-machine loop) | yes (`:233-252`) |
| `agent.rs:1235` via `Agent::dispatch_tool_call` (legacy loop) | yes (`:1156-1171`) |
| `agent.rs:888` (approved/read-only tools) | via the above |
| `acp/server/tools.rs:110` | **no** |
| `platform_extensions/code_execution.rs:382` | **no** |

Plus subagents, which traverse the first two paths with an empty hook manager.

`ExtensionManager::dispatch_tool_call` is where a gate belongs. It is below every bypass, it already receives `ToolCallContext` (session id, working dir, request id), and it is the natural boundary: everything above it is the harness deciding what to do; everything below it is the tool doing it.

---

## 3. The patch

Two forms. Take the second upstream; run the first locally until it lands.

### Form A — local, minimal, for our fork

Insert at the top of `dispatch_tool_call`, before `resolve_tool`:

```rust
if let Some(gate) = self.tool_gate.as_ref() {
    let vctx = zp_trace::ToolCallCtx {
        harness: "goose",
        session_id: ctx.session_id.clone(),
        call_id: ctx.tool_call_request_id.clone(),
        tool_name: tool_call.name.to_string(),
        args: tool_call.arguments.clone()
            .map(serde_json::Value::Object).unwrap_or(serde_json::Value::Null),
        working_dir: ctx.working_dir_str().map(str::to_owned),
        delegated: self.is_subagent,
        depth: self.delegation_depth,
    };
    if let zp_trace::GateVerdict::Deny { reason, .. } = gate.gate(&vctx).await {
        return Err(ErrorData::new(ErrorCode::INTERNAL_ERROR, reason, None));
    }
}
```

Note the deny message shape: Goose's own hook denial text already tells the model *"Do not retry; this is a policy denial, not a transient failure"* (`ops_toolcalling.rs:246-249`). Match that wording — it is good, and consistency across gates means the model learns one pattern.

### Form B — upstream, and the better contribution

Add an in-process gate trait to `ExtensionManager`:

```rust
/// A governance gate consulted before every tool dispatch, on every path.
#[async_trait]
pub trait ToolGate: Send + Sync {
    async fn gate(&self, ctx: &ToolCallContext, call: &CallToolRequestParams)
        -> Result<(), GateDenial>;
}

impl ExtensionManager {
    pub fn set_tool_gate(&mut self, gate: Arc<dyn ToolGate>) { … }
}
```

This is a better upstream proposal than the `fail_closed` hook option I suggested in the survey, for three reasons:

1. It fixes all three bypasses in one change, because it sits below them.
2. It gives AAIF Goose an enforcement story it currently lacks — the hook system is explicitly designed not to be one.
3. It costs the plugin ecosystem nothing. Subprocess hooks keep their fail-open semantics, which is right for plugins; the gate is a separate, in-process, deliberately-installed thing.

It is also the exact trait-injection model GAR §3.1 describes for IronClaw. Same argument, different tenant.

**Suggested sequencing with upstream:** open an issue documenting §1.1 first, on its own, as a security finding — the subagent bypass stands independent of anything ZeroPoint wants. If it is accepted as a bug, the gate trait becomes the natural fix to propose rather than an outside agenda.

---

## 4. What `zp-trace` provides

Crate skeleton attached. Shape:

- **`ToolGate`** — the harness-facing contract. One blocking method, one recording method. Deliberately minimal: anything richer becomes a second home for policy, and `zp-regent/src/tools.rs` documents what two homes for one declaration cost.
- **`ToolCallCtx`** — normalized across harnesses, carrying `delegated` and `depth`. That field is the point: it is the distinction Goose's own gate structurally cannot make, and the one a mode-scoped delegation needs.
- **`FailureMode::Closed` by default** — an unevaluable gate has not allowed. Fail-open is available but marks every receipt it emits with `coverage_asserted: false`, so the chain never carries a claim the gate did not earn.
- **`DenyAllGate`** — installed when governance is enabled but unconfigured. A harness running ungoverned because config was missing is precisely the failure mode this exists to prevent.
- **`redact`** — receipts carry a hash of the full arguments plus a bounded, redacted projection. The hash is over the original, so redaction never weakens verification. Extends `zp-regent/src/config.rs`'s credential rule from the cognitive path to the audit path, which matters more: the chain is durable.

Two things to resolve before it compiles: `ReceiptType` and `Action` variants need pinning against `zp-receipt/src/types.rs:604` and `:1097`, and `ReceiptChain::tip()` needs confirming against `chain.rs`. Both marked in the source.

---

## 5. Revised sequence

1. **`zp-trace` core**, harness-agnostic, with the `DenyAllGate` and redaction tests green. No Goose dependency yet.
2. **Form A patch on a Goose fork**, wired to a trace-only gate. Proves receipts flow from a foreign Rust harness, and proves the choke point catches the ACP path — test by driving it over `goose acp` and confirming subagent calls appear in the chain.
3. **Upstream issue on §1.1** — the subagent bypass, standing alone as a security finding.
4. **Upstream the gate trait** (Form B) once the issue is acknowledged.
5. **Codex adapter** against `app-server`, answering `execCommandApproval` / `applyPatchApproval` as the driving parent. Same `ToolGate`, different transport — which is the portability claim, demonstrated rather than asserted.

The order matters: (2) before (3) means we arrive at the upstream conversation with a working patch and a reproduction, not a proposal.
