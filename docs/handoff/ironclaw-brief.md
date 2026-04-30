# Brief for IronClaw-side Claude — F3/F5/F8 + cognition-level governance

You are working in `~/projects/ironclaw` while another Claude instance
drives `zp-server` from `~/projects/zeropoint`. Coordinate through Ken;
do not modify anything in `~/ZeroPoint/` (that's the ZP runtime — vault,
keys, audit chain). Stay in `~/projects/ironclaw/`.

## Current state (verified by the ZP-side Claude)

- IronClaw is already a canonicalized ZP tenant since 2026-04-23.
- Bead-zero on chain: `tool:canonicalized:ironclaw`.
- 7 preflight checks all passing: env_config, compose_valid,
  images_pulled, launch_method, native_binary, db_connectivity,
  deep_scan:env_override, deep_scan:database_url.
- `.zp-configure.toml` is rich (backend selector pattern, 4 LLM
  backends, messaging channels, code_execution).
- `registry/tools/*.json` ships 13 tool manifests + 1 widget manifest.
  All 14 passed F3 content scan: 0 flagged, 0 blocked.

## What's missing / what to do

### (1) Add F5 `[capabilities]` section to `.zp-configure.toml`

The manifest has no capability envelope. ZP's gate currently treats
IronClaw's reversibility as `unknown`, which folds to `irreversible`
(blocks tier-0 invocations). For the **tool itself**, add at the
top level:

```toml
[capabilities]
reversibility = "partial"
```

`partial` is the right call for IronClaw-as-a-whole because some agent
actions are reversible (web search, llm context lookup) and many are
not (sending email, posting to Slack/Telegram, committing to GitHub).
The gate will treat `partial` as `irreversible` for now (conservative),
but you've recorded the truth.

### (2) Annotate per-tool reversibility on each `registry/tools/*.json`

Each tool manifest is currently just MCP-shaped (name, description,
parameters). Add a `reversibility` field at the top level of each:

| Tool                | Reversibility         | Reason                                        |
|---------------------|----------------------|-----------------------------------------------|
| `web_search`        | `reversible`         | Read-only                                     |
| `llm_context`       | `reversible`         | In-process state                              |
| `portfolio`         | `reversible`         | Read-only (verify; if writes exist → partial) |
| `google_calendar`   | `partial`            | Events can be deleted but invitees notified   |
| `gmail`             | `irreversible`       | Sending email cannot be unsent                |
| `google_drive`      | `partial`            | Files restorable from trash for ~30d          |
| `google_docs`       | `partial`            | Edits restorable from version history         |
| `google_sheets`     | `partial`            | Edits restorable from version history         |
| `google_slides`     | `partial`            | Edits restorable from version history         |
| `slack_tool`        | `irreversible`       | Posts notify recipients immediately           |
| `telegram_mtproto`  | `irreversible`       | Same                                          |
| `github`            | `partial`            | Can revert/delete; commits are durable        |
| `composio`          | `unknown`            | Meta-tool; depends on which sub-tool invoked  |
| Portfolio (widget)  | `reversible`         | UI-only                                       |

(Verify these against the actual JSON schema each tool declares — I'm
inferring from filenames. If a tool's `parameters` show write/delete
verbs you'd downgrade reversibility accordingly.)

The shape ZP expects:

```json
{
  "name": "gmail",
  "description": "...",
  "parameters": [...],
  "reversibility": "irreversible"
}
```

Plain string field, snake_case. ZP's F3 scanner already reads
`.zp-configure.toml`'s `[capabilities].reversibility` for the
tool-as-a-whole; per-tool annotation requires F5's per-tool registry
extension which is on ZP's roadmap. For now, having the field present
means future ZP versions can pick it up without IronClaw needing
another touch.

### (3) Mitigate the dotenvy shadow risk

ZP's deep scan flagged this on every startup:

> Cargo dependency `dotenvy` detected — this crate loads .env files at
> runtime, potentially overriding shell environment variables. Port
> and auth vars MUST be injected via `cmd.env()` to prevent shadow
> conflicts.

This is a real failure mode: ZP injects vault-resolved credentials
into the launched process, then `dotenvy::dotenv()` runs at
`fn main` and silently overwrites them with whatever `.env` says.
Two clean fixes (pick one):

**Option A — drop dotenvy entirely.** ZP injects 28 vars on launch.
Move all dev-mode `.env` loading behind a `cfg!(debug_assertions)` or
a `--load-env` CLI flag so production never reads the file. Cleanest.

**Option B — guard dotenvy.** Replace `dotenvy::dotenv()?` with
`dotenvy::from_filename_override(".env.local")?`. Reserve `.env` for
ZP-injected production state; `.env.local` is dev-only. Document the
contract.

Either way: confirm with Ken which path. The change is small (one or
two files in IronClaw's `src/main.rs` or `src/config.rs` typically)
but it's load-bearing for ZP's vault model.

### (4) Cognition-level governance — receipts from inside the agent loop

This is the actual upgrade from "tenant cockpit" to "tenant cockpit
with cognition governance."

Today IronClaw emits **lifecycle** receipts (canonicalized, configured,
launched) via ZP's tool_chain. To reach cognition level, IronClaw
must emit **observation/policy/execution** receipts from inside its
agent loop — every time the agent picks a tool, executes it, observes
a result, the receipt records *what was decided and why*.

Endpoints to call (from inside IronClaw's agent loop, against
`http://localhost:17010`):

| When                        | Endpoint                            | Receipt type     |
|-----------------------------|-------------------------------------|------------------|
| Before invoking a tool      | `POST /api/v1/gate/tool-call`       | (gate decision)  |
| After observing tool result | `POST /api/v1/receipts/generate`    | `observation`    |
| End of reasoning step       | `POST /api/v1/receipts/generate`    | `policy_claim`   |

The gate-call returns `allowed: bool, receipt_id, reversibility,
denial_reason`. If `allowed=false`, IronClaw must respect the denial
(don't invoke the tool). On `allowed=true`, proceed and emit the
result-observation receipt afterwards.

Pseudocode for IronClaw's agent loop hook:

```rust
async fn invoke_tool_with_governance(
    tool: &str,
    params: serde_json::Value,
    tier: u8,
) -> Result<ToolResult> {
    let gate = zp_client.gate_tool_call(tool, &params, tier).await?;
    if !gate.allowed {
        return Err(GovernanceDenied(gate.denial_reason));
    }
    let result = tools::invoke(tool, params).await?;
    zp_client.emit_observation(json!({
        "tool": tool,
        "result_hash": blake3(serialize(result)),
        "parent_receipt_id": gate.receipt_id,
    })).await?;
    Ok(result)
}
```

`zp_client` can be the F7 Python SDK (if IronClaw has Python helpers)
or a thin Rust HTTP client (`reqwest`). The Python SDK is at
`~/projects/zeropoint/zeropoint-py/`.

### (5) What to NOT touch

- `~/ZeroPoint/` — vault, keys, audit.db, sovereignty config. Read-only
  from your side. ZP-side Claude owns chain mutations.
- `crates/zp-*/` — the ZP source tree. If you spot something needing
  a ZP fix, surface it via Ken.
- IronClaw's bead-zero on the chain — already there, don't try to
  re-canonicalize from your side. ZP-side Claude will emit a lifecycle
  bead carrying the F3 scan + F5 reversibility once your manifest
  changes are committed.

### (6) Done criteria

When you've finished:
1. `.zp-configure.toml` has `[capabilities] reversibility = "partial"`.
2. Each `registry/tools/*.json` has a top-level `reversibility` field.
3. dotenvy mitigation chosen (A or B) and discussed with Ken; if
   applied, IronClaw still builds clean.
4. (Optional, longer scope) cognition-loop hooks drafted in IronClaw's
   agent code with TODOs marking the integration points — actual
   wiring waits for Ken's go-ahead.

Ping Ken when each of (1), (2), (3) is done — ZP-side Claude will
re-run `zp scan ~/projects/ironclaw` to confirm advisories drop, and
will check that the chain picks up the new reversibility on next
zp-server tick.
