# Vault Integrity System — Design Document

**Date**: 2026-06-28
**Status**: Implementation in progress
**Author**: Ken Romero + Claude (Opus)
**Relates to**: ARCHITECTURE-2026-04.md §4c (tool lifecycle), Principle 4 (every bit counts), Principle 8 (one canonical path)

## Problem Statement

The IronClaw LLM routing failure that surfaced on 2026-06-28 traces to a single root cause: **write without verify**. Two API keys were stored in the vault via hidden prompt — one stored empty (0 bytes), one stored with 164 chars of garbage (expected ~108). Neither was validated on write. Neither was validated on launch. The system silently degraded through three fallback layers before surfacing a misleading NEAR AI session error.

This is not a one-off. The vault currently contains:

- 9 orphaned keys under `providers/tools/ironclaw/` that are never injected (resolve_tool_env only reads `tools/{tool}/`)
- A full Anthropic API key leaked as a vault *key name* in plaintext
- A malformed key name with a URL embedded (`OPENAI_BASE_URL=https://routellm.abacus.ai/v1`)
- 3 empty values for keys that should contain credentials

The system has no self-awareness. It cannot distinguish "working correctly" from "silently degraded."

## Diagnosis: Five Structural Gaps

### Gap 1: No canonical schema

IronClaw is the only substrate-launched tool without a `.zp-configure.toml` manifest. The manifest machinery exists (ToolManifest, CapabilityRequirement, VerificationConfig, ConfigurableParam) but IronClaw doesn't use it. Without a schema, there's nothing to validate against.

### Gap 2: Write without verify

`run_vault_set_tool_env` stores a value and prints the byte count, but never reads it back. When input comes from a hidden prompt (rpassword-style stdin), truncation, double-paste, and trailing garbage are common. The system prints "stored (164 bytes)" and moves on.

### Gap 3: Inject without validate

`tool_launch_handler` calls `resolve_tool_env`, gets a `HashMap<String, Vec<u8>>`, and injects everything into the child process env. No type checking, no length validation, no format verification. A 0-byte API key and a malformed key name with `=` in it both get injected silently.

### Gap 4: Silent degradation

Every failure in the ZP governance path is `warn!()` level and degrade-open. The failover chain absorbs N-1 errors. The error the operator sees (NEAR AI session renewal) is 3 layers removed from the actual problem (empty LLM_API_KEY). The `ToolChainState` lifecycle tracks `preflight_passed` but preflight doesn't check vault integrity.

### Gap 5: Namespace incoherence

The vault has three namespaces for ironclaw keys: `tools/ironclaw/` (47 keys, injected), `providers/tools/ironclaw/` (9 keys, orphaned), and `zp_meta/tools/ironclaw/` (2 keys, metadata). `resolve_tool_env` only reads the first. The orphans include RUST_LOG (the tracing config needed to debug the very problems caused by the other orphans).

## Existing Infrastructure (Not Reinventing)

| Component | Location | What it does | What's missing |
|-----------|----------|--------------|----------------|
| `ToolManifest` | zp-engine/capability.rs | Declares required/optional capabilities, env vars, verification endpoints | No per-var format constraints |
| `ToolChainState` | zp-server/tool_chain.rs | Lifecycle: canonicalized → configured → preflight → launched → verified | Preflight doesn't check vault |
| `VerificationConfig` | zp-engine/capability.rs | Post-launch probes to confirm credentials work | IronClaw doesn't have one |
| `ConfigPattern` + `ConfigField` | zp-configure/lib.rs | Semantic field types (ApiKey, Url, Model, etc.) | Not connected to launch-time validation |
| `run_vault_set_tool_env` | zp-configure/lib.rs | Stores tool env vars in vault | No post-write verification |
| `tool_launch_handler` | zp-server/lib.rs | Resolves vault → injects env → launches tool | No validation between resolve and inject |
| `zp-preflight` | zp-preflight/ | System dependency checks (rustc, libssl, ports) | Doesn't touch vault or tool config |
| `validate.rs` | zp-engine/validate.rs | Live credential probes (GET /v1/models, etc.) | Not called during launch |
| `ZP_OWNED_VARS` | zp-server/lib.rs | Substrate-controlled vars skipped during injection | Works correctly but undocumented in manifests |

## Design: Four Phases

### Phase 0: IronClaw Manifest (the canonical schema)

Write `.zp-configure.toml` for IronClaw. This is the single source of truth for what IronClaw requires, what format each var should have, and what the substrate owns.

New manifest section `[[vault_schema]]` declares per-var constraints:

```toml
[[vault_schema]]
var = "ANTHROPIC_API_KEY"
field_type = "api_key"
required = true
min_length = 90
max_length = 120
prefix = "sk-ant-"
```

This extends the existing `CapabilityRequirement.env_vars` (which just lists var names) with format-level validation rules.

### Phase 1: VaultVarSchema in ToolManifest

Add `VaultVarSchema` struct to `zp-engine/capability.rs`:

```rust
pub struct VaultVarSchema {
    pub var: String,
    pub field_type: ConfigField,
    pub required: bool,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub prefix: Option<String>,
    pub allowed_values: Vec<String>,
    pub substrate_owned: bool,
}
```

Add `vault_schema: Vec<VaultVarSchema>` to `ToolManifest`.

Add `validate_tool_env(schema: &[VaultVarSchema], env: &HashMap<String, Vec<u8>>) -> Vec<VaultVarViolation>` — returns a list of violations (missing, empty, too short, too long, wrong prefix, etc.).

### Phase 2: Vault validation in tool_launch_handler

After `resolve_tool_env` and before injection, if a manifest exists:

1. Load the manifest (already done for model resolution — reuse).
2. Call `validate_tool_env` against the resolved values.
3. For each violation:
   - Log at `error!` (not `warn!`).
   - Emit a `tool:preflight:failed:{tool}` receipt to the audit chain.
   - Add to `ToolChainState.preflight_issues`.
4. Still inject and launch (degrade-open for the process), but `preflight_passed = false`.

The existing `ToolChainState.ready` already gates on `preflight_passed`. Any surface that reads readiness (CLI, dashboard, the Regent) will report the broken state.

### Phase 3: Post-write verification

In `run_vault_set_tool_env`, after `store_tool_env` + `save`:

1. Immediately `vault.retrieve(&vault_ref)` to read back.
2. Verify `retrieved.len() == value.len()`. If not, error and abort.
3. If a manifest is available for this tool, load its `vault_schema` and validate the stored value against the var's constraints.
4. Print the validation result: `"Stored ANTHROPIC_API_KEY (108 bytes, prefix=sk-ant-, validated)"` or `"ERROR: ANTHROPIC_API_KEY stored 164 bytes but max_length=120"`.

### Phase 4: Vault hygiene audit

Add `vault_audit(vault: &CredentialVault, tool: &str, schema: &[VaultVarSchema]) -> Vec<AuditFinding>` to zp-configure.

Checks:
- **Orphaned namespaces**: keys under `providers/tools/{tool}/` that shadow `tools/{tool}/` keys.
- **Malformed key names**: `=` in key name, URL fragments in key name.
- **Leaked secrets**: API key patterns (`sk-ant-`, `sk-`, `ghp_`, etc.) appearing in key *names*.
- **Missing required vars**: declared in vault_schema but absent from vault.
- **Empty values**: 0-byte plaintext for non-toggle fields.
- **Suspicious lengths**: ciphertext length outside declared min/max range.
- **Stale refs**: ref targets that don't exist.
- **Duplicate vars**: same var in both `tools/{tool}/` and `providers/tools/{tool}/`.

Run automatically during `zp configure tool` and on `tool_launch_handler`.

## Immediate Vault Fixes Required

Before or alongside implementation, the vault itself needs cleanup:

1. **Delete** `providers/anthropic/sk-ant-api03-...` (leaked key as key name) — rotate the key.
2. **Delete** `tools/ironclaw/OPENAI_BASE_URL=https://routellm.abacus.ai/v1` (malformed).
3. **Fix** `tools/ironclaw/LLM_API_KEY` — store the actual Anthropic key (or make it a ref to `providers/anthropic/api_key`).
4. **Fix** `tools/ironclaw/ANTHROPIC_API_KEY` — re-store with correct value (~108 chars).
5. **Fix** `tools/ironclaw/OPENAI_API_KEY` — clear intentionally or remove.
6. **Delete** all 9 `providers/tools/ironclaw/*` orphans.
7. **Consider** making `tools/ironclaw/ANTHROPIC_API_KEY` a ref to `providers/anthropic/api_key` (like pentagi, ember, and shannon already do).

## Connects To

- **Principle 4 (every bit counts)**: Orphaned keys, duplicate namespaces, and unvalidated values are the duplicate data paths the principle catches.
- **Principle 8 (one canonical path)**: The manifest is the single authority for what a tool requires. The vault is the single authority for credential storage. Validation connects the two.
- **Singular sovereign root**: One schema, everything derived. No separate config files, no ad-hoc vault-set commands that bypass validation.
- **The lsof test (self-awareness)**: The substrate is mature when `zp ps --tools` can report not just "running" but "running with valid credentials, all required capabilities verified."
- **Config reflects today, not roadmap**: The manifest declares what the tool needs now. Validation enforces it now. Future capabilities get added to the manifest when they ship.
