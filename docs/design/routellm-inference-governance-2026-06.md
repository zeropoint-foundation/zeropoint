# RouteLLM Inference Governance — Integration Design

**Date:** 2026-06-14
**Author:** Ken Romero / Claude synthesis
**Status:** Design — pre-implementation
**Companion documents:**
- `docs/ARCHITECTURE-2026-04.md` — north star, especially §4b (cockpit-OS), Part V½ (eight principles), Phase 4 (GAR)
- `docs/design/governed-agent-runtime.md` — GAR spec, §3.1 (integration model), §3.1.1 (MCP tenancy)
- `docs/AGENT-TOOL-CONTRACT-2026-06.md` — agent-side Required affordance #2 (inference through gate)
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — runtime-neutral edge affordances

---

## 1. The gap this closes

The GAR (§2, problem statement) identifies that "cost tracking is enforced but not attested — spending is not receipted as governance evidence." The Agent-Tool Contract (Required affordance #2) states explicitly that inference requests are substrate side effects that must go through the gate before the effect occurs. The architecture (Phase 4, §9) names `InferenceRequestClaim` as one of the 11 new receipt types the GAR introduces.

None of this is implemented. IronClaw talks directly to its configured LLM backend — currently AbacusAI RouteLLM at `https://routellm.abacus.ai/v1` — without gate evaluation, without chain receipts, and without the substrate seeing what model was actually used. Model selection lives in `~/.ironclaw/config.toml` (`selected_model`) and vault-injected env vars (`LLM_BASE_URL`, `LLM_API_KEY`), neither of which are chain-anchored state.

This document defines the integration shape that closes the gap: inference becomes a receipted, gate-evaluated, delegation-scoped substrate concern.

---

## 2. What already exists on each side

### ZeroPoint side
- **ZP-Sig envelopes** — gate request authentication is implemented (`crates/zp-gate-envelope`). IronClaw's `ZpClient` already signs every outbound gate request.
- **`InferenceRequestClaim`** — named in the receipt vocabulary (GAR §9) but not yet implemented in `zp-receipt`.
- **Vault injection** — `LLM_BASE_URL` and `LLM_API_KEY` are vault-stored and injected at launch. This is the credential path; model selection should follow the same pattern.
- **Delegation narrowing** — the eight delegation invariants exist in `DelegationChain::verify()`. Inference scope is a new capability class to narrow against.
- **Gate evaluation** — `gate.evaluate()` is called before every privileged action (EXEC-01..04). Inference is a privileged action.

### IronClaw side
- **`LlmProvider` trait** — IronClaw uses trait objects throughout; `LlmProvider` is the seam. ZP can provide a wrapper implementation that intercepts calls without changing IronClaw's internal logic.
- **`openai_compatible` backend** — `llm_backend = "openai_compatible"` with `LLM_BASE_URL` + `LLM_API_KEY` env vars already routes to RouteLLM. The backend reads `selected_model` from config or `LLM_MODEL` env var for the per-request model field.
- **Response `model` field** — RouteLLM's response carries the actual `model` used (which may differ from the requested model when `route-llm` auto-routes). This is the auditable fact that must land on chain.
- **Cost guard** — `src/agent/cost_guard.rs` (external — RouteLLM's tree, not this one) enforces daily budgets and hourly rate limits internally. These numbers should feed into receipts.

### RouteLLM side
- **OpenAI-compatible API** at `https://routellm.abacus.ai/v1` — standard `/v1/chat/completions`.
- **`route-llm` model** — auto-routes to "best" model; actual model returned in response. No provider exclusion mechanism.
- **Named models** — any named model (e.g. `claude-sonnet-4-6`) bypasses routing. Model IDs discoverable via `GET /v1/models`.
- **Gemini schema constraint** — when `route-llm` routes to Gemini, tool parameter schemas must use only Gemini's type enum. This is a capability compatibility concern, not a routing concern.

---

## 3. The three receipt types

### 3.1 `preference:llm:policy:set`

Emitted when the operator declares inference policy. This is the chain-anchored replacement for `selected_model` in TOML. IronClaw reads this at startup via ZpClient — not from config.

```
preference:llm:policy:set {
    backend_url: string,          // "https://routellm.abacus.ai/v1"
    routing_strategy: string,     // "route-llm" | specific model ID
    model_allowlist: [string],    // [] = unrestricted; ["claude-*", "gpt-*"] = no Gemini
    cost_cap_daily_usd: f64,      // operator-declared ceiling; gate enforces
    schema_compat: [string],      // ["gemini"] = schemas validated before dispatch
}
```

**Who emits it:** Operator, via `zp configure exec` or a forthcoming `zp llm policy set` verb.

**Principle mapping:** P1 (signing is gravity — model policy is an operator assertion, not a config value); P8 (one canonical path — chain state is the single source of truth for what model the agent may use).

### 3.2 `inference:dispatched`

Emitted immediately before the HTTP request leaves IronClaw to RouteLLM. The gate must have produced an `allowed` receipt before this is emitted.

```
inference:dispatched {
    request_id: uuid,
    model_requested: string,      // what IronClaw sent as the `model` field
    tool_names: [string],         // tools declared in the request, if any
    prompt_tokens_estimated: u32, // token count before call
    session_id: string,           // links to agent session
    policy_receipt_id: string,    // the `preference:llm:policy:set` receipt this call operates under
}
```

**Who emits it:** ZP's `LlmProvider` wrapper, after gate evaluation, before HTTP dispatch.

### 3.3 `inference:completed`

Emitted after the HTTP response returns. Captures what actually ran.

```
inference:completed {
    request_id: uuid,             // matches inference:dispatched
    model_used: string,           // from RouteLLM response `model` field — the auditable fact
    prompt_tokens: u32,
    completion_tokens: u32,
    finish_reason: string,        // "stop" | "tool_calls" | "error" | "length"
    error_code: Option<string>,   // if finish_reason == "error"
    cost_usd: Option<f64>,        // if RouteLLM returns usage pricing
    latency_ms: u64,
}
```

**Who emits it:** ZP's `LlmProvider` wrapper, after response parsing.

**Why `model_used` is load-bearing:** When `route-llm` auto-routes, the operator doesn't know what ran without this field. The Gemini schema error (`route-llm` → Gemini → 400) now lands on chain as `model_used: "gemini-*"` + `finish_reason: "error"` — the substrate sees the pattern before the operator has to grep logs. This is the chain as store-and-forward (Principle 5) applied to inference: the truth is in the chain, not in ephemeral HTTP logs.

### 3.4 `inference:failed`

A distinct, lightweight receipt for calls that abort before completing — either blocked by the gate or rejected by the provider. Separate from `inference:completed` for two structural reasons: (1) failed calls produce no usage data, so `inference:completed`'s token/cost fields would all be null — a violation of Principle 4; (2) the gate needs to accumulate failure counts for circuit-breaking without parsing a full completion payload.

```
inference:failed {
    request_id: uuid,
    model_requested: string,
    failure_class: enum {
        GateBlocked,         // gate denied before HTTP call was made
        ProviderError(u16),  // HTTP error from RouteLLM (400, 401, 429, etc.)
        NetworkError,
        SchemaRejected,      // provider-side schema validation — the Gemini case
        Timeout,
    },
    error_detail: string,    // verbatim error message — load-bearing for pattern matching
    tool_names: [string],    // populated when failure_class == SchemaRejected
    session_id: string,
}
```

**`error_detail` is load-bearing.** The verbatim Gemini validation message (`"type" - Input should be 'TYPE_UNSPECIFIED'...`) lets X3 confirm schema incompatibility from the receipt chain without re-running the call. Pattern: agent → `route-llm` → `SchemaRejected` × N with same `tool_names` → the tool schema is the cause, not the model or the routing.

**Circuit-breaker:** The gate accumulates `inference:failed { failure_class: SchemaRejected }` receipts per `(agent, model_requested)` pair within a session window. After a policy-declared threshold (default: 3), the gate issues `gate:denied:inference:circuit_open` without attempting the HTTP call. The circuit-breaker policy lives in `preference:llm:policy:set` — the operator declares the tolerance, the gate enforces it. This prevents flooding RouteLLM with calls the substrate already knows will fail.

---

## 4. The gate integration

Inference is a privileged action. It must pass through `gate.evaluate()` before dispatch. The gate check for inference has two layers:

**Layer 1 — model allowlist check.** Read the current `preference:llm:policy:set` receipt from chain state. If `model_allowlist` is non-empty, verify `model_requested` matches at least one entry. Failure → `gate:denied:inference:outside_allowlist` receipt, no HTTP call.

**Layer 2 — schema compatibility check.** If `schema_compat` includes a provider (e.g. `"gemini"`) and the request carries tools, validate all tool parameter schemas against that provider's type constraints before dispatch. Failure → `gate:denied:inference:schema_incompatible` receipt, no HTTP call.

Layer 2 is the structural answer to the Gemini schema problem: fixing schemas to be Gemini-compatible is the prerequisite for setting `model_allowlist: []` (unrestricted) with `schema_compat: ["gemini"]`. Until schemas are clean, the gate prevents the 400 at the boundary rather than letting it arrive from RouteLLM. The schema audit becomes a governance act, not just a code quality pass.

---

## 5. Delegation narrowing

Inference scope is a new capability class in the delegation envelope. The operator can grant agents access to subsets of the model pool:

```
delegation:llm:model {
    scope: ModelScope,    // Unrestricted | Named(model_id) | Pattern("claude-*") | Provider(anthropic)
    max_tokens_per_call: u32,
    cost_cap_per_call_usd: f64,
}
```

An agent operating under a `delegation:llm:model { scope: Named("claude-sonnet-4-6") }` grant cannot request `route-llm` or any other model — the gate denies and receipts the denial. This is Claim 4 (future actions narrowed by trajectory) applied to inference: the operator's delegation history constrains what the agent can ask the LLM to do.

**The `route-llm` scope:** `ModelScope::Unrestricted` is required to use `route-llm`. Granting unrestricted scope to an agent is a meaningful operator decision — it should require explicit signing, not be the default. The default for new agents is `Named(config.routing_strategy)`, meaning they use whatever the current policy receipt specifies but cannot deviate from it.

---

## 6. The `LlmProvider` wrapper — integration seam

IronClaw's `LlmProvider` trait is the cleanest integration point. ZP provides a `ZpGovernedLlmProvider` wrapper that:

1. Holds an `Arc<ZpClient>` (for gate calls and receipt emission).
2. Holds an `Arc<dyn LlmProvider>` (the underlying RouteLLM backend).
3. On each inference call:
   - Reads current inference policy from chain state (cached with chain-tip invalidation).
   - Evaluates gate (model allowlist + schema compat checks).
   - Emits `inference:dispatched`.
   - Delegates to the inner provider.
   - Captures `model_used` from the response.
   - Emits `inference:completed`.
   - Returns the response to IronClaw unchanged.

From IronClaw's perspective, this is a normal `LlmProvider`. The governance is transparent. No IronClaw code changes beyond wiring the wrapper at `app.rs` construction.

This pattern is the GAR's trait-integration model (§3.1) applied to the inference surface: "ZP provides implementations. The agent doesn't need to be wrapped — it needs to be composed."

---

## 7. What needs to be built

Ordered by dependency:

**Step 1 — `InferenceRequestClaim` in `zp-receipt`**
Define the Rust types for the three receipt kinds above. This is schema definition work in `crates/zp-receipt/src/`. The receipt shape is determined by this document; no design ambiguity.

**Step 2 — `preference:llm:policy:set` verb**
Add `zp llm policy set` CLI verb that:
- Takes `--backend`, `--strategy` (model ID or `route-llm`), `--allowlist`, `--cost-cap` arguments.
- Emits a signed `preference:llm:policy:set` receipt.
- Stores backend credentials in vault (not on chain — chain carries the policy, vault carries the secret).
This replaces `selected_model` in `~/.ironclaw/config.toml` and the manual vault-set-tool-env dance.

**Step 3 — Gate evaluation for inference**
Extend `gate.evaluate()` with an `InferenceRequest` action type. Implement the two-layer check (allowlist + schema compat). This is the mechanism that makes the Gemini schema fix a governance gate rather than a code quality patch.

**Step 4 — `ZpGovernedLlmProvider` wrapper in IronClaw**
Implement the wrapper as described in §6. Wire it at `app.rs` alongside the existing `ZpClient` bootstrap. No IronClaw trait or API changes required.

**Step 5 — IronClaw reads inference policy from chain**
Replace `config.selected_model` with a chain-state read via `ZpClient::current_inference_policy()` at startup. Policy changes mid-session require a restart (acceptable for now; live policy reload is a future concern).

**Step 6 — Schema audit (prerequisite for `model_allowlist: []`)**
Audit all IronClaw built-in tool schemas for Gemini type compatibility. Fix non-conformant types. This is the prerequisite for granting unrestricted `route-llm` routing without the gate's schema-compat layer blocking every Gemini-routed call.

---

## 8. Principle filter

Every step above passes the eight-principle filter:

| Principle | How inference governance satisfies it |
|-----------|--------------------------------------|
| 1 — Signing is gravity | `inference:dispatched` and `inference:completed` are signed receipts. An inference that produces no receipt did not happen in the governance domain. |
| 2 — Identity is a key | Inference receipts trace to the agent's canonicalization receipt, which traces to Genesis. The model that ran is chain-attributable to the operator's key. |
| 3 — There is no center | Chain state is local. Policy reads from the local audit chain, not from a remote authority. RouteLLM is a capability endpoint, not a trust authority. |
| 4 — Every bit counts | `model_used` is load-bearing. `model_requested` is load-bearing. Everything else (latency, tokens, cost) is evidence for X3 sequence-level analysis. No redundant fields. |
| 5 — Store-and-forward is primary | `inference:completed` with `error_code` on a Gemini routing failure survives the session and is queryable later. The truth is in the chain. |
| 6 — A tool is intent, crystallized | `preference:llm:policy:set` IS the operator's intent about inference, crystallized as a signed receipt. Not a config value that could silently drift. |
| 7 — Contact does not commit | IronClaw contacting RouteLLM is contact. The gate's `allowed` receipt and `inference:dispatched` are the commits. A failed call that produces no receipts has produced contact without commit — which the missing receipt makes auditable. |
| 8 — One canonical path | Chain state is the single source for inference policy. `~/.ironclaw/config.toml`'s `selected_model` field is retired. No TOML, no env var, no vault key for model selection — only chain state projected through `ZpClient`. |

---

## 9. What this unlocks for X3

Once `inference:completed` with `model_used` is on chain for every call, the sequence of models used across a session becomes a chain-readable trajectory. X3's sequence-level compliance analysis can ask:

- "Did the agent ever route to a model outside its granted scope?" (delegation violation pattern)
- "Is `model_used` consistently drifting toward higher-cost models over the session?" (cost-abuse trajectory)
- "Does the agent invoke `route-llm` only on complex requests or uniformly?" (routing strategy validation)

These are not detectable from individual receipts. They are detectable from the receipt chain as a trajectory — which is exactly what X3 exists to analyze. The inference receipts are the workload that X3 needs to operate against real agent behavior, per GAR §9.

---

## 10. The Gemini problem, structurally

Under this design, the Gemini schema error has a structural home:

1. Gate evaluates: `model_requested = "route-llm"`, `schema_compat = ["gemini"]`, tool schemas present.
2. Gate finds Gemini-incompatible types in tool schemas.
3. Gate emits `gate:denied:inference:schema_incompatible` receipt.
4. IronClaw surfaces the denial to the operator; no HTTP call is made.
5. The denial receipt is queryable: "why did inference fail?" → "schema incompatible with Gemini routing."

The schema audit (Step 6) is now the prerequisite for clearing this gate layer. Once schemas are clean, the gate passes. The operator sets `schema_compat: ["gemini"]`, schema audit completes, gate opens, `route-llm` has access to the full provider pool including Gemini.

Until schemas are clean, the gate keeps Gemini out of the routing pool structurally rather than via config workaround. The difference: a config workaround is invisible to the chain; a gate denial is a receipt, queryable, auditable, and attributable.

---

*Next action: Step 1 — define `InferenceRequestClaim` in `crates/zp-receipt/src/`. Schema is determined by §3 above. No design ambiguity remains.*
