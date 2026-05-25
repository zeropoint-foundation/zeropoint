# Design — Inference Architecture Consolidation

*2026-05-25. Sonnet tier — design only; no implementation.
Follows investigation at `inference-architecture-consolidation-investigation-2026-05.md`.*

---

## Open question decisions

### Q1 — `zp-llm` direction: **route-through (option a)**

`zp-llm` becomes a thin HTTP client of the proxy. `LlmProvider::complete()`
posts to `http://localhost:{zp_port}/api/v1/proxy/{provider}/v1/chat/completions`;
the proxy talks to the upstream provider, emits the signed receipt, returns the
response. The localhost round-trip is sub-millisecond and substrate LLM calls
are low-frequency coordination work — latency is not the constraint.

Option (b) — absorb proxy discipline into `zp-llm` — creates two
receipt-emitting surfaces, two pricing tables, two governance checkpoints.
Same half-state failure the two-reasonable-models heuristic forbids. Reject.

`AnthropicProvider` (`crates/zp-llm/src/providers/anthropic.rs:181`) is the
migration target: it posts directly to `https://api.anthropic.com/v1/messages`
with no receipt, no cost, no policy gate. It becomes deprecated in favor of
`ProxyLlmProvider`. `OllamaProvider` is a local runtime — distinct concern,
allowlisted in the discipline pin, stays unchanged.

### Q2 — Tier definition location: **routing.toml for v0**

The catalog describes *what exists* (provider capability metadata). Routing
config describes *what the operator chooses* (tier → (model, host) assignment).
These are different concerns; mixing them couples operator preference into
infrastructure.

v0: `~/ZeroPoint/config/routing.toml`. Operators swap (model, host) per tier
without code changes; no catalog edit required. A compiled-in default table
ships with the substrate so unconfigured installs work.

v1 target: routing-policy receipts — signed operator acts recorded in the
chain. "I am shifting high-stakes inference from claude-sonnet to qwen3-72b
via Together" is an accountable decision; the audit chain should say so. That's
not v0 scope — the signing ceremony must be low-friction first.

### Q3 — Catalog location: **stays in `zp-engine`**

The structural gap isn't the catalog's crate; it's that pricing lives in
hardcoded Rust match arms in `proxy.rs` instead of catalog TOML. Fixing that
— adding `input_per_million_usd` / `output_per_million_usd` to `ProviderProfile`
and populating the TOML — gives every consumer (proxy, future billing, routing)
a single pricing source of truth. No new crate needed; no dependency graph churn.

A new `zp-providers` crate becomes warranted when there are three or more
independent consumers of catalog data. Right now there are two (proxy + the
new `ProxyLlmProvider`). Hold the line on new crates.

### Q4 — OpenRouter status: **active; needs aggregator field enrichment**

OpenRouter is wired in both proxy.rs (line 55, 89) and the catalog (line 337).
What's missing from the catalog entry: `openai_compatible = true` (OpenRouter
speaks OpenAI protocol natively) and pricing strategy metadata. No resurrection
needed — add the missing fields in the catalog commit.

### Q5 — Aggregator semantics: **opaque at v0**

OpenRouter returns the actual model string (e.g., `"deepseek/deepseek-r1"`) in
responses. ZP carries that string in the receipt's `model` field. Pricing: use
the aggregator's per-model entry in the catalog if present, otherwise the
conservative fallback. The receipt is the accountability surface — downstream
chain queries can reconcile costs by model name even when ZP lacked that
model's rates at write time.

Transparent tracking (ZP maintaining a shadow catalog of all models available
via an aggregator) is v1 scope. The receipt already has everything needed to
support it later: `(host, model, tokens_input, tokens_output)` are all present.

---

## Audit surprises

**Cost receipts are currently inaccurate for ~half the wired providers.**
`estimate_cost_usd` (`proxy.rs:224`) falls back to `($3.00/$15.00 per M tokens)`
for Together, Fireworks, SiliconFlow, Mistral, Perplexity, Cohere, Google.
Together/Fireworks open-weight models run ~$0.20–$0.80 per M tokens — the
fallback overstates by 10–100×. Every receipt for these providers today has
a wrong `cost_usd`. Commit 2 fixes this.

**Abacus.AI is in the catalog but not in the proxy.** Catalog entry exists at
line 214 (`api.abacus.ai/api/v0`) but `provider_base_url` in proxy.rs has no
Abacus entry. Bigger issue: `api.abacus.ai/api/v0` is not OpenAI-compatible;
adding it requires protocol translation, not just a URL entry. Scoped to a
separate task after the consolidation arc ships.

**DeepInfra is absent from both catalog and proxy.** Needs both a catalog entry
and proxy wiring. Added in Commit 3 (OpenAI-compatible; straightforward).

---

## `zp-llm` shape after consolidation

```
crates/zp-llm/src/providers/proxy.rs   ← new
```

```rust
pub struct ProxyLlmProvider {
    zp_port: u16,
    provider_id: ProviderId,      // "anthropic", "together", etc.
    model: String,
    tier: Option<InferenceTier>,  // added in Commit 5
    http: reqwest::Client,
}

impl LlmProvider for ProxyLlmProvider {
    async fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ZpError> {
        // POST to http://localhost:{zp_port}/api/v1/proxy/{provider_id}/v1/chat/completions
        // Deserialize OpenAI-format response
        // Return CompletionResponse; cost_usd available via X-ZP-Cost-USD header
    }
}
```

`CompletionResponse` gains `cost_usd: Option<f64>` (mirrors `zp_receipt::Receipt`
field already present). `pool.rs` is updated to construct `ProxyLlmProvider`
instances instead of direct providers when the proxy port is known.

`AnthropicProvider` is not deleted — it becomes `#[deprecated]` with a doc
comment pointing to `ProxyLlmProvider`. Hard deletion after the discipline pin
passes (Commit 6 confirms no compile-time bypass paths remain).

---

## Consolidated catalog shape

Add to `ProviderProfile` in `crates/zp-engine/src/providers.rs`:

```rust
#[serde(default)]
pub input_per_million_usd: Option<f64>,
#[serde(default)]
pub output_per_million_usd: Option<f64>,
```

Add to `providers-default.toml` for every wired provider. Representative
entries:

```toml
# Anthropic
input_per_million_usd = 3.00
output_per_million_usd = 15.00   # claude-sonnet-4 tier

# Together AI (open-weight bulk tier)
input_per_million_usd = 0.20
output_per_million_usd = 0.80

# Groq
input_per_million_usd = 0.05
output_per_million_usd = 0.10

# OpenRouter (aggregator — conservative fallback; per-model receipt carries model string)
input_per_million_usd = 1.00
output_per_million_usd = 3.00
```

`estimate_cost_usd` in proxy.rs takes `Option<&ProviderProfile>` and reads
`input_per_million_usd` / `output_per_million_usd` from the profile. The Rust
match-arm table is retired. Model-specific overrides (e.g., claude-opus-4 vs.
claude-haiku-4 within the same provider) handled by a separate
`ModelPricingEntry` list on the profile — added as a follow-up once the base
catalog pricing is validated.

---

## Tier-routing design

### `InferenceTier` (new type, lands in `zp-core`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InferenceTier {
    HighStakes,   // ~20% — Claude Sonnet class; reasoning + accountability
    Bulk,         // ~60% — open-weight via US hosts; agent loops, summarization
    Coding,       // ~20% — Kimi K2.6 class; code generation, review
    Local,        // Ollama — offline, privacy-sensitive
    Experimental, // new hosts under evaluation; receipts flagged
}
```

Relationship to existing `ModelClass`: `ModelClass::RequireStrong` maps to
`HighStakes`; `ModelClass::LocalOnly` maps to `Local`; `ModelClass::Any` and
`ModelClass::Strong` route based on tier config. The two enums are not merged
— `ModelClass` is a policy-engine output (risk-driven); `InferenceTier` is an
operator-facing routing label. They compose: policy says `RequireStrong` →
routing resolves `HighStakes` → catalog says `(anthropic, claude-sonnet-4-6)`.

### `~/ZeroPoint/config/routing.toml` format

```toml
[tiers.high_stakes]
provider = "anthropic"
model    = "claude-sonnet-4-6"

[tiers.bulk]
provider = "together"
model    = "meta-llama/Llama-3.3-70B-Instruct-Turbo"

[tiers.coding]
provider = "openrouter"
model    = "moonshot/kimi-k2"

[tiers.local]
provider = "ollama"
model    = "mistral"

[tiers.experimental]
provider = "deepinfra"
model    = "Qwen/Qwen3-72B"
```

Proxy reads this at startup (and on SIGHUP reload). When a request carries a
`X-ZP-Tier` header or the routing config key, the proxy resolves the
`(provider, model)` before forwarding. Requests without a tier use the
explicit `provider` in the URL (current behavior, preserved).

---

## Discipline pin

```
crates/zp-discipline/tests/no_raw_provider_http_outside_canonical_layer.rs
```

```rust
Discipline::new("no_raw_provider_http_outside_canonical_layer")
    .cite_invariant("Singular canonical inference surface — every inference call emits a signed receipt")
    .rationale("Direct HTTP to cloud provider endpoints bypasses the proxy's cost extraction, \
                policy gating, and receipt signing. AnthropicProvider at \
                crates/zp-llm/src/providers/anthropic.rs:181 is the exact bypass this pin closes.")
    // Cloud provider base URLs — all known providers
    .forbid_pattern(r#""https://api.anthropic.com"#)
    .forbid_pattern(r#""https://api.openai.com"#)
    .forbid_pattern(r#""https://api.together.xyz"#)
    .forbid_pattern(r#""https://api.fireworks.ai"#)
    .forbid_pattern(r#""https://api.groq.com"#)
    .forbid_pattern(r#""https://api.deepinfra.com"#)
    .forbid_pattern(r#""https://openrouter.ai"#)
    .forbid_pattern(r#""https://routellm.abacus.ai"#)
    // Canonical layer — the only place permitted to hold provider URLs
    .allow_path("crates/zp-server/src/proxy.rs")
    // Ollama — local runtime, not a cloud provider; separate discipline concern
    .allow_path("crates/zp-llm/src/providers/ollama.rs")
    // Deprecated direct providers pending deletion
    .allow_path("crates/zp-llm/src/providers/anthropic.rs")  // removed after pin passes
    // Skip comment lines and string literal test fixtures
    .skip_lines_containing("//")
    .skip_lines_containing("test")
    .assert();
```

The `anthropic.rs` allowlist entry is a migration bridge: Commit 4 introduces
`ProxyLlmProvider`; Commit 6 adds the pin with the bridge entry; a follow-up
commit deletes `AnthropicProvider` and removes the bridge entry. The pin
prevents any new direct-provider HTTP from being introduced while the migration
completes.

---

## Sequenced commit plan

**Commit 1 — `feat(zp-engine): pricing fields in ProviderProfile + catalog TOML`**

- Add `input_per_million_usd: Option<f64>` and `output_per_million_usd: Option<f64>`
  to `ProviderProfile` in `crates/zp-engine/src/providers.rs`
- Populate `providers-default.toml` for all 12 currently-wired providers
- Add DeepInfra catalog entry while the file is open
- Test: `cargo test -p zp-engine` passes; pricing fields parse correctly

**Commit 2 — `feat(zp-server): catalog-driven cost estimation; retire hardcoded match arms`**

- `estimate_cost_usd` takes `Option<&ProviderProfile>`; reads catalog rates;
  falls back to `(1.00, 4.00)` if profile absent (conservative, not `$3/$15`)
- Load catalog in `AppState` at server init; proxy looks up profile by provider id
- Retire the Rust match-arm table in proxy.rs
- Test: cost estimates for Together / Fireworks now produce correct values;
  existing tests updated for new fallback

**Commit 3 — `feat(zp-server): wire DeepInfra in proxy provider registry`**

- Add DeepInfra to `provider_base_url` (OpenAI-compatible: `https://api.deepinfra.com/v1/openai`)
- Add `allowed_path_prefixes` entry for DeepInfra
- Test: proxy accepts DeepInfra requests without "Unknown provider" error

**Commit 4 — `feat(zp-llm): ProxyLlmProvider — route-through implementation`**

- New `crates/zp-llm/src/providers/proxy.rs` implementing `LlmProvider`
- `#[deprecated]` on `AnthropicProvider` pointing to `ProxyLlmProvider`
- `CompletionResponse` gains `cost_usd: Option<f64>`
- `pool.rs` updated to prefer `ProxyLlmProvider` when proxy port is in config
- Test: `ProxyLlmProvider` with Ollama backend round-trips correctly in unit tests
  (proxy.rs has existing test infrastructure)

**Commit 5 — `feat(zp-server): routing.toml — tier-based inference routing`**

- `InferenceTier` enum added to `zp-core` (alongside `ModelClass`)
- `routing.toml` schema defined and documented in ARCHITECTURE doc
- Proxy reads tier config at startup; `X-ZP-Tier` header accepted
- `CompletionRequest` gains `tier: Option<InferenceTier>`
- Default routing table compiled in (current provider defaults)
- Test: tier-routed request resolves correct `(provider, model)` pair

**Commit 6 — `feat(zp-discipline): no_raw_provider_http_outside_canonical_layer`**

- New discipline pin test
- Runs on current codebase: passes with `anthropic.rs` bridge allowlist
- Test: `cargo test -p zp-discipline` green; CI gate enforced
- Follow-up (separate commit, separate PR): delete `AnthropicProvider`, remove bridge entry

**Commit 7 — `feat(zp-server): wire Abacus RouteLLM in proxy provider registry`**

### Abacus protocol shape

The catalog entry's `base_url` (`https://api.abacus.ai/api/v0`) is the Python
SDK API — not the LLM inference surface. The RouteLLM API lives at a separate
host: `https://routellm.abacus.ai/v1` and speaks OpenAI protocol natively.
`extract_openai_usage` works as-is; `prompt_tokens` / `completion_tokens` are
standard fields.

One quirk: Abacus rejects tool definitions that include `"strict": true` with
HTTP 400. The proxy needs to strip `strict` from any `function` object in the
`tools` array before forwarding to `abacus`. This is the only protocol delta
from the standard OpenAI path.

### Extractor approach

No new extractor needed — `extract_openai_usage` covers Abacus responses.
The Abacus branch in `extract_usage` simply aliases to the OpenAI extractor:

```rust
"abacus" => extract_openai_usage(body),
```

The strict-stripping is a request-side transform, not a response-side concern.
Add a `strip_tool_strict` helper called from `proxy_handler` when
`provider == "abacus"` before the forwarding step.

### Catalog updates

- Correct `base_url` to `https://routellm.abacus.ai/v1` in `providers-default.toml`
- Add `openai_compatible = true`, `aggregator = true`
- Add pricing for initial target (model, host) pairs:

```toml
# Kimi K2.6 thinking via Abacus (coding tier target)
# Pricing: Abacus claims no markup over provider rate; conservative estimate
# based on external host comparison ($0.73–$0.95/M input; using $0.90)
[[providers.abacus.model_pricing]]
model_pattern = "kimi"
input_per_million_usd = 0.90
output_per_million_usd = 3.50

# Catch-all for other Abacus-routed models
input_per_million_usd = 1.00
output_per_million_usd = 4.00
```

Note: Abacus does not publish per-model rates publicly. The estimates above
are derived from external host comparison data (DeepInfra pricing guide,
2026-05). **Ken should confirm or correct these against actual Abacus billing
before the tier goes into production.**

### Proxy registry changes

- `provider_base_url`: `"abacus" => Some("https://routellm.abacus.ai")`
- `allowed_path_prefixes`: `"abacus" => &["v1/chat/completions", "v1/models"]`
- `proxy_handler`: call `strip_tool_strict(body)` before forwarding when
  `provider == "abacus"`

### Routing config

Update the `coding` tier default (set in Commit 5) from OpenRouter to Abacus,
per the strategic memo's recommendation:

```toml
[tiers.coding]
provider = "abacus"
model    = "kimi-2.6-thinking"
```

### Aggregator semantics for Abacus

Same opaque-v0 treatment as OpenRouter: Abacus returns the model name in the
response; the receipt carries it. Per-model cost reconciliation is possible
post-hoc from the chain. Abacus-specific note: RouteLLM may silently re-route
to a different model than requested under load. The receipt's `model` field
comes from the response, not the request — so the chain reflects what actually
ran, not what was asked for. This is correct behavior; operators should be aware
that Abacus's "intelligent" routing strategy can substitute models.

### Open questions for Ken

1. **Model identifier**: Research suggests `"kimi-2.6-thinking"` but Abacus may
   use a different slug (e.g., `"moonshot/kimi-2.6"`, `"kimi-k2-thinking"`).
   Verify via `GET https://routellm.abacus.ai/v1/models` with your API key
   before the commit ships. The routing.toml `model` value must match exactly.

2. **Pricing confirmation**: The `$0.90/$3.50` per M token estimate is from
   external comparison data, not Abacus's own published rate. If Abacus bills
   differently, update the catalog before the coding tier goes live.

3. **`strict` stripping scope**: The Abacus 400-on-strict behavior was observed
   in community reports. If your key has different tool-calling behavior,
   the strip may be unnecessary. Verify with a tool-calling request to Abacus
   before Commit 7 ships.

- Test: proxy accepts Abacus requests; cost receipt populated; tool-calling
  request with `strict: true` forwarded without 400

---

## Migration plan for bypass code

| File | Current behavior | Action |
|------|-----------------|--------|
| `crates/zp-llm/src/providers/anthropic.rs` | Direct HTTP to `api.anthropic.com` | `#[deprecated]` in Commit 4; deleted after Commit 6 pin passes in CI |
| `crates/zp-llm/src/providers/ollama.rs` | Direct HTTP to local Ollama | Allowlisted; local runtime is not a cloud provider; unchanged |
| `crates/zp-server/src/onboard/inference.rs` | Provider detection only | No migration; no LLM calls; not in scope |
| `crates/zp-configure/src/lib.rs` | Vault/key management, provider detection | No migration; no LLM calls; not in scope |
| `crates/zp-server/src/onboard/detect.rs` | Provider detection only | No migration |

**Abacus.AI wiring** is Commit 7. The catalog base URL (`api.abacus.ai/api/v0`)
is the Python SDK surface — the LLM inference API is at `routellm.abacus.ai/v1`
and is OpenAI-compatible. The only protocol delta is stripping `strict` from
tool definitions. See Commit 7 detail above.

---

## Acceptance criteria mapping

The six invariants from the investigation map to commits as follows:

| Invariant | Delivered by |
|-----------|-------------|
| Every inference call emits signed receipt with cost | Commit 4 (substrate) + existing proxy (tool-launched) |
| Operators swap (model, host) per tier via config | Commit 5 |
| New hosts: adapter + catalog entry, not proxy core | Commit 1+2 establish the pattern; Commit 3 validates it |
| Cost queryable by tier / use case / time | Commit 5 (tier in receipt) + existing chain query |
| Discipline pin passes | Commit 6 |
| All strategic memo hosts wired | Commit 3 (DeepInfra); Commit 7 (Abacus + Kimi K2.6) |

---

*Singular canonical surface. Cost in the chain. (model, host) as swappable
infrastructure.*
