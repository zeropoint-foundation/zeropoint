# Investigation — Inference architecture consolidation

*2026-05-25. Sonnet tier — substrate-level architectural design work.
Mechanical audit + design synthesis; the architectural-judgment work
to set up the five open questions has already been done in the
originating session. Must land before the ZP Surface Spec design
begins. Triggered by a strategic-stack re-evaluation: intelligence is
becoming a commodity input, the competitive moat moves from "best
model" to workflow / taste / distribution, and the substrate must
treat (model, host) as swappable infrastructure. ZP's current
inference layer can't host that stance because it has three parallel
paths with only one of them carrying the cost-tracking discipline.
This is the singular-X pattern at the inference layer.*

## What triggered this

A 2026-05-25 strategic-stack memo (`AI_Stack_Strategic_Memo_2026.docx`,
companion `AI_Stack_Comparison_2026.xlsx`, deck
`AI_Stack_Strategy_2026.pptx`) re-frames the AI provider landscape:

- Chinese-origin frontier models now perform within 2.7% of US frontier
  on LMArena, at 10–40× lower price (open-weight artifacts).
- **Open weights are files, not services.** Model origin and hosting
  location are orthogonal. The right unit of analysis is `(model, host)`,
  not "the provider."
- Three named risk categories — lives with the model, lives with the
  host, lives with the vendor — each handled by different mitigations.
- Recommended tiered split: ~20% Claude Sonnet for high-stakes, ~60%
  open-weight Chinese models via US hosts (Together / Fireworks /
  DeepInfra / Abacus.AI) for bulk and agent loops, ~20% Kimi K2.6 via
  US host for coding. Modeled savings ~65%, ~$6K/year on a moderate
  workload.
- Strategic frame: "treat the (model, host) layer as swappable
  infrastructure, build for portability, and capture the surplus."

Ken's directive: ensure ZP is the right shape to **evolve openly** —
multi-provider, multi-model, cost-transparent, swap-friendly, with
adopters in mind, not just the foundation.

This investigation maps the gap between that requirement and the
substrate's current inference architecture.

## Current state (audit findings)

Three parallel inference paths exist. Only one of them has the discipline
the architecture actually needs:

| Path | Location | Cost tracked? | Multi-provider? | Used by |
|---|---|---|---|---|
| **Proxy** | `zp-server/src/proxy.rs` | **Yes** — UsageMetrics extractor + signed receipts with `cost_usd` | 12 hosts: openai, anthropic, groq, mistral, together, deepseek, fireworks, perplexity, cohere, google, openrouter, siliconflow | Tools that point `*_BASE_URL` at ZP (PentAGI, OpenMAIC, others) |
| **`zp-llm` direct** | `crates/zp-llm/src/` | **No** — `Usage` has token counts, no cost | 2: Anthropic + Ollama only | Substrate code that calls LLMs directly |
| **`zp-engine` catalog** | `crates/zp-engine/src/providers.rs` | N/A (metadata only) | All catalog entries | Provider detection, discovery, env-var → provider-id mapping |

**Receipts already carry cost.** `zp-receipt::types.rs` has
`cost_usd: Option<f64>` as a first-class field. The chain can record
inference cost; the proxy path uses it; the direct path does not.

**ProviderProfile catalog already has the right richness.** The
`ProviderProfile` struct in `zp-engine` carries `capabilities`,
`openai_compatible`, `openai_proxy`, `aggregator`, `routing` strategy
("intelligent" vs "explicit"). This metadata model *is* the (model, host)
split — it recognizes aggregators (OpenRouter, Abacus) as a distinct
shape, and openai-protocol-compatibility as a host trait. But the
catalog doesn't enforce routing or feed into the proxy's pricing /
cost extraction.

**The structural problem:** singular-X pattern at the inference layer.
There IS a structurally-right path (the proxy, which already does
signing + cost + policy + multi-provider). Parallel paths (zp-llm
direct integrations) bypass it. No discipline pin forces consolidation.
Same architectural shape as the singular-sovereign-root and
singular-loopback-binding problems we've already addressed at other
layers.

## The principle being applied

**Singular canonical inference surface.** One path for all inference;
signing + cost tracking + policy gating happen on that path; everything
else routes through it.

Composes with established substrate principles:

- **Signing is gravity** — every inference call produces a signed
  receipt with cost. Cost claims that don't trace to receipts are
  decorative.
- **Identity is a key, not a location** — provider identity is data
  in the catalog, not hardcoded into call sites. (model, host) is a
  lookup against catalog metadata.
- **Every bit counts** — three parallel inference paths is the
  duplicate-data-path the principle catches.
- **Store-and-forward is primary** — cost receipts persist in the
  chain; queryable later for budget, optimization, attribution.

## Target architecture (proposed shape)

1. **Designate `zp-server/src/proxy.rs` as the canonical inference
   surface.** It already has the discipline. Everything else routes
   through it.

2. **`zp-llm` becomes a thin substrate-side client of the proxy.**
   `LlmProvider` trait stays as the Rust-shaped interface for substrate
   code that needs to call LLMs; its implementation routes HTTP through
   the proxy. The Anthropic and Ollama direct-integration providers
   either move under the proxy as registered backends, or become
   deprecated.

3. **Consolidate `ProviderProfile` catalog into the canonical layer.**
   The metadata richness (capabilities, openai_compatible, aggregator,
   pricing rates, residency, ToS) feeds the proxy's cost extraction
   and policy decisions. Single source of truth for "what (model, host)
   pairs exist and what are their properties."

4. **Tier-based routing as architecture.** First-class concept of
   tiers (high-stakes / bulk / coding / experimental per the strategic
   memo). Routing policy declares which (model, host) pairs serve
   each tier. Operators swap (model, host) for a tier without code
   changes. The policy lives in the catalog or in a separate routing
   config; the proxy consumes it.

5. **Discipline pin.** `no_raw_provider_http_outside_canonical_layer`
   — build-time test forbidding raw HTTP calls to known provider
   endpoints outside the proxy module. Same shape as
   `no_raw_tcp_bind_outside_zp_net` and the other boundary pins.
   Forces all inference through the receipt-emitting layer so cost
   tracking is structurally guaranteed.

6. **Host coverage extension.** Add hosts the strategic memo
   recommends that aren't yet wired: Abacus.AI (for Kimi K2.6),
   DeepInfra (for GLM-4.6), AWS Bedrock if it fits operator needs.
   Each is a registered backend in the proxy with cost-extraction
   logic and capability metadata.

7. **Pricing as live capability metadata.** Each (model, host) entry
   in the catalog carries input/output rates per million tokens. The
   proxy multiplies usage × rates to populate `cost_usd` in receipts.
   Pricing can be static config initially; fetched from host APIs
   later where available.

## Investigation surface

For CLIC (or whoever executes this) to confirm the audit before
patching:

```sh
# The three paths
sed -n '1,80p' crates/zp-server/src/proxy.rs       # canonical path
sed -n '1,80p' crates/zp-llm/src/provider.rs       # direct path
sed -n '1,80p' crates/zp-engine/src/providers.rs   # catalog

# Cost field in receipts
grep -n 'cost_usd\|tokens_output\|tokens_input' crates/zp-receipt/src/types.rs

# All provider integrations in the workspace
grep -rln 'OpenAI\|Gemini\|Abacus\|OpenRouter\|Together\|Fireworks\|DeepInfra' \
  --include='*.rs' crates/ | grep -v target

# Existing UsageMetrics extractors
grep -n 'extract_.*_usage\|UsageMetrics' crates/zp-server/src/proxy.rs

# Tier or routing config that already exists
grep -rn 'ModelPreference\|ModelClass\|tier\|routing' \
  crates/zp-core/ crates/zp-llm/ crates/zp-engine/ | head -20
```

## Open questions

Surface in the design doc as questions, not guesses:

1. **`zp-llm` direction: route-through vs. absorb.** Two reasonable
   shapes:
   - (a) `zp-llm` becomes a thin client of the proxy. Substrate code
     calls `LlmProvider::complete()`, which HTTP-posts to the proxy,
     which talks to the upstream provider, returns the response.
     Adds a localhost round-trip but preserves the proxy as the
     singular cost-tracking point.
   - (b) `zp-llm` absorbs the proxy's discipline directly. Substrate
     code calls `LlmProvider`, which talks to upstream providers and
     emits receipts itself. The proxy becomes a thin HTTP wrapper
     around `zp-llm` for tool-launch URL-swap cases.
   
   Trade-offs: (a) is structurally cleaner (one process, one path);
   (b) is faster (no localhost hop). Pick one explicitly per the
   two-reasonable-models heuristic — half-state breaks here.

2. **Tier definition location.** Tier policy can live in:
   - The provider catalog (each (model, host) declares which tiers it
     serves)
   - A separate routing config (`routing.toml` declaring tier → (model,
     host) preference)
   - The chain itself (signed routing-policy receipts; tier changes
     are operator-signed acts)
   
   Recommend the chain-anchored option once the work is mature; start
   with catalog or config for v0.

3. **Catalog source of truth.** Currently `zp-engine/src/providers.rs`
   loads from embedded TOML + user overrides. After consolidation,
   does the catalog live in:
   - `crates/zp-llm` (alongside the trait)
   - A new crate (`zp-providers` or `zp-catalog`)
   - Stays in `zp-engine` (consolidate elsewhere into it)
   
   Catalog-as-its-own-crate is probably right since multiple consumers
   (proxy, zp-llm client, observation/billing) need it.

4. **OpenRouter status.** Ken noted uncertainty about whether
   OpenRouter is still wired. Verify: is it in the current catalog?
   In the proxy's known-provider list? Used by any current substrate
   code? Resurrect or formally deprecate.

5. **Aggregator semantics.** The catalog already marks aggregators
   (OpenRouter, Abacus). Does an aggregator's (model, host) pair
   resolve transparently (catalog knows the underlying model and
   tracks pricing for it) or opaquely (catalog treats aggregator as a
   leaf with its own pricing)? Trade-offs around cost predictability
   vs. operational simplicity.

## Deliverable

A design doc at:

```
docs/handoffs/inference-architecture-consolidation-design-2026-05.md
```

Containing:

1. The decision on each open question (1–5) with rationale.
2. The chosen `zp-llm` shape (route-through vs. absorb) with
   implementation outline.
3. The consolidated catalog shape (crate location, metadata fields
   including pricing).
4. Tier-routing design (where policy lives, how operators swap).
5. The discipline pin's exact pattern (which paths forbidden, which
   allowlisted — probes, tests, etc.).
6. Sequenced commit plan (4–6 commits, each independently testable).
7. Migration plan for existing substrate code that bypasses the
   proxy today.

Do NOT execute implementation as part of this investigation. Design
the consolidation; Ken reviews; implementation happens in subsequent
commits.

## Acceptance criteria (eventually, for the consolidated state)

These are the invariants the implementation arc will need to satisfy.
Not the design's scope, but listed so the design knows what it's
building toward:

1. Every inference call in the substrate emits a signed receipt with
   `tokens_input`, `tokens_output`, `cost_usd`, `(model, host)`,
   latency.
2. Operators can swap (model, host) for any tier via configuration
   without code changes anywhere in the substrate.
3. New hosts can be added by writing a host adapter + catalog entry,
   not by touching the proxy core or zp-llm core.
4. Cost can be aggregated by tier, by use case, by time period — chain
   queries return spend data.
5. Discipline pin passes: no raw provider HTTP outside the canonical
   layer.
6. All hosts in the strategic memo's recommended set are wired
   (Anthropic, OpenAI, Google, Together, Fireworks, DeepInfra, Groq,
   Abacus.AI, OpenRouter at minimum).

## Out of scope (for this investigation)

- **The ZP Surface Spec design** — waits for this work to land,
  because the spec's cost / tier semantics depend on the canonical
  inference shape.
- **ZP Console reference implementation** — also waits.
- **The artifact library storage decision** — separate but adjacent.
- **The foundation Console migration to `app.*`** — entirely separate
  arc.
- **Vault / API-key handling specifics** — the canonical layer reads
  keys from the vault using existing primitives; not redesigned here.
- **Local-only / Ollama specifics beyond confirming they continue to
  work** — local inference stays available; the consolidation must
  not break it.
- **Cost optimization features** (caching, prompt deduplication,
  budget alerts) — these become trivial once the canonical surface
  exists, but they're follow-up work.

## Refs

- `AI_Stack_Strategic_Memo_2026.docx` — the triggering strategic
  context
- `AI_Stack_Comparison_2026.xlsx` — the (model, host) economic
  comparison
- `crates/zp-server/src/proxy.rs` — the canonical surface today
- `crates/zp-llm/src/provider.rs` — the direct-integration trait
- `crates/zp-engine/src/providers.rs` — the metadata catalog
- `crates/zp-receipt/src/types.rs` — cost_usd field already in
  receipts
- `docs/SURFACE-BOUNDARIES-2026-05.md` — substrate boundary
  architecture; this work strengthens the substrate side of that
  boundary
- `docs/handoffs/singular-loopback-binding-design-2026-05.md` — the
  pattern this investigation follows (singular-X consolidation)
- `docs/handoffs/singular-sovereign-root-audit-2026-05.md` — earlier
  instance of the same pattern

---

*Singular canonical surface for inference. Cost in the chain. (model,
host) as swappable infrastructure. Substrate stays calm; adopters
evolve openly.*
