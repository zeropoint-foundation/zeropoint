# Investigation — Pricing freshness as a substrate primitive

*2026-05-25. Sonnet tier — substrate-layer design work. Architectural
shape already roughed out in the originating session; this
investigation pins the details, decides the open questions, and
sequences implementation. Follows the inference-architecture
consolidation arc (commits landed 2026-05-25); not blocking on
anything else.*

## What triggered this

The inference-architecture consolidation arc (7 commits, 2026-05-25)
fixed the static accuracy of pricing data — Together / Fireworks /
SiliconFlow / Mistral / Perplexity / Cohere / Google rates went from a
fallback of $3/$15 per million (10-100× overstated for most) to
catalog-driven actuals.

What that arc did NOT fix: **freshness**. Pricing now lives in
`crates/zp-engine/providers-default.toml`, hand-maintained, with no
staleness signal, no fetch mechanism, no provenance trail. Two
implications:

1. **The catalog goes stale.** Provider rates change on weeks-to-
   months (GPT-5.5 doubled April 2026; Zhipu +30% February 2026;
   open-weight host rates drift with GPU costs). By autumn the
   catalog could be substantially drifted, and nothing in the
   substrate would alarm.

2. **Cost receipts inherit silent inaccuracy.** Receipts capture
   `cost_usd` as computed at call time, but don't record which
   pricing version produced it. An operator querying the chain for
   historical cost analysis has no way to tell which receipts were
   priced against accurate-at-the-time vs. stale data.

The Abacus discovery during the consolidation arc made this concrete:
Abacus's `/v1/models` endpoint returns live pricing for every model it
offers. The substrate didn't read it; CLIC manually populated TOML
values. That's the gap — provider APIs increasingly expose pricing as
data; the substrate should consume it.

## The principle being applied

**Substrate provides verbs; consumers schedule.** Pricing refresh is a
substrate capability (a signed, auditable action). Scheduling, cadence,
and triggering are cockpit / operator / adopter concerns — not
substrate.

This is the same shape as the surface-boundary architecture: substrate
exposes capabilities, cockpits/Console wrap them in UX, the adoption
kit can demonstrate one reference scheduling pattern (e.g., daily cron
via IronClaw's scheduled-tasks system) without committing the
substrate to opinions about cadence.

Composes with:

- **Signing is gravity.** Each refresh action emits a signed receipt
  with delta summary. Cost receipts link back to the refresh receipt
  that produced their rate — provenance chain.
- **Identity is a key, not a location.** Refresh is a capability,
  exposed via CLI and HTTP; not bound to one trigger mechanism.
- **Store-and-forward is primary.** Refresh receipts persist in the
  chain. Operators can query "what did pricing look like on date X?"
  by walking historical refresh receipts.

## Target architecture

### 1. The refresh capability

Substrate exposes a single capability through two surfaces:

```
zp pricing refresh [--host=NAME]              # CLI
POST /api/v1/pricing/refresh                   # HTTP, gated by GovernanceGate
```

Both invoke the same internal code path. The capability:

- Iterates over hosts in the catalog (or one named host if filtered)
- For each host with a known fetcher, calls the fetcher to retrieve
  current pricing
- Compares against catalog values, computes deltas
- Updates the catalog (in-memory immediately; persists to TOML on
  successful completion)
- Emits a signed receipt with the refresh action, source URLs, delta
  summary, count of changed entries

### 2. Per-host fetcher pattern

Each host that exposes pricing via API gets a fetcher. Initial set
based on what's verified-discoverable:

- **Abacus** — `routellm.abacus.ai/v1/models` returns `input_token_rate`
  / `output_token_rate` / `cached_input_token_rate` per model
- **OpenAI** — `api.openai.com/v1/models` (verify whether pricing is
  exposed; if not, manual TOML fallback)
- **Anthropic** — model list endpoint; verify pricing exposure
- **Together / Fireworks / DeepInfra / Groq** — verify per-host

Hosts that don't expose pricing via API stay manual-TOML with explicit
attestation (see field #3 below).

### 3. `ProviderProfile` field additions

Three new fields:

```rust
pub struct ProviderProfile {
    // ... existing fields ...

    /// When this entry's pricing was last verified, by manual edit or
    /// successful fetch.
    pub pricing_verified_at: Option<DateTime<Utc>>,

    /// How pricing for this entry is kept current.
    /// Values: "fetch", "manual", "unknown"
    pub pricing_source: PricingSource,

    /// Optional cached input rate (newer provider feature).
    pub cached_input_per_million_usd: Option<f64>,
}

pub enum PricingSource {
    /// Fetched from a host API; pricing_verified_at is the fetch time.
    Fetch { source_url: String },
    /// Manually attested in TOML; pricing_verified_at is the edit
    /// timestamp.
    Manual,
    /// Not yet verified — using catalog default or initial seed.
    Unknown,
}
```

### 4. Cost-receipt provenance chain

Each cost receipt gains a `pricing_refresh_receipt_id` field linking
to the refresh receipt that produced the rate it used. If a cost
receipt uses pricing tagged `PricingSource::Manual`, the field
references the manual attestation receipt instead.

Query: "show me all cost receipts in the last 30 days that used
pricing older than 7 days at call time" becomes a chain walk.

### 5. Staleness warnings

When a cost is computed against pricing older than a threshold N, the
proxy emits a `pricing:stale-applied` warning receipt alongside the
cost receipt. Threshold is configurable per host (frontier providers
get a tighter threshold than open-weight hosts).

Defaults to propose:

| Host class | Stale threshold |
|---|---|
| US frontier (OpenAI, Anthropic, Google) | 14 days |
| Aggregators (Abacus, OpenRouter) | 14 days |
| Open-weight hosts (Together, Fireworks, DeepInfra, Groq) | 30 days |
| Local (Ollama) | N/A (no cost) |

Operators override per-host via config.

### 6. Scheduling (out of substrate)

Substrate does NOT include a scheduler. The capability is exposed; the
trigger is the consumer's call.

Foundation deployment reference pattern: IronClaw's scheduled-tasks
system invokes `zp pricing refresh` daily. Adopters using a different
cockpit run their own equivalent. Adopters with no cockpit can use OS
cron, launchd, or manual operator invocation.

## Investigation surface

For CLIC to confirm before patching:

```sh
# Existing catalog and pricing path
sed -n '1,80p' crates/zp-engine/src/providers.rs
sed -n '1,80p' crates/zp-engine/providers-default.toml

# Where cost is currently computed
grep -n 'estimate_cost_usd\|cost_usd' crates/zp-server/src/proxy.rs

# Existing receipt types
grep -n 'cost_usd\|tokens_input\|tokens_output\|parent_receipt' \
  crates/zp-receipt/src/types.rs

# Verify Abacus pricing endpoint behavior
curl -s -H "Authorization: Bearer $ABACUS_KEY" \
  https://routellm.abacus.ai/v1/models | jq '.data[] | select(.id=="kimi-k2.6")'

# Whether OpenAI / Anthropic expose pricing via API today (2026-05)
curl -s -H "Authorization: Bearer $OPENAI_KEY" \
  https://api.openai.com/v1/models | jq '.data[0]'
```

## Open questions

Resolve in the design doc; do not guess in implementation:

1. **Receipt schema extension shape.** Does `pricing_refresh_receipt_id`
   become a new field on `ReceiptCore`, or live in a typed receipt
   extension (similar to `zp.port.lifecycle.bound_stacks` per the
   PortRegistry pattern)? Extension is more flexible; field is more
   queryable. Pick one explicitly.

2. **Manual attestation flow.** When an operator edits the TOML by
   hand, what generates the manual-attestation receipt? Options:
   - A pre-commit hook that detects pricing changes
   - A `zp pricing attest` CLI subcommand the operator runs explicitly
   - The substrate watches the TOML for changes on startup and emits
     attestation receipts
   
   Recommend explicit CLI subcommand — operator-initiated keeps the
   signing model singular-sovereign-root-clean.

3. **TOML persistence semantics.** When a fetch updates pricing, does
   it overwrite the TOML or annotate it with new values + previous
   values as comments? Overwrite is simpler; annotation preserves
   history (which the chain already does via receipts, so probably
   not needed).

4. **Fetcher placement.** Where do per-host fetchers live? Options:
   - Inside the proxy module (closest to where they're used)
   - In `zp-engine/src/providers/` alongside the catalog
   - Their own crate (`zp-pricing`)
   
   The catalog-adjacent option is probably right — fetcher and
   catalog are tightly coupled; new host = new fetcher + catalog entry.

5. **Staleness threshold configuration location.** Lives in:
   - The catalog itself (per-host field)
   - A separate `pricing-config.toml`
   - Routing.toml (since it's operator-facing)
   
   Recommend `routing.toml` — same place as tier policy, both are
   operator choices over what providers do.

6. **Initial verification timestamp backfill.** All current entries
   have no `pricing_verified_at`. On first run after the migration,
   does the substrate:
   - Stamp everything with the current time (treating Commit-1's
     TOML population as the initial attestation)
   - Leave them `None` and treat as `Unknown` source until first
     refresh
   - Run a "verify on startup" pass that fetches what it can
   
   Recommend stamp-with-current-time-as-manual on migration; treat
   Commit-1's careful population as the manual attestation it was.

## Deliverable

Design doc at:

```
docs/handoffs/pricing-freshness-design-2026-05.md
```

Containing:

1. Decisions on the six open questions, with rationale
2. Final field definitions for `ProviderProfile` extension
3. Receipt schema decisions (extension vs. core field)
4. Fetcher trait definition and the initial host implementations
5. Sequenced commit plan (probably 4-5 commits: field additions →
   fetcher trait + Abacus impl → CLI/HTTP capability → cost-receipt
   provenance link → staleness warnings)
6. Migration plan for existing catalog entries
7. Test plan, including a chain-query test that walks pricing-
   provenance

Do NOT execute implementation. Design only; Ken reviews; implementation
in follow-up commits.

## Acceptance criteria (eventual implementation)

What the eventual implementation arc must satisfy:

1. `zp pricing refresh` works for any host with a fetcher; emits a
   signed receipt with delta summary
2. `zp pricing refresh --host=abacus` works for a single host
3. `POST /api/v1/pricing/refresh` exposes the same capability,
   gated by GovernanceGate, signed envelope required
4. Cost receipts carry a link to the refresh receipt that produced
   their rate
5. Cost calls against stale pricing emit a `pricing:stale-applied`
   warning receipt with the staleness in days
6. Manual TOML edits can be attested via `zp pricing attest` (or
   chosen mechanism) and the attestation is chain-anchored
7. New host can be added by writing a fetcher + catalog entry
   (when the host's API exposes pricing) OR just a catalog entry
   (when it doesn't, with `PricingSource::Manual`)
8. `cargo test -p zp-discipline` continues to pass

## Out of scope

- **Auto-refresh on substrate startup.** Substrate doesn't make
  decisions about when to refresh; consumers do. (A consumer might
  invoke refresh on its own startup, but that's the consumer's
  choice.)
- **Pricing prediction or forecasting.** The chain records actuals;
  forecasting is consumer-side analysis.
- **Cross-host arbitrage hints.** Suggesting "switch from host A to
  host B for this workload because B is cheaper" is a cockpit-level
  optimization, not substrate.
- **Image / video / audio pricing models.** Those use non-token rate
  structures (credits, per-second, per-megapixel) and don't fit the
  current input/output token framework. Out of scope until ZP adds
  those modalities.
- **API key management for fetchers.** Fetchers use the existing
  vault primitives for the host's API key. Not redesigned here.

## Refs

- `docs/handoffs/inference-architecture-consolidation-design-2026-05.md`
  — the arc this builds on
- `docs/handoffs/inference-architecture-consolidation-investigation-2026-05.md`
  — the investigation that surfaced the freshness gap
- `docs/SURFACE-BOUNDARIES-2026-05.md` — substrate vs. cockpit
  boundaries; this work strengthens the substrate-side trust quality
- `AI_Stack_Strategic_Memo_2026.docx` — the original triggering
  context; describes pricing drift cadences in section 5
- `crates/zp-engine/providers-default.toml` — current catalog
- `crates/zp-server/src/proxy.rs` — where cost is computed today

---

*Substrate provides verbs; consumers schedule. Pricing freshness
becomes auditable, queryable, attributable. Cost receipts gain
provenance. The chain stays truthful about what it knew when.*
