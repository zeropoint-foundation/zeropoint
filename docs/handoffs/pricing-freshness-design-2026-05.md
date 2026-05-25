# Design — Pricing freshness as a substrate primitive

*2026-05-25. Sonnet tier — substrate-layer design work. Follows the
inference-architecture consolidation arc (ec71de7, 2026-05-25). Does
not execute implementation; Ken reviews, implementation follows.*

## Open question decisions

### Q1 — Receipt schema extension shape

**Decision: `extensions` HashMap with key `"zp.pricing.refresh_receipt_id"`.**

`Receipt` already carries `extensions: Option<HashMap<String, serde_json::Value>>`
for exactly this use case — it is the established ZP pattern for domain-specific
metadata on execution receipts (same shape as `zp.port.lifecycle.bound_stacks`).
Adding a core field to `Receipt` would pollute the type for every non-proxy receipt.
A new `ClaimMetadata` variant is for claim-type receipts; execution receipts (what
the proxy emits) use extensions. Chain queries can filter on extension key presence —
queryability concern does not change the answer.

Each proxy execution receipt will carry:

```json
"extensions": {
  "zp.pricing.refresh_receipt_id": "pric-abc123",
  "zp.pricing.source": "fetch",
  "zp.pricing.age_days": 3
}
```

`age_days` is precomputed at call time and stored on the receipt so chain walk
queries ("receipts that used pricing older than 7 days") never need to recompute it.

### Q2 — Manual attestation flow

**Decision: `zp pricing attest [--host=NAME]` CLI subcommand.**

Operator-initiated keeps the signing model singular-sovereign-root-clean. A
pre-commit hook fires in a process, not a signed operator ceremony — the key that
signs the attestation receipt must be the one the operator authenticated at process
start. A startup watcher is silent (no explicit operator intent). The CLI subcommand
is the one path where the operator consciously asserts "I reviewed this TOML entry
and attest its accuracy." Emits a `PricingRefreshClaim` receipt with
`PricingSource::Manual` and the attested host(s).

### Q3 — TOML persistence semantics

**Decision: Overwrite.**

The chain already holds the full history via `PricingRefreshClaim` receipts. TOML
comments would create a second history that can drift from the receipts, violating
*every bit counts* (no duplicate data paths). Overwrite is correct — the chain
IS the history; the TOML is the current-state config file.

### Q4 — Fetcher placement

**Decision: `crates/zp-engine/src/pricing.rs` (new file).**

Catalog-adjacent: new host = new fetcher + catalog entry, same crate. The proxy is
already large; adding HTTP fetchers there grows the wrong surface. A `zp-pricing`
crate would be premature abstraction for 1-2 initial fetchers. `zp-engine` owns
the catalog; fetchers that update the catalog live alongside it.

### Q5 — Staleness threshold configuration location

**Decision: `routing.toml` with a `[pricing]` section.**

Tier policy and pricing staleness policy are both operator choices about how
providers are used — same file, same reasoning. Per-host fields in the catalog
would conflate catalog facts (what the provider is) with operator policy (how stale
is tolerable). Separate `pricing-config.toml` would fragment operator config files
with no benefit.

```toml
# ~/ZeroPoint/config/routing.toml (new section)
[pricing]
default_stale_days = 30

[pricing.host_stale_days]
anthropic = 14
openai = 14
google = 14
abacus = 14
# open-weight hosts inherit default (30)
```

Compiled-in defaults match the investigation brief's proposed thresholds.

### Q6 — Initial verification timestamp backfill

**Decision: Stamp existing entries with `pricing_verified_at = "2026-05-25"` and
`pricing_source = "manual"` in the migration commit.**

Commit-1's careful TOML population (the consolidation arc) was a manual attestation
— rates were researched and deliberately written. Stamping `2026-05-25` treats it as
the manual attestation it was, which is more honest than `Unknown`. Auto-fetch on
startup contradicts "substrate provides verbs; consumers schedule." Leaving as
`Unknown` wastes the work already done.

---

## Final field definitions — `ProviderProfile` extension

```rust
// In crates/zp-engine/src/providers.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingSource {
    /// Fetched from the provider's API; pricing_verified_at is the fetch time.
    #[serde(rename = "fetch")]
    Fetch { source_url: String },
    /// Manually attested via `zp pricing attest`; pricing_verified_at is
    /// the attestation timestamp.
    #[serde(rename = "manual")]
    Manual,
    /// Not yet verified — using initial seed or catalog default.
    #[serde(rename = "unknown")]
    Unknown,
}

impl Default for PricingSource {
    fn default() -> Self { PricingSource::Unknown }
}

// New fields appended to ProviderProfile:
/// When this entry's pricing was last verified (fetch or manual attestation).
#[serde(default, skip_serializing_if = "Option::is_none")]
pub pricing_verified_at: Option<DateTime<Utc>>,

/// How pricing for this entry is kept current.
#[serde(default)]
pub pricing_source: PricingSource,

/// Optional cached-token input rate (Anthropic prompt cache, Abacus cached tokens).
#[serde(default, skip_serializing_if = "Option::is_none")]
pub cached_input_per_million_usd: Option<f64>,
```

TOML representation (per-provider):

```toml
pricing_verified_at = "2026-05-25T00:00:00Z"
pricing_source = "manual"
```

For fetch-sourced entries after first refresh:

```toml
pricing_source = { fetch = { source_url = "https://routellm.abacus.ai/v1/models" } }
pricing_verified_at = "2026-05-25T18:34:00Z"
```

---

## Receipt schema — `PricingRefreshClaim`

New `ReceiptType` variant (prefix `"pric"`):

```rust
// In crates/zp-receipt/src/types.rs

// ReceiptType enum — add:
/// Records a pricing refresh (fetch or manual attestation) for one or more hosts.
PricingRefreshClaim,

// id_prefix arm:
ReceiptType::PricingRefreshClaim => "pric",

// ClaimMetadata enum — add:
PricingRefresh {
    /// Host IDs refreshed (e.g., ["abacus", "anthropic"])
    host_ids: Vec<String>,
    /// How pricing was updated: "fetch" | "manual"
    method: String,
    /// Source URL(s) fetched (empty for manual attestations)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    source_urls: Vec<String>,
    /// Count of entries whose rates changed
    changed_count: u32,
    /// Count of entries that matched existing rates
    unchanged_count: u32,
    /// Human-readable delta summary (e.g., "abacus/kimi-k2.6: $0.90→$0.85 input")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    delta_lines: Vec<String>,
},
```

`zp pricing attest` emits a `PricingRefreshClaim` with `method = "manual"`.
`zp pricing refresh` (fetch path) emits the same type with `method = "fetch"` and
`source_urls` populated.

---

## Fetcher trait and initial implementations

```rust
// crates/zp-engine/src/pricing.rs

use async_trait::async_trait;
use zp_core::ZpError;

pub struct PricingUpdate {
    /// Which catalog entry this applies to (provider_id, e.g. "abacus")
    pub provider_id: String,
    /// Model-level override (None = updates host-level defaults)
    pub model_id: Option<String>,
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
    pub cached_input_per_million_usd: Option<f64>,
}

#[async_trait]
pub trait PricingFetcher: Send + Sync {
    fn host_id(&self) -> &str;
    fn source_url(&self) -> &str;
    async fn fetch(&self, api_key: &str) -> Result<Vec<PricingUpdate>, ZpError>;
}

/// Registry: returns the fetcher for a given host_id, or None if manual-only.
pub fn fetcher_for(host_id: &str) -> Option<Box<dyn PricingFetcher>> {
    match host_id {
        "abacus" => Some(Box::new(AbacusFetcher)),
        // Future: openai, anthropic, together, etc. as their APIs expose pricing
        _ => None,
    }
}

// ── Abacus fetcher ──────────────────────────────────────────────────────────

struct AbacusFetcher;

#[async_trait]
impl PricingFetcher for AbacusFetcher {
    fn host_id(&self) -> &str { "abacus" }
    fn source_url(&self) -> &str { "https://routellm.abacus.ai/v1/models" }

    async fn fetch(&self, api_key: &str) -> Result<Vec<PricingUpdate>, ZpError> {
        let client = reqwest::Client::new();
        let resp = client
            .get(self.source_url())
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| ZpError::ProviderError {
                provider: "abacus".into(),
                message: format!("Pricing fetch failed: {}", e),
            })?;

        // Parse OpenAI /v1/models response; extract pricing sub-object
        // Fields: data[].id, data[].pricing.input_token_rate,
        //         data[].pricing.output_token_rate,
        //         data[].pricing.cached_input_token_rate (optional)
        // Rates are in USD per token; multiply by 1_000_000 for per-million.
        // ... parse and return Vec<PricingUpdate>
        todo!("parse response per Abacus /v1/models schema")
    }
}
```

**Note on Abacus field names:** The investigation brief lists
`input_token_rate` / `output_token_rate` / `cached_input_token_rate`. These must
be verified against a live `GET routellm.abacus.ai/v1/models` before implementation
(open question from the consolidation arc). The fetcher implementation is a single
file, so the field name is easy to correct in the implementation commit.

---

## Sequenced commit plan

### Commit 1 — ProviderProfile pricing provenance fields + TOML backfill

Files: `crates/zp-engine/src/providers.rs`, `crates/zp-server/assets/providers-default.toml`

- Add `PricingSource` enum
- Add three new fields to `ProviderProfile` with `#[serde(default)]`
- Backfill all 13 current TOML entries: `pricing_source = "manual"`,
  `pricing_verified_at = "2026-05-25T00:00:00Z"`
- Add `pricing_age_days(now: DateTime<Utc>) -> Option<u64>` helper to `ProviderProfile`

No breaking changes — all new fields have defaults.

### Commit 2 — New receipt types + routing.toml staleness config

Files: `crates/zp-receipt/src/types.rs`, `crates/zp-server/src/routing.rs`

- Add `ReceiptType::PricingRefreshClaim` with prefix `"pric"`
- Add `ClaimMetadata::PricingRefresh { ... }` variant
- Extend `RoutingFile` with optional `pricing` section and `PricingConfig` struct
- Extend `get_routing_config()` to parse new section; provide compiled-in defaults
  matching the staleness table from the investigation brief

### Commit 3 — Fetcher trait + Abacus impl

Files: `crates/zp-engine/src/pricing.rs` (new), `crates/zp-engine/src/lib.rs`

- `PricingUpdate` struct
- `PricingFetcher` trait
- `AbacusFetcher` impl (pending live API field name verification)
- `fetcher_for()` registry
- `pub async fn refresh_hosts(hosts: &[&str], ...) -> Result<PricingRefreshResult, ZpError>`
  (internal function, called by CLI and HTTP handler)
- `PricingRefreshResult`: changed count, unchanged count, delta lines, source URLs

### Commit 4 — CLI + HTTP capability

Files: `crates/zp-cli/src/commands.rs`, `crates/zp-server/src/routes.rs` (or
wherever HTTP routes live)

- `zp pricing refresh [--host=NAME]` CLI command
  - Loads API key from vault for the target host
  - Calls `refresh_hosts()`
  - Emits signed `PricingRefreshClaim` receipt
  - Reports delta to stdout
- `zp pricing attest [--host=NAME]` CLI command
  - Emits signed `PricingRefreshClaim` with `method = "manual"` for current TOML values
- `POST /api/v1/pricing/refresh` HTTP handler
  - GovernanceGate gated, signed envelope required
  - Same internal path as CLI

Catalog cache (`PROVIDER_CATALOG: OnceLock`) needs invalidation after refresh.
Replace `OnceLock` with `RwLock<Vec<ProviderProfile>>` in `proxy.rs` so the
refresh path can write a new snapshot without process restart.

### Commit 5 — Cost receipt provenance + staleness warnings

Files: `crates/zp-server/src/proxy.rs`

- Cache `most_recent_refresh_receipt_id_for(host: &str)` at startup
  (query audit chain for latest `PricingRefreshClaim` per host)
- On each proxy request, extend the execution receipt:
  ```rust
  receipt.extensions = Some(HashMap::from([
      ("zp.pricing.refresh_receipt_id".into(), json!(refresh_rcpt_id)),
      ("zp.pricing.source".into(), json!(source_str)),
      ("zp.pricing.age_days".into(), json!(age_days)),
  ]));
  ```
- If `age_days > stale_threshold_for(host, &routing_config)`, emit an additional
  `ObservationClaim` receipt:
  ```
  observation_type = "pricing:stale-applied"
  tags = ["pricing", "staleness"]
  detail: { host, age_days, threshold_days, refresh_receipt_id }
  ```
  This receipt links to the execution receipt via `parent_receipt_id`.

---

## Migration plan

1. **Commit 1 ships** — TOML gains `pricing_source` and `pricing_verified_at` on all
   existing entries. Existing deserializers handle missing fields via `#[serde(default)]`.
   No runtime change needed; nothing reads the new fields yet.

2. **Commits 2–4 ship** — CLI and HTTP capability available. Operators can now invoke
   `zp pricing refresh --host=abacus` manually. Foundation deployment adds
   `zp pricing refresh` to IronClaw scheduled tasks (daily). First successful fetch
   writes new `pricing_source = { fetch = ... }` and `pricing_verified_at` to TOML.

3. **Commit 5 ships** — Cost receipts gain provenance extensions. Staleness warnings
   begin emitting. Receipts emitted before Commit 5 have no provenance extension —
   this is acceptable; the chain walk use case ("find cost receipts with stale pricing")
   applies to receipts from this point forward.

4. **`OnceLock` → `RwLock` migration** (part of Commit 4) — `PROVIDER_CATALOG` and
   `ROUTING_CONFIG` in `proxy.rs` change from `OnceLock<T>` to
   `std::sync::RwLock<T>` with a `get_or_init`-equivalent pattern. The `RwLock` is
   taken read-locked on every request (no contention on the hot path) and
   write-locked only during refresh (rare). This is the only non-additive change in
   the arc.

---

## Test plan

### Unit tests

- `test_pricing_source_serde` — round-trip `PricingSource::Fetch { source_url }` and
  `Manual` through TOML and JSON
- `test_provider_profile_missing_fields_backward_compat` — deserialize a TOML entry
  without the new fields; confirm `pricing_source == Unknown`, `pricing_verified_at == None`
- `test_pricing_age_days` — `pricing_age_days(now)` returns correct integer for a
  known `pricing_verified_at`
- `test_abacus_fetcher_parse` — feed a fixture JSON (captured from live API) through
  `AbacusFetcher::fetch`; verify `PricingUpdate` fields match expected rates
- `test_staleness_threshold_routing_toml` — parse a `routing.toml` with a `[pricing]`
  section; verify per-host and default thresholds parse correctly

### Integration tests

- `test_refresh_updates_catalog_and_emits_receipt` — mock Abacus `/v1/models`
  endpoint returning a known rate; call `refresh_hosts(&["abacus"])`; verify catalog
  entry updated, `PricingRefreshClaim` receipt emitted with correct delta lines
- `test_attest_emits_manual_receipt` — call `zp pricing attest --host=anthropic`;
  verify `PricingRefreshClaim` with `method = "manual"` in chain
- `test_proxy_receipt_carries_provenance` — after a known refresh receipt is in the
  chain, make a proxy request; verify execution receipt extensions contain
  `zp.pricing.refresh_receipt_id` matching the refresh receipt

### Chain-provenance query test

```rust
#[test]
fn test_pricing_provenance_chain_walk() {
    // 1. Seed chain with a PricingRefreshClaim for "abacus" at T=0
    // 2. Emit 3 proxy execution receipts at T+1, T+2, T+3 with
    //    extensions["zp.pricing.refresh_receipt_id"] = refresh_rcpt.id
    // 3. Emit another PricingRefreshClaim at T+10
    // 4. Emit 2 more proxy receipts linked to new refresh
    // 5. Walk chain: filter execution receipts by
    //    extensions["zp.pricing.refresh_receipt_id"] == first_refresh_id
    // 6. Assert exactly 3 receipts found; assert age_days in extensions
    //    for each matches expected values
}
```

This test validates the end-to-end claim from the investigation brief:
"show me all cost receipts in the last 30 days that used pricing older than 7 days."

### Discipline pin

No changes needed to `no_raw_provider_http_outside_canonical_layer` — fetchers live
in `zp-engine`, which is a new allowable surface for non-cloud-provider HTTP. The
discipline pin's allowlist covers `zp-server/src/proxy.rs` as the lone cloud-provider
call site; `zp-engine/src/pricing.rs` calls the same provider base URLs but only for
pricing metadata (not completions). Consider whether a new discipline test is needed:
`no_pricing_fetch_outside_engine_crate` — low priority; the fetcher registry design
already constrains call sites by construction.

---

## What surprised me in the audit

**Test harness still has hardcoded rates.** Lines 865–920 of `proxy.rs` (the unit
test block) still have hardcoded `estimate_cost_usd(2.50, 10.00, ...)` etc. These
were the live code arms before Commit 5 of the consolidation arc retired them. The
test block wasn't updated — it's now testing the function signature against stale
fixture inputs rather than the catalog-driven path. These should be replaced with
catalog-driven test fixtures in the same pass as Commit 5 of this arc, or as a
cleanup commit against the consolidation arc.

**`OnceLock` is the wrong primitive for a writable cache.** The consolidation arc
correctly used `OnceLock` for process-lifetime-constant catalogs, but the pricing
refresh arc requires invalidation after a refresh. The migration to `RwLock`
(Commit 4) is a consequence of making pricing mutable at runtime — not a design
mistake in the consolidation arc, which had no refresh capability yet.

---

*Substrate provides verbs; consumers schedule. Pricing freshness becomes auditable,
queryable, attributable. Cost receipts gain provenance. The chain stays truthful
about what it knew when.*
