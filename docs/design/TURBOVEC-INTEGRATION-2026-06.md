> **Promoted from `docs/handoffs/` on 2026-07-29.** Shipped code cites this document
> as its rationale — `crates/zp-memory-index/src/lib.rs:10` — and `docs/handoffs/` is excluded by `.gitignore`, so the
> code travelled with the repo and the reason for it did not. Promotion test: a handoff
> moves when something shipped cites it. Content unchanged; the handoff original remains
> in place locally. References below to companion *investigation* documents still point
> into `docs/handoffs/` and are still local-only.

**Document type:** Design record, 2026-06. **Status:** `crates/zp-memory-index/` shipped; no consumer wired yet (the `memory:retrieve` gated tool is its named call site).

# TurboVec Integration — Cache-not-canon at the Retrieval Surface

*Dated 2026-06. The first concrete instance of the Cache-not-canon*
*integration pattern (SCC §6, added during the 2026-06 spoke arc).*
*Names what TurboVec adoption looks like under substrate governance:*
*tier composition, gated-tool contract, new receipt classes for the*
*verb set, allowlist-during-search composition with the gate, rebuild*
*protocol, candidate-verification semantics, policy-filtered test path,*
*and the architectural reasoning that makes alpha-status adoption*
*tolerable.*

---

## What this brief is

The TurboVec analysis earlier in this arc established architectural
alignment between TurboVec (a Rust vector index with NEON SIMD,
TurboQuant compressed embeddings, IdMapIndex allowlist filtering, and
online ingestion) and ZeroPoint's substrate. The analysis surfaced
the Cache-not-canon integration pattern as the structural frame for
incorporating alpha-status retrieval components under substrate
governance, and the pattern was captured in SCC §6 alongside the
existing seven integration patterns.

This brief is the operational complement to that capture. It names
how TurboVec adoption composes against the now-complete tier contracts
(11 of 11 SCC spokes landed), what new verb-set claim types the
integration introduces, what the gated tool's affordance partition
looks like, how the gate's policy decision becomes the IdMapIndex
allowlist directly, what triggers index rebuild, and how the substrate's
defense-in-depth makes adopting an alpha-status component a tolerable
architectural decision rather than a substrate-correctness risk.

The brief does not commit the operator to adopting TurboVec. It
specifies what conformant adoption looks like if the operator decides
to proceed.

## TurboVec recap

TurboVec is a Rust vector index with Python bindings. It compresses
embedding vectors using Google Research's TurboQuant approach, then
performs approximate nearest-neighbor search directly over the
compressed representation. Published benchmarks show ~10M float32
vectors compressed from ~31 GB to ~4 GB while outperforming FAISS
FastScan on ARM (~12-20% search-speed advantage on M3 Max).

The features structurally relevant to ZeroPoint:

- **IdMapIndex with allowlist during search.** Stable external uint64
  identifiers; search accepts an allowlist that filters inside the
  SIMD search kernel rather than as a post-filter on results.
- **Online ingestion.** Vectors added are indexed immediately; no
  separate training phase, no periodic rebuild required for routine
  additions.
- **Embedded local index.** Not a managed service; runs in-process or
  as a sidecar, no external network dependencies for the search path
  itself.
- **Native Apple Silicon support.** ARM64 macOS wheel published; hand-
  written NEON SIMD search path.
- **Lossy compression.** TurboQuant is lossy by design; some retrieval
  accuracy is sacrificed for compactness and speed.
- **Alpha status.** PyPI classification is Alpha; May 30 2026 release
  fixed 14 active bugs across the Rust core, Python bindings, and
  LangChain integration. Not yet stable.

## Tier composition

TurboVec composes against multiple SCC tiers, with one primary home
and several boundary compositions.

**Primary: Agent/tool integration tier (SCC tier 6).** TurboVec is
invoked as a gated tool. The substrate's gate evaluates each retrieval
request against the operator's active delegation envelope and policy;
the tool executes only after the gate produces an allow decision; the
tool's invocation produces a chain-anchored receipt triple (intent +
policy + exec).

**Operator substrate Receipt sub-layer.** TurboVec's integration adds
new verb-set claim types (named below); these claims are anchored as
canonical receipts under the operator's identity key on the operator's
chain.

**Operator substrate Verb-set sub-layer.** The new claim types must be
registered in `crates/zp-verbs`'s canonical schema; the
`verbs_must_match_schema` discipline pin enforces that no receipt is
emitted with a claim not in the schema.

**Storage tier.** TurboVec's local index is *not* stored under the
Storage tier's append-only chain semantics — those apply to the
canonical audit chain. The index is derived state, held in whatever
on-disk format TurboVec uses (typically a binary file). The
authoritative records remain in the chain; the index is a projection.

**Cache-not-canon integration pattern (SCC §6).** TurboVec is the
first concrete instance. The pattern's structural properties
(rebuildable from canonical records, replaceable with alternative
implementations, gate-mediated for any operator-facing access,
cache-correctness decoupled from substrate-correctness) all apply.

## New verb-set claim types

The integration introduces three new claims to the canonical verb-set
schema:

1. **`memory:indexed:turbovec`** — the substrate indexed N memory
   records at time T against catalog version C and embedding model E.
   Fields: `index_id` (a chain-anchored identifier for the index
   instance), `record_count`, `catalog_version`, `embedding_model`,
   `embedding_model_version`, `index_hash` (content-addressed hash of
   the index's stable bytes). The receipt is emitted on initial build
   and on every rebuild.

2. **`memory:retrieved:by-agent`** — an agent retrieved memory IDs
   from a query under a policy decision. Fields: `agent_subject_id`,
   `query_hash` (content-addressed hash of the canonicalized query
   embedding plus any literal query text), `allowlist_size` (size of
   the gate-produced allowlist that constrained the search),
   `candidates_returned` (count of IDs returned), `index_id` (which
   index instance served the retrieval), `policy_decision_id` (the
   chain id of the gate's allow decision for this retrieval). The
   receipt is emitted for every retrieval that the gate allows.

3. **`memory:revoked:from-turbovec`** — an operator revoked a specific
   memory ID from the index. Fields: `revoked_memory_id`,
   `revocation_reason`, `chain_revocation_id` (the underlying
   chain-level revocation receipt this propagates from). The receipt is
   emitted when revocation propagates from the canonical chain into the
   index. The index implementation removes the corresponding vector
   from search results.

A fourth claim may be considered, depending on how rebuild is
operationally surfaced:

4. **`memory:index:rebuild:triggered`** — an operational signal that a
   rebuild has begun, naming the trigger (catalog change, embedding
   model change, corruption detected, scheduled). Optional; the
   `memory:indexed:turbovec` receipt emitted at completion covers the
   same accountability surface.

These claims are registered in `crates/zp-verbs` and become part of
the verb-set schema. The `verbs_must_match_schema` discipline pin
ensures no other code path emits claims under these names.

## The gated tool's affordance partition

TurboVec is exposed to agents through a single gated tool —
`memory:retrieve` — whose conformance partition aligns with the
Agent/tool tier contract.

**Required affordances of the retrieval tool:**

- Accept the gate-produced allowlist as a typed parameter. The tool's
  signature requires the allowlist explicitly; agents cannot invoke
  retrieval without one.
- Map TurboVec's opaque uint64 IDs back to chain-anchored memory entry
  IDs in every result. Raw uint64 IDs are not returned to agents;
  every result is a chain-anchored reference.
- Produce a `memory:retrieved:by-agent` receipt on every successful
  invocation, with all the fields named above.
- Honest failure on index unavailability — if the index is being
  rebuilt or has been removed, the tool returns a structured error
  rather than fabricating empty results.

**Optional affordances:**

- Parallel queries across multiple TurboVec indices (e.g., one per
  semantic domain).
- Result re-ranking against canonical entries before returning to the
  agent.
- Caching of recent query embeddings to avoid re-computing them
  within a session.
- Operator-readable surface for index introspection (size, age, hit
  rates) via the cockpit tier.

**Forbidden affordances:**

- Bypassing the gate. The tool cannot be invoked without a current
  gate allow decision; no "fast path" that skips gate evaluation
  exists.
- Treating TurboVec results as authoritative. Results are candidates;
  any decision derived from them must anchor in the canonical chain
  entry referenced, not in the embedding-space proximity score.
- Storing operator-derived material in the index beyond what the
  canonical chain has already anchored. The index is rebuildable
  from the chain; anything in the index that doesn't trace back to
  a chain entry is wrong-shaped.
- Returning results outside the allowlist. The tool's contract
  requires that no result ID falls outside the allowlist; this is
  enforced both by TurboVec's IdMapIndex (which filters during
  search) and by the tool's output validation (defense-in-depth).
- Persisting query embeddings outside the gate's session scope.
  Embeddings of operator queries may carry sensitive information;
  long-term retention without explicit operator authorization is
  forbidden.

## The allowlist-during-search composition

The structural fit between ZeroPoint's gate and TurboVec's IdMapIndex
is the architectural insight that makes the integration interesting
beyond "fast vector search."

The gate's policy evaluation already produces an authorization decision
per request: which memory IDs is this agent authorized to see, under
its current delegation envelope, for this query, at this time? The
gate's decision can be encoded directly as the allowlist parameter to
TurboVec's search:

```
agent invokes memory:retrieve(query, k=20)
    ↓
gate evaluates: authorize agent A to retrieve memory under delegation D for query Q?
    ↓
gate produces:
    - allow decision (chain-anchored receipt)
    - allowlist of authorized memory IDs (parameter to tool)
    ↓
tool invokes turbovec.search(query_embedding, k=20, allowlist=authorized_ids)
    ↓
turbovec filters during SIMD search kernel — only authorized IDs enter result space
    ↓
results: (memory_id, score) pairs, all within allowlist
    ↓
tool maps memory_ids to chain-anchored entry references
    ↓
tool emits memory:retrieved:by-agent receipt
    ↓
results returned to agent
```

The structural property: unauthorized memories never enter the
result space, because the filter is inside the search kernel rather
than applied after retrieval. Post-filter shims are where leak bugs
live (the result set is computed, then narrowed; if the narrowing logic
has a bug, unauthorized results leak); the kernel-level filter has no
window for that class of bug.

## The rebuild protocol

The index is rebuilt from canonical chain records under specific
triggers; rebuild is the structural mechanism that keeps the cache
honest to the chain.

**Triggers that mandate rebuild:**

1. **Catalog version change.** The substrate's catalog grammar version
   has advanced; the receipt schema may have changed; embedding logic
   that depends on receipt structure may behave differently.
2. **Embedding model change.** The model that produced the indexed
   embeddings has changed. Embedding-space proximity from the old
   model is not comparable to embedding-space proximity from the new
   model.
3. **Index corruption detected.** Storage-layer corruption, partial
   write, or bit rot detected via the TurboVec implementation's own
   integrity check or via mismatch between a chain entry's expected
   embedding and the index's stored embedding.
4. **Revocation backlog exceeds threshold.** When many revocations
   have accumulated, a full rebuild may be cheaper than incremental
   removal.

**Optional triggers (operator policy):**

5. **Scheduled maintenance window.** Operator may choose to rebuild
   periodically as operational hygiene.
6. **After a chain epoch boundary.** If the substrate adopts epoch
   compaction, rebuild may align with epoch transitions.

**The rebuild process:**

1. Read canonical chain entries that constitute the substrate's
   indexable memory (per the operator's configured policy for what's
   indexable — not every chain entry is necessarily indexed).
2. Generate embeddings against the current embedding model for each
   indexable entry.
3. Build a fresh TurboVec index with `add()` calls for each entry.
4. Compute the new index's content-addressed hash.
5. Emit a `memory:indexed:turbovec` chain receipt attesting the new
   index instance: count, catalog version, embedding model version,
   index hash.
6. Atomically swap the active index reference to the new index. The
   old index file may be retained for one cycle for rollback or
   deleted immediately depending on operator policy.

The swap is atomic — concurrent retrievals do not observe a partial
rebuild; they see either the old index or the new index, never a
mixed state.

## Lossy compression and candidate verification

TurboQuant is lossy by design. Compressed retrieval may surface results
in a different rank order than full-precision retrieval would, or may
miss results that an exact-search system would have returned, or may
return false-positive results that exact search would have excluded.

This is architecturally tolerable under the substrate's structural
commitments. The propose-not-sign integration pattern (SCC §6) is
exactly the right frame at the retrieval surface: TurboVec proposes
candidates at scale (cheap, compressed, approximate); any decision
derived from those candidates anchors in canonical chain content (the
agent acts on what the chain says, not on what the embedding score
suggests).

The substrate's worst case from a lossy index is degraded retrieval
quality — the agent sees worse candidates than it might have under
exact search. The substrate's worst case is *not* corruption of
authority. The agent cannot act on a hallucinated memory entry,
because the chain-anchored entry reference would fail verification
when the agent tries to use it. The agent cannot bypass policy on the
basis of a wrong candidate, because the gate already filtered for
policy before TurboVec saw the query.

## The policy-filtered retrieval test path

The empirical test that exercises the substrate-specific structural
fit — distinct from generic recall/latency benchmarks — is the
policy-filtered retrieval path:

1. **Setup.** Operator-controlled substrate with one agent identity,
   one delegation grant, and a configured policy that limits the
   agent to a specific subset of memory IDs (e.g., "agent A may
   retrieve memories tagged as project-X for the next 24 hours").
2. **Drive.** Agent invokes `memory:retrieve(query, k=20)`.
3. **Observe.**
   - Gate produces a chain-anchored receipt naming the allowed
     subset.
   - Tool emits `memory:retrieved:by-agent` chain receipt naming the
     allowlist size and candidates returned count.
   - All returned IDs fall within the policy-defined subset.
4. **Inject failures.**
   - Bypass the gate (call TurboVec directly, bypassing the tool's
     allowlist parameter) — should fail or be structurally
     impossible if the implementation is correct.
   - Inject a TurboVec result outside the allowlist (simulating a
     compression-induced false positive that maps to an
     unauthorized ID) — the tool's output validation must catch
     and reject this.
   - Set the agent's delegation to expired between the gate's allow
     decision and the tool's invocation — the second invocation must
     not succeed.

The injection tests exercise the substrate's defense-in-depth: each
boundary (gate evaluation → tool invocation → output validation)
independently enforces the policy, so a bug in any one layer does
not cascade to authorization failure.

## Alpha-status posture

The substrate's defense-in-depth makes alpha-status adoption tolerable
in a way it would not be for a non-substrate stack. If TurboVec has
bugs that produce incorrect rankings, spurious results, or even
crashes:

- The chain remains authoritative. No TurboVec result is treated as
  authoritative without chain-canonical verification.
- The gate still enforces policy. No retrieval bypasses gate
  evaluation, regardless of TurboVec's correctness.
- The allowlist still filters. Unauthorized memories never enter
  result space, even if TurboVec's ranking is wrong.
- The retrieval is replayable. The `memory:retrieved:by-agent`
  receipt captures query hash, allowlist size, candidates returned;
  if a decision later proves wrong, the retrieval can be analyzed.

The worst case is degraded retrieval quality (agent sees worse
candidates). The not-worst-case is substrate corruption (agent acts
on false authority). The substrate-readiness commitment that the
chain is the source of truth, combined with Cache-not-canon's
structural decoupling of cache correctness from substrate
correctness, is what makes this tolerable.

## Composition with principles

The TurboVec integration composes with several principles in ways
the existing tier contracts already structurally enforce — this brief
just names how the integration honors them:

- **P1 (signing is gravity).** Every retrieval produces a signed
  chain receipt; the index build produces a signed receipt; the
  agent's decision based on retrieval results produces signed
  receipts. The cache itself is unsigned (it's derived state); but
  every consequential operation involving the cache is signed.

- **P3 (no center).** The index is the operator's; TurboVec is not
  a central retrieval service. Multiple operators each have their
  own index over their own chains. No central registry of memory.

- **P4 (every bit counts).** Every indexed memory traces to a
  canonical chain entry; no implicit memories live in the index
  alone.

- **P5 (store-and-forward primary).** The chain survives index
  unavailability; the index can be rebuilt from chain at any time.

- **P8 (one canonical path).** The retrieval path is canonical:
  gate → allowlist → search → mapping → receipt. No side path.

## Composition with the Cache-not-canon pattern

This integration is the first concrete instance of Cache-not-canon
from SCC §6, and several of the pattern's structural properties show
up directly:

- **The chain is the source of truth.** Canonical memory entries
  live on the chain; TurboVec holds embeddings derived from them.
- **The cache is rebuildable.** Any rebuild trigger reads the chain
  and produces a fresh index.
- **The cache is replaceable.** A future migration to a different
  vector index (different compression scheme, exact search, etc.)
  is a swap behind the same `memory:retrieve` tool interface.
- **The cache is gate-mediated.** No operator-facing access bypasses
  the gate's policy decision.
- **Cache correctness ≠ substrate correctness.** A misbehaving
  TurboVec produces degraded performance or stale projections,
  not corrupted authority.

If the empirical work surfaces a property that doesn't fit the
pattern as named in SCC §6, that's a signal to revise the pattern's
naming or to introduce a sub-pattern. For now, TurboVec maps cleanly.

## Implementation outline

The substrate-side work breaks into five pieces:

1. **Verb-set schema additions.** Register the three (or four) new
   claim types in `crates/zp-verbs`. Add round-trip tests per the
   schema's existing testing discipline.

2. **TurboVec integration crate.** A new `crates/zp-memory-index`
   (or equivalent) that wraps TurboVec's Rust API behind a substrate-
   shaped interface. Trait abstraction so that future alternative
   implementations (exact search, different compression, etc.) can
   conform without rewriting the consumer.

3. **The `memory:retrieve` tool.** Implemented in the agent/tool
   integration crate, exposed through the substrate's tool registry.
   Required affordance enforcement at the tool boundary; gate
   composition wiring.

4. **Index lifecycle management.** Code that handles initial build,
   triggered rebuilds, revocation propagation, and atomic swap.
   Composes with the chain-walk path that produces indexable
   entries.

5. **Operator surface.** `zp memory index` CLI subcommand for index
   introspection (size, age, hit rates, last rebuild reason). the Regent
   tool equivalent. Cockpit-tier surface for visibility.

The discipline-pin work composes naturally: a pin like
`turbovec_calls_only_through_gated_tool` would enforce that no code
path invokes TurboVec's search API outside the gated tool's
implementation. This prevents future "small optimization" temptations
from creating side paths that bypass the gate.

## Open questions

Three minor questions worth surfacing for operational consideration,
none blocking the brief's architectural posture:

1. **Embedding model selection and lock-in.** The integration assumes
   the operator selects an embedding model at index-build time. Model
   selection has implications (lock-in, recall characteristics,
   privacy if model is cloud-hosted). The brief does not prescribe a
   specific model; it names that model selection is an operator
   decision recorded in the `memory:indexed:turbovec` receipt.

2. **Index granularity per agent vs shared.** Should each agent have
   its own index (filtered to the memories that agent's delegation
   could ever authorize) or should there be one substrate-wide index
   (with allowlist filtering at query time)? My read is shared with
   per-query allowlist filtering, because (a) it matches how
   TurboVec's IdMapIndex is designed, (b) it avoids per-agent rebuild
   complexity, (c) the gate's allowlist already provides the
   filtering. But operationally there may be reasons (privacy
   isolation, performance under high-cardinality agent populations)
   to prefer per-agent indices. Operator decision; not blocking.

3. **MMR limitation.** TurboVec's LangChain integration cannot
   faithfully implement maximum marginal relevance because full-
   precision vectors are discarded after encoding. If the substrate's
   retrieval use case depends on MMR-style diversification, this is a
   functional gap; if it doesn't, this is a non-issue. The brief
   notes the gap without prescribing.

## Refs

- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` §6 — the
  Cache-not-canon integration pattern this brief is the first
  concrete instance of
- `docs/AGENT-TOOL-CONTRACT-2026-06.md` — the tier contract that
  governs the `memory:retrieve` gated tool's affordance partition
- `docs/OPERATOR-SUBSTRATE-CONTRACT-2026-06.md` — Receipt and
  Verb-set sub-layers (new claim types register here); Surface
  sub-layer (operator surface exposes the index)
- `docs/STORAGE-TIER-CONTRACT-2026-06.md` — the chain that hosts the
  canonical memory entries the index projects from; the index itself
  is *not* under Storage tier semantics
- `docs/VERIFIER-TIER-CONTRACT-2026-06.md` — verifier may
  cross-check `memory:retrieved:by-agent` receipts against the
  canonical entries they reference
- `docs/handoffs/discipline-pin-audit-2026-06.md` — adjacent
  structural enforcement context; a
  `turbovec_calls_only_through_gated_tool` pin candidate composes
  with the existing set
- `docs/handoffs/receipt-lifecycle-2026-06.md` — the central-tier
  lifecycle this integration extends with new claim types
- `docs/ARCHITECTURE-2026-04.md` — Principles 1, 3, 4, 5, 8 are the
  structural justifications
- TurboVec repository — `github.com/RyanCodrai/turbovec` (the
  upstream component; alpha-status as of May 30, 2026)
- `crates/zp-verbs` — verb-set schema registration site
- `crates/zp-policy`, `crates/zp-gate-envelope` — gate composition
  surface for allowlist production
