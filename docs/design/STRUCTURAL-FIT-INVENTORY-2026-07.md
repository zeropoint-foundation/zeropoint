# Structural Fit Inventory

**Document type:** Investigation. **Not** a Tier 2 canonical elaboration — it elaborates no KEEL section. It audits correspondence between what the corpus claims and what the substrate's *representations* supply, which places it in *Investigations and programs* alongside `SPEC-IMPLEMENTATION-COHERENCE-INVESTIGATION-2026-07.md`. That document runs code-to-spec on behaviour; this one runs it on data structures.

**Date:** 2026-07-27.

**Motivation:** Several substrate invariants are data-structure properties stated as prose. Where the structure supplies the property, the invariant holds under adversarial and concurrent conditions for free. Where it does not, the invariant is aspiration maintained by vigilance, and vigilance is the thing that lapses. Nothing in the corpus currently pairs a structure with the claim made over it, so the question of which case each one is in has never been asked in one place.

**Source:** Prompted by a 28-minute survey of fourteen data structures (`docs/mindmaps/data-structures-shape-is-the-trade-2026-07.json`), whose spine is that every structure buys one property and pays for it at a named place. The framing — that the substrate should be shaped by best fit rather than by naive assertion — is Ken's. Every row below was verified by direct read of `crates/` on 2026-07-27; where a claim could not be verified, the row says so.

**Composes with:** `SPEC-IMPLEMENTATION-COHERENCE-INVESTIGATION-2026-07.md` (same code-to-spec direction, aimed at behaviour rather than representation; its §2 records the failed-search method this document avoided), `CONNECTION-INTEGRITY-PROGRAM-2026-07.md` (its conditions for an unrealized connection — SF-2 is a C2 instance at type granularity, and the detector gap it exposes is noted in §Findings), `AUTHORING-DISCIPLINE-2026-07.md` (A11 is the discipline this document exists to apply to representations), `EXTERNAL-ANCHOR-TIER-CONTRACT-2026-06.md` (the compact-commitment discipline whose property the epoch Merkle tree already supplies), `MULTI-DEVICE-OPERATION-2026-07.md` (the causal-ordering claim examined in SF-3), `CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md` (peer verification, the consumer an inclusion proof would serve).

---

## Framing

**1. There are four states, not two, and conflating them is what makes this hard to see.** "Does the structure supply the property" sounds binary. In practice the substrate exhibits four distinct conditions, and each calls for a different response:

- **Structural** — the type or the compiler makes violation impossible. Nothing to do.
- **Convention** — the property holds because one call site maintains it. A second call site is all it takes.
- **Absent** — the structure cannot supply the claimed property at all. The claim is aspiration.
- **Present but unconsumed** — the structure supplies it and nothing calls the code. This is `CONNECTION-INTEGRITY-PROGRAM`'s C2 (*built, not wired*) observed at type granularity rather than at feature granularity, and it is the cheapest state to fix.

**2. The fourth state produced the finding this investigation did not expect.** The most interesting row below is not a gap. `crates/zp-receipt/src/epoch.rs` contains a complete Merkle implementation — `MerkleTree`, `MerkleProof`, `ProofStep`, `Direction`, and a `verify()` on the proof — and `compute_merkle_root` is genuinely production-wired through `zp-server/src/anchor_pipeline.rs` for epoch sealing. But `MerkleProof` appears in exactly two files: its own module and the `lib.rs` re-export. No CLI path, no server path, and no peer path ever constructs or checks an inclusion proof. The capability is built, tested, and unused.

**3. This must be scoped or it becomes an audit nobody finishes.** `ZP_OWNED_VARS` being a linear-scanned array is correct and uninteresting. The inventory covers **structures over which the corpus makes a claim**. If no document depends on the representation's properties, it is out of scope by construction, and that exclusion is the reason this document is finishable.

---

## Method

Four columns. Structure, the claim the corpus makes over it, whether the representation supplies that property, and — where it does not — the canonical alternative that would.

The direction is code-to-spec, per A11 and per `SPEC-IMPLEMENTATION-COHERENCE-INVESTIGATION` §2's record of why spec-to-code searching is unsound here. Every row was verified by reading the type in `crates/` first and the claim second. Rows are stated as *verified present*, *verified absent*, or *could not determine*; there are no inferred rows.

---

## The inventory

| # | Structure | Claim made over it | Supplied? | Canonical alternative |
|---|---|---|---|---|
| **SF-1** | Audit chain: `prev_hash` / `entry_hash` on `AuditEntry` (`zp-core/src/audit.rs:29`) | Tamper-evidence; *"peer-verifiable by hash equality"* | **Structural** for tamper-evidence. Hash chain gives O(n) verification and no compact membership proof | — for tamper-evidence |
| **SF-2** | Epoch Merkle tree (`zp-receipt/src/epoch.rs:25-482`), root computed in `zp-server/src/anchor_pipeline.rs` | Anchor tier §3: only a compact commitment crosses the boundary, never chain content | **Present but unconsumed.** `MerkleProof`/`ProofStep`/`Direction` with `verify()` exist and are tested; no consumer outside the module. Roots are used; proofs are not | Wire `MerkleProof` into peer verification — the structure is already there |
| **SF-3** | Multi-device sync ordering | `MULTI-DEVICE-OPERATION` §5.4: *"causal ordering and merge receipts"* | **Absent.** No implementing code found: no vector clock, version vector, or Lamport structure anywhere in `crates/`. The design itself compares chain-tip hash plus *timestamp* | Vector clocks or dotted version vectors. Timestamps cannot supply causality |
| **SF-4** | `NodeRegistry` heartbeat sequence (`zp-mesh/src/node_registry.rs`) | §III.19 detectability — silence must be observable | **Structural.** Strict `seq` monotonicity rejects regression (`SequenceRegression`), which makes a *gap* observable rather than inferable | — this is the worked example; see below |
| **SF-5** | `GrantedCapability::contains` (`zp-core/src/capability_grant.rs:1047`) | Delegation narrowing — a child grant never exceeds its parent | **Convention.** Hand-written `match` per enum-variant pair dispatching to `scope_contains`/`set_contains`. No `PartialOrd`, no subsumption trait. **`Custom` compares name only and ignores parameters** | Meet-semilattice with a `subsumes` relation; per-variant logic becomes the lattice's meet |
| **SF-6** | `DelegationChain` (`zp-core/src/delegation_chain.rs:18`) | *"Once constructed via `verify()`, the chain is guaranteed to satisfy all delegation invariants"* — eight of them | **Structural.** Private fields, constructible only through the verifying constructor. This is the pattern working | — |
| **SF-7** | `AuditStore` constructors (`zp-audit/src/store.rs:113`) | *"there is no path by which a production writer can construct an unsigned store"* | **Structural.** `open_unsigned` is `cfg(test)`-gated inside the crate, feature-gated outside. Compiler-enforced | — |
| **SF-8** | `Receipt::signatures: Vec<SignatureBlock>` (`zp-receipt/src/types.rs:435`) | *"callers MUST keep signatures sorted by `(algorithm, key_id)` … so the entry hash is deterministic"* | **Convention.** `Signer::sign` preserves it; the `Vec` enforces nothing. Any other push breaks hash determinism silently | A newtype with a sorted-insert constructor, or a `BTreeSet` keyed on the ordering tuple |
| **SF-9** | `DiscoveryManager::recent_nonces` — `HashMap<(hash, source), VecDeque<(String, DateTime)>>` (`zp-mesh/src/discovery.rs`) | Anti-replay on announce intake | **Convention, and unbounded.** No cap on `peer_records`, no per-poll ceiling; TTL pruning must be called externally | Bloom or cuckoo filter: bounded memory, tunable false-positive rate, and a wrong-yes is the safe direction for replay rejection |
| **SF-10** | `PeerReputation` per-category `Vec`, `MAX_EVENTS_PER_CATEGORY = 100` FIFO (`zp-mesh/src/reputation.rs`) | Time-decayed reputation with a 30-day half-life | **Absent, subtly.** FIFO eviction drops the oldest event *of a category* regardless of weight, biasing the decay the score is meant to model | Exponentially-decayed counters: no eviction, no growth, decay is the representation rather than a post-hoc computation |
| **SF-11** | `SkillMatcher::match_request` (`zp-skills/src/matcher.rs:30`) | Skill relevance matching; lens `keyword_composition` triggering shares the shape | **Absent.** Triple-nested linear scan doing **bidirectional** substring containment — `keyword.contains(token) \|\| token.contains(keyword)`. Self-labelled *"Phase 1"* | Inverted index or Aho-Corasick. Note the bidirectional `contains` also makes short tokens match nearly everything |
| **SF-12** | Ontology graph (Cartographer) | `ONTOLOGY-AND-CARTOGRAPHER`; officers query it; Regent composes from it | **Absent.** No crate, no node or edge type, no schema. Four comments in `crates/` name it as deferred | Deferred by design — recorded here so the absence is visible in one place |
| **SF-13** | `MemoryIndex` trait + `TurboVecIndex` (`zp-memory-index/src/lib.rs:46`) | Swappable backend behind a stable trait | **Structural** for swappability — this is the pattern the corpus already praises. Search algorithm lives in the external `turbovec` crate; quantized at 2 or 4 bits | **Could not determine** whether the backing search is structured or brute-force over quantized vectors — the crate is not vendored |
| **SF-14** | `GossipFinding` (`zp-gossip/src/finding.rs:18`) | *"Contains zero operator-specific data by construction"* | **Structural in shape** — the struct has no identity fields to leak. Not runtime-checked; the guarantee is exactly "there is no field for it" | — |

---

## The worked example: SF-4

Worth stating explicitly, because it is the shape the other rows should be judged against.

§III.19 requires that silence be detectable — that the substrate distinguish *nothing happened* from *something was lost*. That is a hard property to maintain by vigilance, because the failure is an absence and absences do not raise events.

`NodeRegistry::verify_and_record` enforces strict sequence monotonicity: a heartbeat whose `seq` is less than or equal to the last recorded value is rejected with `SequenceRegression`. The consequence is that a *gap* in the sequence is directly observable — a receiver holding `seq=7` and then seeing `seq=9` knows something is missing, without any protocol for asking.

Nobody has to remember to check. The representation makes the invariant a consequence of reading, and that is the entire difference between a structural property and a convention. Where a row below is marked *Convention*, the question to ask is: what would make this a consequence of reading rather than a thing someone maintains?

---

## Findings

**The Merkle result inverts the expected finding.** Going in, the working hypothesis was that the chain is a hash chain and therefore cannot supply compact membership proofs — the property the anchor tier's compact-commitment discipline and the peer contract's verification story both want. The hypothesis was wrong in the most useful way: the structure exists, is complete, is tested, and is production-wired for epoch sealing. What is missing is a *consumer*. `MerkleProof` is referenced in its own module and the re-export, nowhere else.

This is `CONNECTION-INTEGRITY-PROGRAM` C2 — *"An implementation exists and no path reaches it."* An earlier draft of this document claimed it was a shape that program does not enumerate; that was wrong, and the correction is recorded rather than silently applied. What C2 does not yet have is an instrument at this granularity: its detector is `granted_tools_must_be_reachable`, which covers Regent tools, and the program's own text notes *"Nothing generalizes it."* The general form — *every implemented public type has at least one non-test consumer* — is mechanically checkable and would have surfaced `MerkleProof` without anyone asking.

**Two claims use words their representations do not earn.** "Causal ordering" (SF-3) names a property that requires vector clocks or version vectors; the design compares timestamps, and no implementation exists at all. "Time-decayed" (SF-10) describes a computation applied over a window whose eviction policy quietly biases it. In both cases the prose is doing work the structure does not do, which is precisely the naive-assertion pattern this inventory was built to surface.

**One narrowing hole is concrete rather than theoretical.** `GrantedCapability::contains` returns `pn == cn` for the `Custom` variant — matching on name and ignoring parameters entirely. A child `Custom` grant with the same name and broader parameters passes the subset check. Whether that is reachable depends on how `Custom` is issued, which this investigation did not trace; it is recorded as SF-A below rather than asserted as a vulnerability.

**The successes share one property.** SF-4, SF-6 and SF-7 all make the invariant a consequence of construction or reading: monotonic sequence, verify-then-construct with private fields, `cfg(test)`-gated constructor. None of them relies on a caller remembering. That is the template.

---

## Verifiable outcomes (SF)

- **SF-O1** — Every row in the inventory carries a state of *structural*, *convention*, *absent*, or *present-but-unconsumed*, with a file:line for the representation.
- **SF-O2** — No row is stated from inference. Rows that could not be verified say so and name what would settle them.
- **SF-O3** — Each *convention* row names what would make it structural.
- **SF-O4** — Each *absent* row names the canonical alternative and the property it would supply, or records that the absence is deliberate.
- **SF-O5** — A claim in any corpus document that depends on a representation's property links to its row here, so the dependency is traversable in both directions.
- **SF-O6** — A detector exists for C2 at type granularity: every implemented public type has at least one non-test consumer, or is annotated as deliberately ahead of its consumer.
- **SF-O7** — The inventory is re-run when a structure carrying a claim changes, not on a schedule.

---

## Minimum slice

**m0: wire one `MerkleProof` consumer.**

It adds no new structure, no new dependency and no new concept. The tree, the proof type, the `verify()` and the tests already exist; `compute_merkle_root` is already called in production. The slice is to have peer verification request and check an inclusion proof for a single receipt rather than walking the chain — which is the property the anchor tier's confidentiality discipline was reaching for and the peer contract's verification story needs.

What makes it the right first slice is that it is the only row where the expensive part is already paid. Every other *absent* row requires building a structure; this one requires calling one.

The natural second slice is SF-8, since a sorted-insert newtype around `Vec<SignatureBlock>` is perhaps thirty lines and converts a hash-determinism invariant from a single-call-site convention into a type property.

---

## Alternatives considered (tie-offs)

- **Audit every structure in `crates/`.** *Disposition: rejected.* Most representations carry no claim, and an unscoped audit does not finish. Reopens only if a defect is traced to a structure the scoping rule excluded.
- **Replace the hash chain with a Merkle log outright.** *Disposition: rejected — the premise was wrong.* Both layers already exist and serve different purposes: `prev_hash` for append-order tamper-evidence, epoch Merkle roots for compact commitment. The gap was a consumer, not a structure.
- **Introduce a lattice abstraction for capabilities now (SF-5).** *Disposition: deferred behind evidence.* The imperative `match` is legible and works for the current nine variants. The argument for a lattice strengthens with variant count and with composition depth. Reopens if a tenth variant lands or if a narrowing defect is found in the wild — the `Custom` parameter hole may already be that trigger.
- **Fix SF-11's matcher as part of this investigation.** *Disposition: rejected — wrong document.* It is self-labelled Phase 1 and its replacement is a design decision about semantic matching, not a structural-fit finding. Recorded here, decided elsewhere.

---

## Open positions

- **SF-A — Is the `Custom` narrowing hole reachable?** `contains` compares `Custom` grants by name and ignores parameters. *Resolution: trace how `Custom` capabilities are issued and whether any grantee controls the parameter set of a delegated child. If reachable, it is a delegation defect and belongs in the security channel, not here.*
- **SF-B — Does "causal ordering" survive as the word?** SF-3's claim has no implementation and its design leans on timestamps. *Resolution: either the multi-device design adopts version vectors explicitly, or the wording changes to what timestamps actually supply. Decided when multi-device sync is first implemented.*
- **SF-C — What algorithm does `turbovec` use?** SF-13 could not be determined from this repo; the crate is an external dependency and not vendored. *Resolution: read the upstream crate, or measure recall against brute force on a known set. Matters if memory recall quality is ever in question.*
- **SF-D — Should `MemoryIndex`'s trait pattern be generalized?** It is the corpus's cleanest instance of representation-behind-a-trait, and `DEPENDENCY-POSTURE` cites it as the model for structural hedging. *Resolution: an authoring or design ruling on whether structures carrying a claim should default to a trait boundary, or whether that is over-abstraction for structures with one plausible implementation.*
- **SF-E — Where do inclusion proofs belong in the peer contract?** m0 wires a consumer, but `CROSS-SUBSTRATE-PEER-CONTRACT` §3's Required affordances do not currently mention proof-based verification. *Resolution: a contract revision at the point m0 lands, or an explicit finding that proofs are an optional affordance.*

---

## What is specified vs. what is shipped

Per A11. Every row was verified by direct read on 2026-07-27; the states below are as-of that read.

- **Verified present in code:** `AuditEntry` hash-chain linkage; the full epoch Merkle implementation including `MerkleProof::verify`; `compute_merkle_root` called from `anchor_pipeline`; `NodeRegistry` sequence monotonicity with `SequenceRegression`; `DelegationChain`'s verify-then-construct pattern and its eight enumerated invariants; `AuditStore`'s `cfg(test)`-gated unsigned constructor; `GrantedCapability::contains` and its two helper functions; `DiscoveryManager::recent_nonces`; `PeerReputation` FIFO capping; `SkillMatcher::match_request`; the `MemoryIndex` trait and `TurboVecIndex`.
- **Verified absent from code:** any vector clock, version vector or Lamport structure; any Cartographer crate, ontology node type or edge type; any `PartialOrd`, `subsumes`, `implies` or `narrows` abstraction over capabilities; any consumer of `MerkleProof` outside its own module and tests; the function named `narrow_capability` that `CapabilityGrant::delegate`'s doc comment cites.
- **Could not determine:** `turbovec`'s internal search algorithm (external, not vendored); whether the `Custom` parameter hole is reachable in practice.
- **Note on a stale doc reference:** `CapabilityGrant::delegate`'s doc comment states narrowing is *"enforced by `narrow_capability`"*. No such function exists; enforcement is `GrantedCapability::contains`. A one-line comment fix, recorded because it is exactly the drift A11 exists to catch.

---

## Non-goals

- **Not a performance audit.** Nothing here is motivated by speed. SF-9 and SF-11 are named for boundedness and correctness, not throughput.
- **Not a refactoring plan.** The inventory records state and names alternatives; whether any row is worth changing is decided per row, elsewhere.
- **Not a claim that structural beats convention everywhere.** A convention maintained by one call site is often the right cost. The point is knowing which you have.
- **Not a review of every structure in the codebase.** Scoped to structures over which the corpus makes a claim, and that scoping is what makes it finishable.
- **Not a security assessment.** SF-A may become one; if it does, it moves to the security channel and out of this document.
