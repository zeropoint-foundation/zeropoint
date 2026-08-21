# Extension Eviction Ceremony — declared inverses, ordered teardown, verified confluence

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.10 (composition contracts), §II.12 (Layer A / Layer B split), §II.15 (substrate boundary planes), §III.18 (delegable safety), §III.19 (detectability over invulnerability), §III.20 (forward-only recovery), §III.22 (verify before commit). Specifies what happens to a component's *effects* when its delegation is revoked. Canonical claims live in KEEL.

**Date:** 2026-08-16. **Status:** Proposed. No code written.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Composes with:** `EXTENSION-SURFACE-2026-07.md` (capability declaration language — this document adds one required field to it; §"Composition rules" gains a departure half), `QUARANTINE-PLANE-2026-07.md` (admission ceremony Step 2 gains one check, Step 5 revocation gains a body), `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` (the dependency graph this ceremony orders by is materialized, not tracked in memory), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` and `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` (the recompute-and-compare pattern §5 borrows), `BLAST-RADIUS-AND-RECOVERY-2026-07.md` (termination semantics for the arrest path, which this does NOT replace), `CIRCUIT-BREAKER-2026-07.md` (emergency revocation bypasses this ceremony by design — §6).

**Prior art:** Cordis, the plugin runtime under DeepSeek's harness, and its preprint *A Programming Paradigm for Spatiotemporal Composability* (`github.com/cordiverse/paper`, draft of 2026-08-13, marked as under active revision). Mechanisms adopted, adapted and rejected are itemised in §7.

**Correction, same day.** This document's first revision was written from the repository abstract and secondary descriptions, and attributed a **confluence theorem** to the paper — that a system which loaded A, added B, tried C and removed C settles equivalent to one that loaded A and B directly. On reading the formal sections, **the paper states no such theorem.** What it proves is structural preservation: that effect tracking preserves composition. Those are preservation results, not a global equivalence claim, and the confluence framing appears to originate in secondary commentary rather than the source. §5 survives the correction unchanged in substance because it was deliberately built to measure the property rather than inherit it — but the attribution was wrong and is withdrawn. Two mechanisms found only on reading the source have been added: idempotent inverses (§4.6) and epoch invalidation (§4.1 Phase 0), the second of which closes a real hole in the first revision's ceremony.
---

## 1. The gap

`EXTENSION-SURFACE` §"Revocation" specifies eviction in one clause: *extension unloaded, in-memory state discarded, chain retains history.*

That is a **drop, not an unwind**, and the surface it drops from is large. Under §"Composition rules" an admitted extension may register verbs into the Regent's vocabulary, add observation surfaces, declare ontology object types, insert policy into the gate at a chain-anchored evaluation position, declare ceremonies, and add cognitive input sources. None of those live in the extension's own memory. Discarding the extension does not retract them.

Concretely, and each of these is answerable today only by inspection:

- An **ontology object type** declared by a revoked extension. Instances were materialised from chain under that schema. The Cartographer rebuilds ontology from chain; on the next rebuild, what types those instances.
- A **policy extension** removed from the gate. Evaluation order is chain-anchored and positional; every policy behind it shifts.
- A **verb provider** revoked while a second extension's delegation names it as `preferred_provider`.
- A **cognitive input source** removed between Tier assembly and cycle start.
- An **observation surface** whose findings are on chain — those are fine, chain is truth — but whose registration is not.

The corpus has rich rules for how components **coexist** and none for how they **depart**. This document supplies the departure half.

## 2. Inverse as an admission obligation

Cordis records inverses at runtime: an author wraps each effect in a call that returns its own undo, and the runtime accumulates them on a stack. The inverse is a *runtime promise by the author*.

ZeroPoint can do better, because it already refuses entry to under-declared components. `EXTENSION-SURFACE` §"Capability declaration language" is fine-grained, justified per capability, and structurally audited at `QUARANTINE-PLANE` Step 2 against the WASM module's actual imports.

**Every declared capability that transforms substrate context must declare its inverse.** The manifest gains an `inverse` field per capability scope:

```toml
[capabilities.chain_write]
scopes = [
  { receipt_type = "example:recommendation:*",
    justification = "Emits recommendation receipts",
    inverse = "none_required",              # chain is append-only; §4.2
  },
]

[capabilities.ontology_declare]
scopes = [
  { object_type = "example:Recommendation",
    justification = "Materialises recommendations as typed objects",
    inverse = "orphan_retype",              # §4.3 — declared disposition for existing instances
    inverse_target = "example:Recommendation:orphaned",
  },
]

[capabilities.policy_insert]
scopes = [
  { position = "post_constitutional",
    justification = "Adds org-specific egress rule",
    inverse = "positional_withdraw",        # §4.4 — remaining policies re-derive order from chain
  },
]
```

**Admission refuses a context-transforming capability with no declared inverse.** New verification failure, in the family `QUARANTINE-PLANE` Step 2 already emits:

```
quarantine:verification_failed:<surface>:<hash>  reason=no_declared_inverse capability=<name> scope=<index>
```

This is a structural audit in the same sense as the existing capability audit — the check is on manifest completeness against declared trait implementations, not on whether the inverse is *correct*. Correctness is out of reach (§7) and is handled by §5 instead.

The gain over the prior art is timing. Cordis learns an inverse exists when the effect runs. ZeroPoint learns it before the operator is ever asked to sign, so the delegation ceremony can show the operator not only what the extension will do but **how it leaves**.

## 3. Ordering derived from the ontology, not from process memory

Cordis orders teardown by a runtime dependency graph: dependents are drained before their provider's own effects are recovered, and within a component inverses unwind LIFO.

Adopt both orderings. Take the graph from a different place.

The Cartographer materialises the ontology from chain as typed objects and typed relationships. `provides` and `depends_on` between extensions and capabilities are relationships like any other. The teardown order is therefore a **query against materialised state**, not a structure the runtime must maintain.

Three consequences follow, and the third is the reason to prefer it:

1. **It survives restart.** An in-memory graph does not; a chain-derived one is rebuilt with everything else.
2. **It is auditable.** The order a teardown used is reconstructible after the fact from the same chain that produced it.
3. **It can be asked before it is used.** `zp extension revoke --preview <hash>` answers *what breaks and in what order* without revoking anything.

Revocation preview is the feature the prior art structurally cannot offer, and it is worth more than the unwind itself. Operators do not fear removing things; they fear not knowing what removal costs.

## 4. The ceremony

### 4.1 Phases

0. **Epoch** — take an epoch marker over the dependency graph. The plan below is computed against it, and every subsequent phase re-checks it at its boundary. **If the graph changes mid-eviction — an admission, a revocation, a delegation edit — the ceremony aborts rather than proceeds against a stale plan**, emitting `extension:eviction:aborted reason=epoch_invalidated`. Taken directly from the source's Epoch mechanism, which aborts at iteration boundaries when dependencies change mid-execution. The first revision of this document had a plan phase and an execute phase with nothing between them; that was a race, and this is the fix.
1. **Resolve** — query the ontology for the transitive dependent set of the target's provided capabilities. Emit `extension:eviction:planned` carrying the ordered plan and its hash. The plan is chain-anchored *before* execution, so a teardown that diverges from its plan is detectable.
2. **Drain dependents** — each dependent evicted first, recursively, provider-last. A dependent that is itself a provider recurses.
3. **Unwind** — the target's declared inverses invoke in reverse declaration order (LIFO), one receipt each (§4.5).
4. **Withdraw registration** — verbs, surfaces, ceremonies, input sources deregister.
5. **Verify** — §5.
6. **Settle** — emit `extension:eviction:complete` citing the plan hash, the count of inverses invoked, and the count that failed.

### 4.2 Chain effects have no inverse and require none

A receipt an extension emitted is history. `inverse = "none_required"` is the correct and only declaration for `chain_write`, and III.20 is the reason: the substrate does not roll back truth. An extension's receipts survive its eviction permanently. This is not a limitation to be worked around; it is the property that makes the rest of the ceremony safe to attempt.

### 4.3 Ontology types outlive their declarer

The interesting case. Instances materialised under a revoked extension's schema cannot vanish — they are derived from chain receipts that remain valid. The declared inverse chooses their disposition:

- `orphan_retype` — instances re-materialise under a declared orphan type, remaining queryable and clearly marked as unmaintained.
- `retain_frozen` — the type definition persists, marked as having no live declarer; re-admitting the extension resumes it.
- `refuse_eviction` — the extension declares its types load-bearing; eviction requires an explicit operator override ceremony.

`refuse_eviction` is deliberately available. Some capabilities *should* be hard to remove, and making that a declared property the operator sees at admission is better than discovering it at revocation.

### 4.4 Positional effects re-derive

Gate policy order is chain-anchored and positional. The inverse is not "put everything back" — it is *recompute the order from the surviving chain-anchored positions*, which is III.20's forward-only recovery applied to a small derived structure.

### 4.5 Unwind receipts

One receipt per inverse invoked:

```
extension:inverse:invoked  ext=<hash> capability=<name> scope=<index> outcome=ok
extension:inverse:failed   ext=<hash> capability=<name> scope=<index> reason=<...>
```

A failed inverse **does not abort the eviction.** It is recorded and the unwind continues. Aborting midway leaves a half-torn-down component with no plan for the remainder; continuing leaves a fully-attempted teardown with an exact record of what did not come back. The second is recoverable by a human, the first is not.

This is the direct answer to the prior art's unaddressed case: an inverse that throws. Not prevented — *made countable*, per III.19.

### 4.6 Inverses run at most once

The source enforces idempotence through private handles: an inverse **must run at most once**, and the runtime holds the
only reference that can fire it.

Adopt this, and note why it is load-bearing *here* specifically. §4.5 records a failed inverse and continues rather than
aborting, which makes retry attractive — an operator who sees three failures will want to run the eviction again. Without
an at-most-once guarantee, the retry re-fires the inverses that already succeeded. A withdrawal applied twice is not a
withdrawal.

So the invocation receipt is also the guard: an inverse with an `extension:inverse:invoked` receipt for this eviction's
plan hash is spent, and re-eviction resumes from the first unspent one. The chain supplies the private handle.

## 5. Confluence as a verified postcondition

Path-independence of settled state — load A, add B, try C, remove C, and end up where a direct load of A and B would have put you — is the property an eviction ceremony most wants to be able to claim.

**No source proves it.** The paper formalises effects as context transformations carrying inverses and proves that tracking preserves composition; it states no global equivalence theorem, and its own formalism assumes recoverable transformations form a group while its implementation merely asks authors for cleanup callbacks. The gap between those two is precisely where an unverified inverse lives.

**The substrate does not need to assume it. It can measure it, per operation.**

After Phase 4, recompute the ontology from chain and compare it against the ontology now in memory:

- **Match** → confluence held for this eviction. Emit `extension:eviction:confluent`.
- **Mismatch** → emit `extension:eviction:divergent` with the differing object set.

This is `OBSERVER-COHERENCE-DISCIPLINE` and `CHAIN-READ-CANARY` pointed at eviction: two independent derivations of the same state, compared. Divergence is not a failure of the ceremony — it is the ceremony working. It says *this component's declared inverses were not complete*, which is exactly the fact nobody can obtain by reading a manifest.

Two properties worth stating plainly:

- **The chain is never confluent.** Load, use and unload are all permanent history. Path-independence is a claim about derived state only, and asserting it about the record would contradict III.20.
- **Nothing here depends on the paper's theorem.** If its hypotheses are wrong or narrower than reported, the measurement still works — it simply reports divergence more often. A design that measures what a proof would have assumed is strictly the safer one, and it was chosen for that reason rather than out of doubt about the proof.

Over time the divergence rate per extension is a dossier-grade fact about component quality, obtainable no other way.

## 6. What this does not cover

- **Circuit-breaker trips.** Emergency revocation bypasses this ceremony deliberately. `BLAST-RADIUS` termination semantics govern arrest; an ordered teardown is exactly the wrong response to a component under suspicion. The trade is recorded rather than resolved: arrest leaves debris, and cleaning it up is a post-incident ceremony, not part of the trip.
- **External effects.** A component that sent an email can be evicted; the email stays sent. Shared with the prior art and unfixable by either.
- **Semantic correctness of any inverse.** §2 checks that an inverse is declared. §5 checks whether the result diverged. Neither checks that the inverse does what its name says, and no static mechanism can.
- **Layer A.** §8.

## 7. Prior art — adopted, adapted, rejected

| Cordis mechanism | Disposition here |
|---|---|
| `ctx.effect()` — effect returns its own inverse | **Adapted.** Moved from runtime registration to admission-time declaration, so absence is refusable rather than discoverable. |
| LIFO unwind within a component | **Adopted** unchanged (§4.1 Phase 3). |
| Provider-first notification; dependents drained first | **Adopted** as the ordering rule (§4.1 Phase 2) — but note the source mandates LIFO recovery and proves **no partial-ordering theorem on dependencies**. This is implementation behaviour, not a proved result. |
| Runtime dependency graph | **Rejected.** Replaced by the materialised ontology (§3), which survives restart and supports preview. |
| Confluence as proved property | **Withdrawn — no such theorem exists in the source.** §5 measures the property per operation instead, which is what it did before the correction too. |
| Uniform plugin grammar over all components | **Rejected.** §8. |
| Partial failure during unload (unaddressed there) | **Specified** here: continue, record, do not abort (§4.5). |
| Idempotent inverses via private handles | **Adopted** (§4.6), with the invocation receipt serving as the handle. |
| Epoch checks aborting on mid-execution dependency change | **Adopted** (§4.1 Phase 0). Closes a race the first revision had. |
| Effects as a subgroup of recoverable transformations | **Noted, not adopted.** The formalism assumes invertibility; the implementation asks authors for callbacks. That gap is where semantic incorrectness lives, and §5 is the only thing here that detects it. |

## 8. The Layer A boundary, stated in composability terms

`KEEL` §II.12 divides compiled Layer A from loadable Layer B, and §III.17 makes the point sharply: removing peer-to-peer messaging would require shipping a substrate binary that is not ZP.

The prior art's grammar — model adapter, tool registry, scheduling, sandbox policy, agent loop and interface all as plugins — has a governance cost its own materials do not name. **If the sandbox policy is a plugin, it is removable by the same mechanism that removes a colour theme.** DeepSeek is candid that creator mode is not a security boundary and should be treated like shell access; that candour is the tell.

This document therefore proposes a definition rather than only a prohibition:

> **A component belongs to Layer A precisely when it has no admissible inverse.**

Constitutional capability is exactly that which cannot be withdrawn. The inverse obligation in §2 is the test that sorts the layers: a capability that can declare a coherent inverse is Layer B and evictable; one that cannot is Layer A and compiled. This is a sharper articulation of the split than "compiled versus loaded," which describes the implementation rather than the reason.

## 9. Open positions

1. **Is `refuse_eviction` (§4.3) an escape hatch or a Layer A admission?** An extension declaring itself unremovable is claiming constitutional status without the ceremony. Either it needs a stronger admission bar, or it should be disallowed and such components pushed to Layer A.
2. **Preview cost.** §3's transitive dependent query is an ontology traversal of unknown cost at realistic extension counts. Unmeasured, and preview is worthless if it is slow enough to skip.
3. **Divergence remediation.** §5 detects divergence and does nothing about it. Full ontology recompute is the blunt answer and is precisely the recovery-margin reserve `BUFFER-OBSERVATION` §3 is watching drain.
4. **Whether unwind reduces recompute distance.** Argued informally that verified-confluent unwind could substitute for recompute-from-checkpoint. This only matters if extension churn is a meaningful share of chain growth, which is **unmeasured**. Do not bank it.
5. **The preprint is under active revision** and says so. The formal sections were read at the 2026-08-13 draft; a later version may add the equivalence result this document withdrew, in which case §5's measurement becomes a check on a claimed theorem rather than a substitute for an absent one. Re-read before citing.

---

## Framing note

The corpus has an admission story of unusual depth — six surfaces, fine-grained capability declaration, structural audit against WASM imports, an operator ceremony that shows what a component will do. It pairs that with a single clause about what happens when the same component leaves.

That asymmetry is not an oversight so much as a consequence of where attention goes: admission is where the danger feels concentrated, and eviction feels like cleanup. The prior art's contribution is to notice that removal is the harder half — creating a capability is easy, and unmaking it in a live system is where the guarantees have to come from.

What the substrate adds is that it need not take the guarantee on faith. A chain-anchored system can plan the teardown before it runs, record each inverse as it fires, and then check whether the world came back the way the manifest promised. The prior art proves a property under hypotheses. This proposal measures it, one eviction at a time, and keeps the record either way.
