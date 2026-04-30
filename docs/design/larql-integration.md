# Design Note: Cognitive Accountability Layer — LARQL + MEDS Integration

*Status: exploratory stub. No code. Frames the integration surface for a
future RFC.*
*Updated 2026-04-18: Added MEDS error-basin detection (integration point 4),
ReasoningFingerprint and DriftSignal schema types, three-layer framing.*

---

## Motivation

Today `zp-skills` treats skill payloads as signed, chain-anchored, and
attributable, but the *contents* of a skill are opaque. If a skill encodes
facts or relations inside model weights, we can prove who issued the skill
but we cannot address individual facts within it. LARQL's FFN-as-graph
decomposition would let us attach provenance at the fact level rather than
the payload level — materially improving revocation granularity, drift
detection, and dispute resolution.

## Integration surface

Three integration points, ordered by how invasive they are to the existing
architecture.

### 1. Knowledge-edit receipts (least invasive)

LARQL's INSERT → patch overlay → COMPILE flow is already two-phase. Wrap
each phase in receipt emission:

- **Proposal receipt** — emitted on INSERT. Records the proposed fact
  (entities, relation, layer, feature index), the delegating agent,
  the grant under which the edit is proposed, and a hash of the patch
  overlay.
- **Attestation receipt** — emitted by the compiling party. Records
  verification that the edit does not violate invariants (no collision
  with existing facts, no scope violation, within delegated trust tier).
- **Commit receipt** — emitted on COMPILE. Records the resulting Vindex
  delta and the safetensors digest.

This layer alone gives every fact in the model a provenance chain without
touching inference.

### 2. Trace-committed inference receipts

At runtime, every decision an agent commits to a chain receipt carries a
LARQL trace commitment: a hash over the sequence of (layer, feature index,
gate activation, relation label) tuples that the forward pass actually
consulted. The receipt claims "this agent decided X" and the trace lets any
auditor reconstruct "and here is the path through the FFN graph that
produced X."

Two costs to name honestly:
- **Overhead** — producing a trace at every forward pass is non-trivial.
  Likely requires either async trace emission (trace attaches to receipt
  out-of-band) or a trace-on-demand model (receipt commits to a trace
  retrievable from the agent's evidence store).
- **Attention gap** — LARQL decomposes FFN but attention routing is not
  in the graph. Trace only captures which features were consulted, not
  why attention routed to them. This is a real limit, not a
  minor one.

### 3. Policy over trace properties

Once trace commitments exist, the policy engine can reason over them.
Rules can reference trace properties directly:

- "Reject if trace invokes any relation tagged as `deceptive` or
  `manipulative`."
- "Require trace depth ≥ N for any decision crossing a trust-tier
  boundary."
- "Reject if the trace's stated relation path diverges from the
  agent's post-hoc explanation by more than ε."

This is a substantial extension of the policy engine and should wait for
empirical experience with (1) and (2).

### 4. MEDS-style error-basin detection

MEDS (Memory-Enhanced Dynamic Reward Shaping, 2025) demonstrates that
layer-wise logits at the final answer token serve as a compact "logic
fingerprint" of the reasoning trajectory. HDBSCAN clustering over these
fingerprints identifies dense regions of repeated errors — "stable error
basins" — that persist despite surface variation in the model's text
output.

Integration with ZP:

- **Fingerprint emission** — after each inference, compute the deep-layer
  (last ~14 layers) logit fingerprint. Store alongside the LARQL trace
  in the agent's evidence store.
- **Error-basin registry** — maintain a clustered index of known error
  fingerprints. When a new fingerprint lands in a dense cluster, emit
  a **drift signal receipt** recording the cluster ID, density score,
  and the decision receipt it accompanies.
- **Policy over fingerprints** — the policy engine can evaluate rules
  like "reject if fingerprint lands in error cluster with density above
  threshold T" or "require human review if fingerprint diverges from
  the agent's stated reasoning by more than ε."
- **Confabulation detection** — compare the LARQL trace (which features
  and relations were actually consulted) against the agent's stated
  reasoning. The divergence between the two — the confabulation gap —
  is measurable as a distance metric between the trace's relation path
  and the semantic content of the agent's explanation.

MEDS and LARQL are complementary: LARQL decomposes what the model *knows*
(FFN as graph), MEDS characterizes how the model *reasons* (activations as
trajectory fingerprints). Together they provide the two inputs needed for
full trace-layer accountability.

Key engineering finding from MEDS: only the last ~14 transformer layers
gave the best alignment between clusters and true logical error types,
because deep layers encode higher-level logic rather than surface grammar.
This suggests layer-selective commitments: commit to the deep-layer
fingerprint always (lightweight), commit to the full LARQL trace only on
demand (expensive).

## Schema additions

Sketch, not final:

```
TraceCommitment {
    trace_hash: Blake3,
    layer_count: u32,
    feature_count: u32,
    relations: Vec<RelationId>,       // labels invoked
    vindex_digest: Blake3,            // which compiled knowledge state
}

KnowledgeEditProposal {
    proposing_agent: AgentId,
    grant: GrantId,
    proposed_fact: { entity_a, relation, entity_b },
    layer: u32,
    patch_overlay_hash: Blake3,
}

KnowledgeEditCommit {
    proposal_hash: Blake3,
    attestation_hash: Blake3,
    vindex_delta_digest: Blake3,
    safetensors_digest: Blake3,
}

ReasoningFingerprint {
    fingerprint_hash: Blake3,        // hash of the deep-layer logits
    layer_range: (u32, u32),         // which layers (e.g., last 14)
    model_digest: Blake3,            // which model weights produced this
    vindex_digest: Blake3,           // which compiled knowledge state
}

DriftSignal {
    fingerprint: ReasoningFingerprint,
    cluster_id: Option<u64>,         // None if isolated (novel reasoning)
    cluster_density: f64,            // high = known error basin
    decision_receipt: ReceiptId,     // the receipt this fingerprint accompanies
    confabulation_gap: Option<f64>,  // divergence from stated reasoning
}
```

## Open questions

1. **Polysemanticity and provenance** — a single feature index encodes
   multiple concepts across layers. If we sign "feature 1247 asserts
   relation X between A and B," we are signing a probabilistic claim, not
   a deterministic one. How do we reconcile cryptographic-grade provenance
   with statistically-entangled representations? One candidate: sign the
   *joint* (gate, down, layer, context) tuple rather than the feature
   index alone.

2. **Revocation semantics** — revoking a delegation should cascade to any
   facts committed under it. What does "revoke a fact" mean when the
   fact is baked into weights via COMPILE? Options: (a) require an
   explicit DELETE → COMPILE round trip, (b) maintain a revocation
   overlay that short-circuits queries at inference time, (c) require
   periodic recompilation excluding revoked facts.

3. **Cross-agent knowledge transfer** — if Agent A queries Agent B's
   knowledge store (LARQL remote-FFN scenario), the transfer is itself
   a trust event. Should it produce a receipt? How does the querying
   agent verify the remote knowledge came from a non-revoked source?

4. **Architecture dependence** — LARQL targets standard transformer FFN.
   Mixture-of-experts, state-space models, and hybrid architectures
   will need different decomposition primitives. Does the receipt
   schema stay architecture-neutral, or do we need per-architecture
   decomposition adapters?

5. **Trace verifiability** — trace commitments only help if a verifier
   can reconstruct and check them. This implies verifiers have
   access to the Vindex at some point. How do we handle models
   where weights are confidential?

## Non-goals

- Not trying to solve model explainability in general. LARQL gives us
  decomposable FFN; that's narrower than "why did the model do this"
  but it's the narrow part we can actually sign.
- Not trying to replace training pipelines. Knowledge-edit receipts
  apply to post-training edits, not to attribution of learned
  weights.
- Not proposing trace commitments become mandatory on every receipt.
  Opt-in per skill, with policy able to require them for
  high-stakes decisions.
