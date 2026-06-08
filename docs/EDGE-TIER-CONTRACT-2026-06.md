# Edge Tier Contract — What the Foundation Worker Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the worker tier*
*and the substrate tier. Names which affordances the edge*
*implementation MUST have, which it MAY have, and which it MUST NOT*
*have, so that affordance gaps are quickly classifiable as*
*degradations vs disqualifications vs correct postures.*

---

## What this doc closes

The architecture doc's §4c ("Edge capability split — why the gateway is incomplete by design") says *why* the foundation worker cannot carry policy or signing authority — the chain lives at the operator's substrate, signing-is-gravity requires the signer hold the canonical key, and there-is-no-center forbids edge-resident authority. That section is the structural reasoning.

This document is the operational complement. It names *what specifically* an edge implementation must do, may do, and must not do — the partition that turns "can we put X at the edge?" into a one-document lookup instead of a re-derivation from principles. The contract is runtime-neutral by construction: the current Cloudflare Workers + D1 deployment is one implementation; another runtime (Bun, Deno, Fastly Compute@Edge, a self-hosted Rust binary fronted by Caddy, even just the Cloudflare Tunnel with no worker tier at all) meets the same contract differently.

The doc exists because the contract was, until this point, implicit — it lived in `crates/zp-server/src/foundation_relay.rs` (the operator-side consumer) and in `zeropointfoundation.org/src/auth/forward.js` (the worker-side producer), with no single document partitioning the categories. Implicit contracts produce slow architectural decisions, because each new feature requires re-deriving whether it's allowed at the edge from first principles. The explicit contract is what makes the architecture's edge tier composable with future work without each decision becoming a re-litigation.

## The three categories

### Required — implementation must have these to serve as the foundation worker

An implementation lacking any of these cannot be the foundation worker for ZeroPoint. The fallback when a required affordance is missing is to drop the worker tier entirely and address operator substrates directly via the Cloudflare Tunnel (or equivalent). That's a real degradation in foundation features — no cross-operator routing, no anonymous auth-failure capture, no public surface auth — but the substrate's correctness is unaffected because the chain still lives where it always did.

The five required affordances:

1. **Inbound authentication primitive.** The worker must be able to verify the identity of incoming requesters before doing anything else. The specific primitive varies by deployment — Cloudflare Access JWT verification, OIDC token verification, passkey-bound session cookies, or equivalent — but the affordance is "the worker can decide whether this request comes from a known principal before forwarding anything." Without inbound auth, the worker forwards to the substrate based on requester claims it cannot validate, and the operator's substrate receives unauthenticatable traffic.

2. **Envelope-signing key access.** The worker must hold an Ed25519 keypair derived from Genesis via the `zp.foundation.edge.v1` context (see `crates/zp-keys/src/foundation_edge_signer.rs`), and must be able to sign outgoing forwards with it. Key storage may be a Cloudflare secret, an environment variable, an HSM, a sealed file — the affordance is access to the signing material at request time. Without this, the operator's substrate cannot authenticate forwards as originating from a legitimate edge identity.

3. **Identity-route lookup.** The worker must resolve `operator-id → operator endpoint URL`. The lookup table may be a KV store, a D1 table, an environment-bound config blob, or a static map — the affordance is the lookup, not the storage shape. Without this, the worker cannot determine where to forward an inbound request, and the cross-operator routing function that distinguishes the foundation worker from a per-operator tunnel evaporates.

4. **HTTP body transformation.** The worker must transform external request shapes into the canonical receipt-intent shape that `foundation_relay`'s `POST /v1/foundation-receipts` accepts. The transformation is mechanical — pull the actor, the claim, the subject, the capability-used, the metadata from the inbound shape and assemble the intent envelope — but if the worker cannot perform it, the substrate-side endpoint receives data it cannot parse into receipts.

5. **Outbound fetch.** The worker must be able to make outbound HTTP requests to the operator's substrate endpoint. Trivial in nearly every modern edge runtime, but worth naming explicitly because some constrained environments (e.g., KV-only Workers configurations) lack it. Without outbound fetch, the worker can authenticate and transform but cannot complete the forward.

### Optional — implementation may or may not have these; lacking any is degradation, not failure

Each optional affordance is a strict improvement over its absence, but the substrate's correctness — chain integrity, gate enforcement, operator authority, signing-is-gravity — does not depend on any of them being present. An implementation that lacks rate limiting is more exposed to DoS than one that has it; it is not architecturally wrong.

The optional affordances:

1. **TLS termination.** Typically delegated to the hosting runtime or CDN. An implementation that does its own TLS termination is fine; one that delegates is fine; one that runs without TLS in a constrained internal deployment is fine for that scope. The substrate does not require TLS at the edge because the envelope signature already provides body integrity and origin attestation.

2. **Rate limiting.** DoS mitigation against the operator's substrate. The substrate's natural rate limit is delegation lease scope, which is policy-level. Edge rate limiting is a DoS protection layer, not a policy primitive, and the substrate stays correct without it.

3. **Edge caching of signed artifacts.** When signed artifacts exist (per the substrate-proposes / operators-sign lifecycle), they are content-addressed and cache-safe by construction. Edge caching them would meaningfully cut read latency. An implementation without this affordance just defers more reads to the operator's substrate; no correctness implication.

4. **Compression.** Standard performance affordance. Substrate-orthogonal.

5. **Content-blind analytics.** Logging request rates, response sizes, error counts, and other metrics that do not see receipt contents or operator-derived material. Operationally useful; substrate-orthogonal. Note the "content-blind" qualifier: analytics that inspect receipt contents step into forbidden territory (see below).

6. **Proactive operator-endpoint health checking.** Periodic liveness probes against operator substrates with cached results that short-circuit forwards to known-down endpoints. Improves failure-mode UX (faster honest failure on inbound) but is not required — reactive failure (a forward attempted and failing) is also correct, just slower to surface.

7. **Anonymous receipt routing.** A dedicated catch-all forwarding path for pre-authentication events where the operator identity is not yet known (e.g., the `operator: unknown` auth-failure case surfaced in `docs/handoffs/delegation-lifecycle-2026-06.md`). The substrate stays correct without this affordance — pre-auth events without canonical landing don't break chain integrity — but having it improves audit completeness.

### Forbidden — implementation must not exercise these even if the runtime supports them

The forbidden category is the architecturally interesting one. Forbidden affordances are the things an edge runtime might be technically capable of doing — WebCrypto Ed25519 is available in Cloudflare Workers, persistent storage is available via D1 and KV, complex logic is available because the worker is just code — but doing them is the failure mode. Lacking the affordance is fine; having and using it is the structural breakage.

The discipline-pin candidate `no_edge_signed_canonical_chain` (see `docs/handoffs/discipline-pin-audit-2026-06.md` §1) is the structural enforcement of one forbidden line; the other lines below are currently enforced by code review and architectural discipline alone, but warrant similar pin coverage over time.

The forbidden affordances:

1. **Signing canonical receipts.** The worker must not produce `Receipt` structs signed with the operator's audit-chain signing key, even transiently, even cached, even as drafts. Canonical receipt signing is what `foundation_relay`'s `POST /v1/foundation-receipts` does on the operator's substrate, with the operator's Genesis-derived audit key. P1 (signing is gravity): the signature is the substrate's attestation; an edge-issued signature is decorative because the chain it attests to does not live there. The foundation-canonical-v1 architectural correction was precisely the empirical instance of this line being crossed.

2. **Holding chains.** The worker must not maintain any storage shape that resembles a chain — hash-linked entries, ordered receipts, prev-pointer columns — even as a cache, even for performance. Reading the chain through the worker is fine (the worker proxies the operator's substrate's chain endpoint); having the chain at the edge is not. P3 (there is no center): chain-resident state at the edge would be a center forming where the architecture commits to having none.

3. **Enforcing policy decisions.** The worker must not run gate evaluations, evaluate constitutional rules, or make policy decisions of any kind. It may decide *whether to forward this request to the operator at all* — that's the inbound auth primitive, a coarse-grained yes/no — but it must not decide *whether the operator is allowed to perform this action*. That's the gate's job, on the operator's substrate, signed by the operator's key. The split is between "do I forward this?" (worker's call) and "does this action pass policy?" (operator-substrate's call).

4. **Persisting operator-derived material beyond ephemeral pass-through.** The worker must not store receipts, delegation grants, capability grants, operator chain state, or any other operator-derived material in worker-side storage with anything stronger than request-lifetime semantics. Caches that expire within a request are fine; caches that persist across requests with operator-derived contents are forbidden. P3 again: persistent operator-state at the edge is a center.

5. **Mediating chain queries with worker-side authority claims.** The worker may proxy chain queries to the operator's substrate. The worker may not augment, filter, redact, or otherwise mediate query results with authority the worker claims for itself. If the operator's substrate returns N entries, the worker forwards N entries. If the operator's substrate denies a query, the worker forwards the denial. The worker's role is transport, not interpretation.

6. **Acting as the source of truth for delegation state, capability state, or operator identity state.** Delegations are chain-resident; capabilities are chain-resident; operator identity is Genesis-resident. The worker may cache these for routing decisions (e.g., the identity-route lookup table) but must not be the authoritative source for any of them. The authoritative source is always the operator's substrate, and the cache must be designed such that staleness produces honest failure (forward fails, operator's substrate denies) rather than silent incorrect authorization.

## How affordance gaps get classified

When an implementation lacks affordance X, the classification follows directly from the three categories:

- If X is **Required**: the implementation cannot serve as the foundation worker. Use a different implementation, or drop the worker tier and address operator substrates directly. The fallback degrades foundation features (no cross-operator routing, no public surface auth, no anonymous auth-failure capture) but the substrate stays correct.

- If X is **Optional**: degrade gracefully. The substrate's correctness is untouched; the worker is operationally weaker. Document the gap so operators making deployment decisions know what they're trading off.

- If X is **Forbidden**: not a gap. That's the correct posture. An implementation that lacks the ability to sign canonical receipts is, in that specific respect, more architecturally honest than one that has the ability and must be disciplined into not using it.

## Composition with existing architecture

The contract composes with several existing structural commitments:

- **§4c (Edge capability split)** says *why* the gateway is incomplete by design — P1 and P3 force the split. This doc says *what specifically* the gateway must do, may do, and must not do. The two sit as design-philosophy and operational-spec for the same architectural concern.

- **Principle 1 (Signing is gravity)** is the structural justification for the forbidden category's first line — edge-signed receipts are decorative because the chain they attest to does not live at the edge.

- **Principle 3 (There is no center)** is the structural justification for most of the forbidden category — persistent state at the edge, chains at the edge, authority at the edge all form centers where the architecture commits to having none.

- **Principle 8 (One canonical path per substrate concern)** is what this doc is making true for the edge-tier-contract concern: previously the contract lived in two source-code paths (`foundation_relay.rs` and `forward.js`); now it lives in one document that those source paths implement.

- **II.0 (Contracts singular, implementations plural)** is the runtime-portability commitment. The contract here is singular; the Cloudflare Workers deployment is one implementation; future implementations are possible against the same contract.

- **Proposed discipline pin `no_edge_signed_canonical_chain`** (see `docs/handoffs/discipline-pin-audit-2026-06.md` §1) is the structural enforcement of the forbidden category's first line. The other forbidden lines warrant similar pin coverage over time; this doc names the targets.

## Portability — what changes if the implementation isn't Cloudflare Workers

The contract is runtime-neutral by construction. The Cloudflare Workers deployment is one implementation. Other implementations against the same contract:

- **Bun / Deno / Node** running on a small VPS or container, fronted by a TLS-terminating reverse proxy. All five required affordances are trivially available. Operational trade-off: more substrate-managed infrastructure, but no Cloudflare lock-in for the edge tier.

- **Fastly Compute@Edge.** WebCrypto Ed25519 is available; KV is available; outbound fetch is available. All required affordances available. Optional affordances (rate limiting, caching) available with Fastly's own primitives.

- **Self-hosted Rust binary** (axum + cloudflared tunnel for public reachability). Required affordances trivially available; optional affordances available with whatever crates one wires in. This brings the edge tier closer to the substrate's own implementation language and reduces cross-language complexity at the cost of operating one more service.

- **No worker tier at all** — operator substrate directly addressed via cloudflared tunnel + DNS. The Required category is moot because the worker tier doesn't exist; degradation in foundation features is real and accepted. The substrate's correctness is unaffected, which is the point: the contract makes this degradation legible rather than catastrophic.

## When this doc gets updated

The autoregressive structure: affordances move between categories only with explicit reasoning landed in the doc. A new affordance that's been deployed in production and proven safe might move from Forbidden → Optional. A new architectural commitment (e.g., a new principle) might move an affordance from Optional → Forbidden. The doc tracks these transitions explicitly because each one is a substrate-readiness signal.

Conditions that should trigger a revision:

1. **A new runtime is adopted.** If the substrate deploys on a new runtime (Bun, Fastly, self-hosted), the doc should be updated with the affordance availability for that runtime, even if the runtime meets the contract — the public record helps future deployment decisions.

2. **A required affordance proves harder than expected to implement portably.** If "every runtime must do Ed25519 envelope signing" turns out to exclude a runtime worth supporting, the question is whether to relax the contract or accept that the runtime is out of scope.

3. **A forbidden affordance is proposed for relaxation.** If someone proposes "let's let the worker sign drafts of receipts for performance reasons," the doc is what the proposal must justify against. The default answer is no; the proposal must move at least one architecture claim (Part I §2) closer to true without weakening any of the others.

4. **A new optional affordance is added.** Each addition extends the optional category and should be reasoned about — is it really optional, or does some part of the substrate now depend on it?

## Refs

- `docs/ARCHITECTURE-2026-04.md` §4c — *why* the gateway is incomplete by design (this doc's structural complement)
- `docs/ARCHITECTURE-2026-04.md` §4b — the cockpit-OS framing (categorical home of the edge tier)
- `docs/ARCHITECTURE-2026-04.md` Part V½ Principles 1, 3, 8 — the principles this contract structurally derives from
- `docs/handoffs/discipline-pin-audit-2026-06.md` — recommended pins, including `no_edge_signed_canonical_chain` for the forbidden category's first line
- `docs/handoffs/foundation-worker-chain-relocation-2026-06.md` — the architectural correction whose lessons drove this contract; the foundation-canonical-v1 instance is the empirical evidence for why the forbidden category needs to be explicit
- `docs/handoffs/foundation-worker-read-path-migration-design-2026-06.md` — the read-path migration that shaped the proxy-not-mediate constraint
- `docs/handoffs/delegation-lifecycle-2026-06.md` §3 — anonymous receipt routing as an optional affordance whose absence surfaced empirically
- `crates/zp-server/src/foundation_relay.rs` — the operator-side consumer of forwarded intents (the contract's substrate-side endpoint)
- `crates/zp-keys/src/foundation_edge_signer.rs` — Genesis-derived envelope key derivation (Required affordance #2)
- `zeropointfoundation.org/src/auth/forward.js` — current worker-side producer (the contract's edge-side implementation)
