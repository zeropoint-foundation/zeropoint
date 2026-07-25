# Context Sharding and Salting for Regent Inference Routing — July 2026

**Document type:** Design note. Specifies a structural defense against provider profiling — the Regent shards outbound inference across providers and injects plausible-but-false salt queries so no single provider can reconstruct what the operator is actually working on. This is not a privacy overlay applied to existing routing; it's a structural change to how inference gets requested and assembled.

**Status:** Design draft.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-08.

---

## Part I — What This Is

The Regent routes outbound inference to external providers when local inference is unavailable or unsuitable. Each request reveals context to that provider. Over time and across requests, providers accumulate enough context to reconstruct what the operator is working on, who they're talking to, what decisions they're making. Even with strong provider trust postures — retention limits, deletion promises, third-party audits — the underlying capability to profile remains, and the operator's sovereignty is only as strong as every provider's ongoing willingness to not exercise that capability.

Sharding and salting attack the capability directly. Sharding splits queries so no single provider sees a complete picture. Salting injects plausible-but-false queries so what a provider does see is mixed with noise indistinguishable from signal. Together they make profiling structurally difficult rather than merely policy-restricted — a much stronger defense.

This is not privacy through obscurity. The mechanisms are documented, the chain records what got sharded where. Adversaries knowing the design don't gain much because the strength is structural, not secret.

---

## Part II — Threat Model

Six specific threats the system defends against.

**Direct profiling.** A provider builds a dossier on the operator by aggregating queries over time. The operator's substrate becomes legible to the provider even without the operator sharing anything explicit — the pattern of queries alone is enough.

**Cross-request linkage.** Providers correlate queries within a session or across sessions, building a running model of what the operator is thinking about. Even with API-key rotation, patterns of query timing, phrasing, and content leak identity.

**Compelled disclosure.** Subpoena, warrant, or government request causes a provider to hand over stored queries. What's compellable is what was sent; nothing else. Reducing what gets sent to any one provider reduces disclosure surface directly.

**Insider access.** Rogue employee, log leak, misconfigured storage — same shape as compelled disclosure. Reducing exposure surface at each provider reduces breach surface too.

**Training on queries.** Providers use queries as training data with or without operator consent depending on provider posture and jurisdiction. Sharding means no single provider's training corpus contains the operator's coherent context.

**Downstream inference.** A sufficiently sophisticated provider can infer things about the operator from the pattern of queries, not just their content — timing, frequency, topic distribution. Salting attacks this specifically by injecting misleading patterns.

The threat model is not that any one provider is malicious. It's that the aggregate capability of external providers to reconstruct operator context is structurally uncomfortable regardless of any individual provider's posture. The defense makes the structural capability weak.

---

## Part III — Context Sharding

The Regent decomposes an outbound inference request into subqueries, each independently answerable, and routes them to different providers. Local assembly produces the final answer. No single provider sees the full query.

Four decomposition strategies:

**Semantic decomposition.** Split by topic. A policy analysis touching regulatory, financial, and reputational dimensions goes as three subqueries to three providers. Local assembly weaves the three responses over the operator's actual context.

**Temporal decomposition.** Split by time slice. Historical context to one provider, current state to another, projected implications to a third. Each provider sees a slice of the trajectory but not the arc.

**Role decomposition.** Different subqueries phrased as different personas — a strategist asking one thing, an analyst asking another, a critic asking a third. Provider-visible identity differs per subquery; no persistent operator persona forms across providers.

**Referent obscuration.** Replace specific names, places, and dates with tokens. The provider sees "Party A negotiating with Party B over Instrument X"; the local Regent knows who A and B are and reassembles the response over real referents.

The Regent decides per query which strategy applies, or which combination. The decision draws on the query's structure, the sensitivity classification the operator has attached to the underlying context, and the current provider-rotation state. Provider selection composes with existing mandate scope — a subquery only goes to a provider the operator has authorized under the query's capability scope.

Some queries can't be sharded. A query that genuinely requires holistic context to answer correctly is one the Regent recognizes and either falls back to local inference (M4-hosted Ollama when available), asks the operator to confirm the un-sharded exposure explicitly, or declines with a clear reason. Sharding when it's structurally impossible produces bad answers; the Regent's job is to know the difference.

Chain receipts record the sharding decision — which subqueries went where, which strategy applied, which providers received what. The chain is truth; the substrate can always reconstruct what was actually revealed.

---

## Part IV — Salting

The Regent injects plausible-but-false queries into the outbound stream. Salt queries look like real operator queries but describe things the operator isn't actually working on. Providers see a corpus of real signal mixed with plausible noise; no provider can distinguish salt from real, so no provider can build an accurate model.

Four properties salt queries must have.

**Plausible.** A salt query about market analysis in a domain the operator has never engaged should still look like something a person with the operator's rough profile might ask. Implausible salt is filterable and defeats the point.

**Diverse.** Salt spans topics the operator isn't working on. If all salt clusters around one domain, that domain gets classified as noise by the provider and the operator's real queries stand out. Spread thin.

**Rate-limited.** Salt costs tokens. The budget is bounded — a fraction of the operator's real inference spend, tunable. Aegis observes salt spending and surfaces if it drifts.

**Non-harmful.** Salt never generates content that would violate constitutional rules if it were real. The Regent isn't allowed to route real queries that would cause harm; salt inherits the same constraint. Salt is misleading, not weaponized.

Salt is generated by a lightweight local model — the Regent's own reasoning surfacing plausible-but-false contexts. The chain marks each salt query as salt; the substrate never confuses salt for signal. Provider-side, real and salt are indistinguishable.

Rotation matters. Salt queries get distributed across providers so no single provider gets an unrepresentative slice. Real queries also rotate. Over long time horizons, each provider's view of the operator is a shifting mix of real fragments and salt — legible enough to answer specific questions, insufficient to reconstruct the operator's trajectory.

---

## Part V — Fit into the Regent Architecture

Sharding and salting compose with the Regent's existing inference routing rather than replacing it. Three integration points.

**Mandate scope.** Provider routing already runs under mandate scope — the operator authorizes which providers can receive which capability classes of query. Sharding respects this: each subquery routes only to providers the operator has authorized for that subquery's capability. Salt runs under a specific salt-inference mandate the operator issues explicitly, with its own budget and rotation policy.

**Gate authorization.** Every outbound inference request passes the gate. Sharding produces multiple outbound requests per operator query; each passes the gate independently, receiving its own signed receipt. Salt queries pass the gate too, tagged as salt on the chain so the substrate can distinguish them retrospectively even though the provider cannot.

**Officer integration.** Aegis observes the sharding and salting stream for coherence — is salt getting distributed evenly, is any provider receiving a suspiciously coherent slice of real queries, is the token budget staying within the operator's declared bounds. Sentinel watches for provider-side signals that suggest profiling attempts. Cleo narrates sharding and salting decisions to the operator on request; the operator can see what got sent where and adjust routing policy from there.

Chain receipts are the source of truth. Every sharding decision, every salt generation, every provider selection produces a receipt. The chain records what actually happened; the substrate can always reconstruct the operator's real trajectory from the local chain even though no external provider can.

---

## Part VI — Invariants

Seven invariants the system preserves regardless of routing decisions.

The full answer never composes at any external provider. Assembly is always local.

The chain of truth is local. Providers see fragments and salt; the substrate knows what was real, what was salt, and how the fragments compose. The operator's own reasoning stays sovereign.

Constitutional rules apply to every outbound query — sharded or not, real or salt. Sharding doesn't create a bypass; salt doesn't get an exemption.

Salt never impersonates the operator's sovereign identity. Salt queries use anonymous or ephemeral personas; Genesis-derived identity is never used to send salt.

Provider linkage identifiers are stripped. No shared request IDs, session tokens, or metadata that would let one provider correlate its queries with another's.

Local inference is preferred when available. Sharding and salting defend against provider exposure that has to happen; they don't make provider exposure attractive. If M4-hosted Ollama can answer, that's the first choice.

Operator visibility is preserved. The operator can query the chain for exactly what got sharded, salted, and routed to where. No hidden decisions, no invisible spending. The mechanism is legible to the operator even though it is opaque to providers.

---

## Part VII — Constraints

Three practical constraints the design lives inside.

**Cost.** Sharding multiplies request count. Salting adds requests that produce no operator value. Both are budget-bounded and the budget is operator-controlled. Sharding budget scales with sensitivity classification; salt budget is an explicit tunable with a default fraction of real inference spend.

**Latency.** Sharded queries add coordination overhead — parallel requests, local assembly, occasional retries if one subquery fails. The Regent bounds this and falls back to un-sharded routing (with operator notification) if the latency envelope would be violated.

**Provider capability.** Not every provider is equally capable at every subquery type. Sharding respects capability matching — a subquery requiring code understanding goes to a provider strong at code, even if that constrains the rotation. Capability matching composes with sensitivity classification and mandate scope in the routing decision.

---

## Part VIII — Composition

- MULTI-DEVICE-OPERATION-2026-07.md — sovereign identity structure that salt must never impersonate.
- REGENT-COMPARTMENTALIZATION-2026-07.md — the compartmentalization discipline this extends across providers rather than across operator projects.
- TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md — Aegis's role in observing sharding and salting patterns for coherence and drift.
- SECURITY-SIGNAL-CHANNEL-2026-07.md — the channel over which Sentinel would surface provider-profiling detection findings if they emerged.
- ARCHITECTURE-2026-07.md — the mandate and gate primitives this composes with.
- ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md — the local-side counterpart; sharding defends outbound, encrypted storage defends at rest.
