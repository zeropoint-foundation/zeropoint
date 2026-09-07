# Signal Ingestion Plane

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.13 P7 (Contact
does not commit), §III.24 (Aligned blindness), and §III.19 (Detectability over
invulnerability). Specifies how the substrate reaches outward for external
signal — news, specs, regulatory movement, competitor behaviour — and turns what
it finds into chain-anchored candidates without letting the outside world write
to substrate state. Canonical claims live in KEEL.

Draft — 2026-08-11 — internal audience only. Composes with
`OBSERVATION-PLANE-2026-07.md` (of which this is the outward mirror),
`LENS-DISCIPLINE-2026-07.md` (ingestion is lens-scoped and emits
`lens:applied:*`), `AI-LANDSCAPE-SIGNAL-2026-07.md` (the first lens this feeds),
`COGNITIVE-INPUT-PLANE-2026-07.md` (findings reach Regent at Tier 2), and
`ARTIFACT-LIBRARY-2026-05.md` (candidate → signed lifecycle).

---

## 1. What this is

The observation plane watches the **host**: processes, network, filesystem,
credentials, application state. Six surfaces, delegation-gated, reach varying by
Substrate Form.

This is its mirror, pointed outward. The substrate reaches **the world** —
vendor announcements, protocol specs, regulatory text, research, the operator's
own curated media — and produces chain-anchored evidence of what it found and
when.

The two planes share a shape and differ in exactly one respect that governs
everything below: **the host is the substrate's own body, and the world is not.**
Observation of the host can inform action directly. Ingestion from the world
cannot, because the world is not trustworthy and the substrate has no authority
over it.

## 2. Why this document exists

Two failures, days apart, with the same root.

**The lens was starving.** `AI-LANDSCAPE-SIGNAL-2026-07.md` §7 declares the
`ai_landscape` lens and states plainly that its own silence is a defect signal —
*"Silent-ai-landscape-lens over a long observer window is a signal that substrate
work has drifted from external market pressure that once informed it."* Nothing
fed it. Its receipt semantics are still written conditionally (*"when
chain-anchored as a `lens:declared:ai_landscape` receipt"*), because there was no
mechanism to anchor them from. The corpus had specified an attention discipline
and nothing to exercise it — the shape of most defects found on 2026-08-06:
built, declared, unreachable.

**An unsourced strategy document arrived.** On 2026-08-11 a Cloudflare
agent-economy analysis landed asserting product behaviour and ZeroPoint
capabilities that neither its source nor the codebase supported. Its source was
one person's YouTube summary. Its ZP claims — multi-party atomic settlement,
programmable settlement contracts, on-chain audit trails — were written in the
present tense about things that do not exist. Auto-captions had mangled the
protocol name (`x402` → "X42") and the mangled form was carried forward.

Neither failure is about laziness. Both are about the absence of a mechanism
that makes provenance structural rather than a matter of the author's care.

## 3. P7 is the governing constraint

> **Contact does not commit** — reaching the world does not update the substrate.
> (§II.13, principle 7)

This principle has had little to do until now, because the substrate has rarely
reached outward. Signal ingestion is where it does its first real work, and it
decides the architecture:

**A fetch produces a candidate, never a fact.** Retrieving a page changes nothing
about what the substrate believes. It produces an artifact — content, source,
retrieval time, content hash — and that artifact is a *claim by an external
party*, chain-anchored as such.

**Nothing external is admitted as substrate truth without disposition.** A
candidate becomes something the substrate reasons from only via operator
signature, or via precedent already established by operator signature (§III.16,
act on precedent, escalate on novelty). This is `ARTIFACT-LIBRARY`'s
candidate → signed lifecycle, applied to material the substrate did not author.

**The chain records the reaching, not just the finding.** A sweep that found
nothing still emits evidence that it ran, over what ground. Otherwise "no signal"
and "no sweep" are indistinguishable — the ambiguity that let the lens sit unfed.

## 4. Structure

```
sources (declared, scoped)
    ↓  egress, delegation-gated
fetch → candidate artifact
    ↓  content hash + retrieval time + source
classification: shipped | announced | speculated | commentary
    ↓
lens filter (transformation_question)
    ↓
signal:candidate:* receipt          ← chain-anchored, not yet believed
    ↓  operator disposition, or precedent
signal:admitted:* / signal:rejected:*
    ↓
Cartographer materializes → Regent Tier 2 context
```

### Sources are declared, not discovered

The substrate does not crawl. It reads a declared source list — vendor blogs,
spec repositories, regulatory feeds, named media channels — and nothing else.
Adding a source is an operator act.

This is §III.24 pointed outward. The question is not "what could we usefully
read" but "what does an aligned substrate have any business ingesting on its
operator's behalf." General web crawling fails that test: it acquires far more
than the operator asked for, most of it about people who did not consent to
being read into a sovereign's chain.

### Egress is a gate class

Outbound network access is delegation-gated, `delegation:egress:<scope>`, in the
same shape as the observation plane's `delegation:observe:*`. Baseline is no
egress. A scope names its sources and its cadence. The gate refuses a fetch to a
host outside the granted scope, and the refusal is chain-anchored.

This matters beyond tidiness: a substrate that can fetch arbitrary URLs on a
schedule is a substrate that can be made to exfiltrate by anything that can
influence its source list. Scoping the reachable set is what keeps a research
mechanism from becoming a covert channel.

### Classification is part of the receipt

Every candidate carries `shipped | announced | speculated | commentary`. Not
editorial garnish — a structural field, because the Cloudflare document's core
failure was collapsing those four into undifferentiated assertion.

- **shipped** — verified against the vendor's own documentation as available
- **announced** — the vendor says it is coming
- **speculated** — a third party expects it
- **commentary** — someone's reading of someone else's claim

Commentary about a product is never promoted to a claim about the product
without an independent primary source. A creator describing a vendor's protocol
is commentary, however knowledgeable.

### Content hash pins what was seen

Pages change and are retracted. A receipt naming only a URL cannot support the
claim it was created to support. The candidate carries a hash of the retrieved
content, so a later reader can tell whether the source still says what the
substrate recorded — and, if it does not, that is itself a finding.

## 5. Aligned blindness, outward

§III.24 asks what an aligned substrate has no business observing. Applied to
ingestion, three classes stay out regardless of who would authorize them:

- **Other people's private material.** A sovereign's chain is not a place to
  accumulate third parties' personal data because it was technically reachable.
- **Credentialed content the operator has access to but the substrate has no
  business copying.** Read-for-the-operator is not ingest-into-the-chain.
- **Bulk acquisition.** The scoped-source rule is the mechanism, and the reason
  is that a corpus assembled without purpose is a liability with no offsetting
  benefit — toxic to hold, per the tier discipline in
  `INFORMATION-CUSTODY-TIERS-2026-08.md`.

Ingested material is **Tier 2 subject matter** in that model: the substrate must
reason over it, so it lives on the chain rather than the vault. It is not
secret. It is, however, *someone else's claim*, which is why classification and
content hash are structural.

## 6. Noise discipline

The whole value of an ingestion plane is that its signal stays trustworthy over
months, and the failure mode is well documented in this substrate's own history:
`degraded` posture became furniture because it never changed;
`unauthorized_listener` fired sixty times an hour for an unchanging host until
nobody read Sentinel at all.

Three rules, all learned the expensive way:

**A sweep that always finds something is inventing most of it.** Empty results
are recorded as empty. `_none_` is a valid and expected finding.

**Load-bearing is a high bar.** An item earns it only by pressuring a specific
substrate direction, named. "Interesting" is not load-bearing; it goes in the
adjacent or pattern tiers, which exist so that the top tier can stay honest.

**Silence is itself a signal, in both directions.** A lens with no applications
over a long window means the substrate has drifted from pressure that once
informed it — or the pressure abated and the lens should be retired. A source
that has produced no load-bearing item in months is costing a fetch a day for
nothing. The log records which source produced each finding, so the evidence for
pruning accumulates without anyone having to remember to gather it.

## 7. Composition with lens discipline

Ingestion is lens-scoped. Each sweep declares which lens it applies, and applies
that lens's `transformation_question` as the relevance filter.

Each run emits `lens:applied:<lens_id>:<invocation_id>` per
`LENS-DISCIPLINE-2026-07.md` §32 — which makes this plane the thing that keeps
lens-silence meaningful. Before it exists, a silent lens might mean drift or
might mean nobody ran anything. After, silence means drift.

The first consumer is `ai_landscape`. The mechanism is not specific to it:
`media_provenance` wants standards-body movement, and a future
`regulatory_landscape` lens would want primary legislative text.

## 8. Migration path

**Stage 0 — today.** A Claude-scheduled task (`zp-ai-landscape-sweep`, created
2026-08-11) runs the sweep and appends to `docs/review/ai-landscape-log.md`.
Nothing chain-anchored; the log can go stale silently. Adequate, and honest
about being interim.

**Stage 1 — egress delegation and a scheduling primitive.** ZP has periodic
machinery (officer sweeps, Cartographer, canary probes) but no operator-declared
schedule and no egress gate class. Both are prerequisites, and the scheduling
primitive is reusable well beyond this.

**Stage 2 — chain-anchored candidates.** The sweep emits `signal:candidate:*`
with source, hash, classification and lens. The markdown log becomes a
projection of the chain rather than the artifact of record.

**Stage 3 — disposition and cognition.** Operator dispositions candidates;
precedent accrues for classes that don't need a signature each time. Cartographer
materializes admitted signals; Regent reads them at Tier 2, so external pressure
reaches her reasoning instead of sitting in a file she cannot see.

Stage 3 is where this stops being a research digest and becomes part of how the
substrate thinks.

## 9. What this does not do

**It does not make the substrate believe things.** Ingestion produces candidates.
Belief requires disposition. P7 is the whole architecture.

**It does not verify truth.** Classification records *what kind of claim* a thing
is and who made it. Whether a vendor's shipped feature works as documented is
outside this plane's competence.

**It does not act.** No ingested signal triggers a substrate action. Findings are
advisory input to operator attention and Regent's context. The Governance Gate
stays atomic (§II.13 P8/P9) — the same non-conflation Aegis holds to.

**It does not crawl.** Declared sources only, and that is a constraint rather
than an implementation gap.

## 10. Verifiable outcomes

- **SI1** — a sweep that reaches zero sources still emits evidence that it ran
- **SI2** — a fetch outside granted egress scope is refused, and the refusal is
  chain-anchored
- **SI3** — every candidate carries source, retrieval time, content hash, and
  classification
- **SI4** — commentary is never promoted to a claim about a product without an
  independent primary source
- **SI5** — no candidate becomes substrate-canonical without operator signature
  or cited precedent
- **SI6** — `lens:applied` fires per run, so lens silence means drift rather than
  absence of mechanism

## 11. Connects to

**§II.13 P7 (Contact does not commit)** — the architecture. Reaching the world
produces candidates, not facts. This plane is where a principle with little
prior work to do acquires its first real load.

**§III.24 (Aligned blindness)** — pointed outward. Declared sources rather than
crawling, and three refused classes regardless of authorization.

**§III.19 (Detectability)** — recording the reaching and not only the finding is
what makes an empty sweep distinguishable from an absent one.

**The observation plane** — same delegation shape, same receipt discipline, same
refusal to act on what it sees. Inward and outward halves of one sensory
architecture.

**`INFORMATION-CUSTODY-TIERS-2026-08.md`** — ingested material is Tier 2 subject
matter, on the chain because the substrate must reason over it, carrying
provenance because it is someone else's claim rather than the substrate's own
observation.

**`METACOGNITIVE-FIDELITY-HARNESS-2026-08.md`** — that harness asks whether the
substrate's claims about *itself* are accurate. This asks the same of its claims
about *the world*. Together they cover both directions in which a substrate can
believe something untrue.
