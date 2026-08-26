# KEEL Amendment Proposal — Root-Authority Locus as Axis of Differentiation

**Status:** Proposal, not enacted. This is a proposed amendment to KEEL Layer A. Layer A amendments require canonicalization ceremony + substrate binary release per KEEL III.6; this proposal defines the amendment language and the ceremony's decision surface, but does not perform either.
**For:** ZeroPoint operator (Ken) evaluating whether the §11 root-authority reduction from the TC260 comparative analysis (commit `258cd73`) earns Layer A invariant status.
**Companion to:** INTENT-CRYSTALLIZATION-PRIMITIVE-2026-08 (drafted with — or that would be drafted with — this amendment's discipline in force), Buildout tab Rank 1 sub-piece 3.1 on the substrate-maturity dashboard.
**Origin:** Seven TC260 primary-read passes 2026-08-20 produced the §11 reduction — *"the substrate architecture is the same shape; the difference is where the authority chain terminates."* Operator direction 2026-08-20 sequenced this into the Buildout roadmap as Rank 1 sub-piece 3.1. Operator direction 2026-08-21 confirmed drafting under the crystallization primitive's discipline once that primitive is in force.

---

## 1. What this amendment proposes

Add a new invariant to KEEL §II (Layer A invariants), naming **root-authority locus** as the axis of the substrate's differentiation. The eight currently-scattered Layer A properties that name specific substrate features (Genesis root, aligned blindness, coordination-not-oversight, sovereign fleet, delegation narrowing, chain-anchored discipline, forward-only recovery, detectability) become *derivations* from the one root claim rather than eight independently-asserted invariants.

Proposed slot: **§II.20** — after the existing II.5 (Genesis-as-single-root), II.9 (two-layer architecture), II.13 (nine design principles), II.14 (canonical substrate form), II.15 (substrate boundary planes), II.17 (chain-anchored discipline), II.19 (the current final invariant). §II.20 is the invariant that anchors the others.

Amendment language proposal, verbatim shape:

> **§II.20 — Root-authority locus.** The substrate's architectural differentiation is at the locus where the authority chain terminates. The substrate terminates authority at *sovereign-operator-Genesis*; institutional-root alternatives terminate authority at *multi-agency-composite regulatory registration*. Every other Layer A invariant that names a specific property of the substrate is a consequence of the axis being drawn at sovereign-operator-Genesis rather than at institutional root.
>
> The substrate's differentiation cannot be preserved by adopting institutional root and defending the downstream properties independently. The downstream properties are not enforceable without the axis being at sovereign root:
>
> - Aligned blindness (§III.24) cannot be enforced under regulator-inspection authority — the regulator can compel observation the substrate would refuse.
> - Coordination-not-oversight (§III.23) cannot be enforced when an oversight body has structural authority to compel — coordination without a coordination-authority requires no coordination-authority to exist above sovereign roots.
> - Sovereign fleet (§III.15) cannot be enforced when device onboarding routes through institutional registration — the fleet is one-substrate because a single sovereign root binds it, not because the devices agree to cooperate.
> - Genesis-as-single-root (§II.5) is definitionally at odds with institutional root — the amendment does not add this claim, it restates §II.5 as a consequence of §II.20.
> - Delegation narrowing (§II.4) requires no external appeal authority — narrowing is a sovereign act.
> - Chain-anchored discipline (§II.17) terminates signatures at sovereign root — institutional root would ground signatures at institutional key hierarchies.
> - Forward-only recovery (§III.20) requires the sovereign to hold the sole authority to sign recovery ceremonies — regulatory rollback authority would break this.
> - Detectability over invulnerability (§III.19) is only load-bearing if the sovereign is the sole authority that can *act on* detections; regulator-directed action would relocate the detection surface.
>
> The axis IS the substrate. Adopting the same properties under institutional root would produce architecturally similar but categorically distinct system. §II.20 names the axis explicitly to prevent Layer B compositional work from drifting into institutional-root adoption disguised as adapter interoperability.

Reflexivity clause:

> This amendment is itself an act performed under §II.20 — the operator signs the amendment; no external body has authority to enact or veto Layer A invariants. The amendment names the axis that authorizes the amendment. This is not circularity; it is fixed-point discipline consistent with §II.5's Genesis-as-single-root and the Foundation's peer-not-authority framing (§IV.1).

## 2. Why now

The corpus has been operating *as if* §II.20 were an invariant since KEEL 2026-07. Every downstream Layer A claim listed above was drafted with implicit reference to sovereign-root; every Tier-2 elaboration that composes with them assumes the reference. The reference has been *tacit*, not explicit. Tacit invariants are exactly what the substrate's own detectability discipline (§III.19) says to refuse: an invariant is either explicit and testable, or not an invariant.

The tacit period was tolerable while ZP was the only substrate reaching for these properties. Seven TC260 primary-read passes 2026-08-20 established that the Chinese apparatus is now reaching for architecturally identical substrate properties (chain-anchored discipline via CAC 《实施意见》 clause 7, three-tier delegation via clause 6, multi-agent cascade bounding via TR-005 AIA06, cognitive substrate first-class treatment via TR-004 认知安全) — but reaching for them under institutional root rather than sovereign root. The apparent convergence at the substrate-architecture level is real; the difference at the root-authority level is the *only* substantive delta. If ZP does not name this delta explicitly, the convergence becomes indistinguishable from adoption, and Layer B work will drift toward compositions that quietly relocate the axis to institutional root under the guise of interoperability.

Making §II.20 explicit converts the delta from tacit-and-vulnerable to explicit-and-enforceable.

## 3. What the amendment does not do

- Does not prevent Layer B composition with institutional-root regimes. Adapter substrate work (Buildout Rank 1 sub-piece 3.2, and Candidate 1 MEDIA-PROVENANCE-INTEROP six-layer) remains permissible and desirable. Layer B adapters compose with institutional-root regimes at the *interface* layer without relocating the *root* layer.
- Does not repudiate existing composition work. Everything the corpus has produced remains valid; §II.20 makes explicit the axis those compositions have already assumed.
- Does not require peer substrates to hold the same invariant. Peers may enact §II.20 via their own ceremonies or choose not to. KEEL Part VII peer-verification composes across the choice — verifying a peer at their sovereign root does not require the peer's root to match ours in schema, only in terminating at sovereignty rather than at institutional composite.
- Does not amend §II.5 (Genesis-as-single-root); §II.5 becomes a *derivation* from §II.20 rather than an independent invariant, but its enforceable content is unchanged.
- Does not amend §III (Layer B canonical claims). Individual §III invariants gain "derives from §II.20" annotations but their normative content is unchanged.
- Does not add new receipt schemas. §II.20's activity is entirely at the Layer A invariant level; Layer B receipts already carry the sovereign-root signature that §II.20 makes explicit.

## 4. Ceremony surface (deferred to a companion ceremony doc)

Enacting §II.20 requires the standard KEEL Part VI two-layer amendment ceremony:

1. Operator primary read of the amendment language above
2. Disconfirming-observation check (see §5 below)
3. Chain-anchored operator signature emitting `keel:layer_a:amended:v1` with amendment-doc hash
4. Substrate binary rebuild encoding §II.20 as a compiled invariant
5. Substrate binary release through the standard release chain
6. Post-release: existing §II.5 and the eight §III derivations gain "derives from §II.20" annotations in `docs/KEEL-2026-07.md` (or in whatever KEEL successor document is current at post-release time)

Steps 4-5 are heavier than the Layer B canonicalization ceremonies for INTENT-CRYSTALLIZATION and STANDING-IMPASSE (those enact via chain-anchored signature alone, no binary rebuild). This is intentional: Layer A changes cost substrate release; that cost is the substrate's own honesty about the difference between invariant and canonical claim.

The full ceremony spec is deferred to a future companion ceremony doc — not yet written — if operator direction advances this proposal past disconfirmation. That doc, once drafted, would follow the pattern established by the two Layer B ceremony docs already in the corpus (INTENT-CRYSTALLIZATION-CEREMONY-2026-08 and STANDING-IMPASSE-CEREMONY-2026-08), extended for KEEL Part VI two-layer amendment discipline.

## 5. Disconfirming observations

If any of the following hold, the amendment should be rejected or radically reshaped:

**(a)** The eight downstream properties are actually *independent* invariants, not derivations from a single root axis. If each can be enforced under institutional root (with sufficient regulatory design), then §II.20 is a categorical claim the substrate has no basis for. **Rebuttal test:** find one downstream property that remains enforceable under institutional root. Aligned blindness under regulator-inspection authority is the primary counterexample to look for — if some regulatory design authentically preserves the substrate's refusal to observe certain classes, then §III.24 is enforceable across the root-authority axis and §II.20 is over-claimed.

**(b)** The TC260 comparative analysis's §11 reduction is over-general. If the reduction only holds within the CAC/TC260 track and not across the broader Chinese apparatus (MIIT, CACR, GB standard families), then the delta is less structural than §II.20 claims. **Rebuttal test:** find a Chinese-apparatus substrate property that does not reduce to the root-authority axis. The comparative doc's four MIIT stress-test corroborations (§Appendix A.4) and five-tier statutory chain stress-test (§Appendix A.7) suggest no such property exists, but a targeted new primary-read pass could produce a counterexample.

**(c)** Fixed-point discipline collapses on inspection. If naming the axis under which the amendment is authorized is actually circular (rather than fixed-point) — if §II.20 is asserting its own authority by fiat — then the amendment fails the Foundation's peer-not-authority framing and should be rewritten to derive from an already-canonical Layer A claim. **Rebuttal test:** identify a Layer A claim that authorizes §II.20 without §II.20 authorizing itself. If none exists (as expected — this is fixed-point rather than circular), the amendment stands.

**(d)** The amendment forecloses Layer B work that would otherwise be permissible. If naming the axis explicitly prevents adapter substrate scaffolding from composing with institutional-root regimes in ways that would otherwise be architecturally sound, the amendment is over-constraining. **Rebuttal test:** identify a Layer B adapter shape that would be permitted without §II.20 and would be forbidden by it. Sub-piece 3.2 (adapter framework) is the immediate target; if drafting that framework runs into §II.20's constraint in a way that breaks the composition, the amendment needs revision.

## 6. Reflexivity check

If §II.20 were in force during the drafting of *this proposal doc*, what would have been different? Nothing about the language of §II.20 itself — it names an axis the substrate had already implicitly committed to. What changes is the *epistemic status* of the proposal: without §II.20 in force, this doc is *proposing* an axis; with §II.20 in force, this doc is *documenting* an axis that is already binding. That epistemic distinction matters because Layer A amendments are permanent (via §III.20 forward-only recovery); a proposal explicitly names its own tentativeness, an active documentation does not.

The doc is currently structured as a proposal because §II.20 is not in force. If the operator canonicalizes §II.20, this doc's status header updates to "Amendment enacted 2026-XX-XX at chain-position N; this doc's status is now historical documentation of the enactment."

## 7. Non-goals

- Not a strategic reveal. §II.20 makes explicit what was already architectural; nothing about the substrate's competitive positioning changes on the day of enactment. What changes is that Layer B work henceforth composes against an explicit invariant rather than a tacit one.
- Not a positioning claim against specific competitors. §II.20 does not name Google, OpenAI, Anthropic, or the Chinese apparatus. It names the axis; other apparatus may fall on either side of it by their own architectural choices, and the axis is neutral about which side is "better" — it is only load-bearing that the substrate has chosen sovereign-root and refuses drift toward institutional-root.
- Not a peer-verification schema change. Part VII peer-verification composes across the axis; peers do not need to hold §II.20 for verification to succeed.
- Not a foundation-role change. §IV.1 (Foundation as peer-not-authority) is unchanged; §II.20 makes the Foundation's peer-status *require* sovereign-root architecture rather than merely permit it.

## 8. Composition with Buildout roadmap

Once §II.20 is enacted (Rank 1 sub-piece 3.1 advances from `spec` to `ok`):

- **Sub-piece 3.2** (adapter substrate scaffolding) becomes the concrete verification of §II.20's non-foreclosure claim (§5(d)). If the adapter framework composes cleanly with institutional-root regimes while §II.20 is in force, §5(d) is empirically refuted and §II.20 stands. If the adapter framework encounters §II.20 as a genuine obstacle, either the framework needs redesign or §II.20 needs revision.
- **Sub-piece 3.3** (public thesis) becomes a legibility exercise rather than a positioning claim. The thesis says *"here is the axis; the substrate is on this side of it; other substrates are on the other; the axis is the delta"* — and the thesis writes itself because the axis is already invariant.
- **Rank 2** (STANDING-IMPASSE canonicalization) is unaffected by §II.20; the primitive is Layer B and does not reference the root-authority axis.
- **Rank 3** (MEDIA-PROVENANCE-INTEROP six-layer) becomes the first concrete Layer B composition that must reconcile with §II.20. GB 45438 metadata schema, CAC 《标识办法》 Article 5 implicit marking, and Article 6 platform verification all route through institutional root; the six-layer composition must implement adapter-plane discipline that composes with them without relocating ZP's root.

## 9. Deliverable shape for the fresh session that picks this up

If Ken advances the proposal past disconfirmation, the fresh session should:

1. Read this doc, the TC260 comparative analysis (`docs/research/tc260-vs-zeropoint-comparative-2026-08.md`, especially §11 and §Appendices A.5-A.7), and `docs/KEEL-2026-07.md` §II in full.
2. Draft a companion ceremony spec (naming convention to be decided at drafting time — not yet written) per KEEL Part VI two-layer amendment ceremony discipline.
3. Draft the substrate-binary rebuild plan: which compiled crates encode Layer A invariants, and what compile-time assertions become active under §II.20.
4. Draft the annotation patch to `docs/KEEL-2026-07.md` adding "derives from §II.20" notes to §II.4, §II.5, §III.15, §III.19, §III.20, §III.23, §III.24, and P1.
5. Draft the disconfirmation trial harness: concrete tests corresponding to §5(a)-(d). If any test would fail, the amendment does not proceed to substrate release.
6. If crystallization primitive (Rank 0) is enacted by then, apply crystallization discipline reflexively — did the intent for this specific ceremony crystallize before drafting began? If not, use the shaping repertoire to bring it into focus first.

## 10. One conversation piece worth preserving

The §11 reduction sentence, verbatim from `docs/research/tc260-vs-zeropoint-comparative-2026-08.md`:

> *Between ZeroPoint and the emerging Chinese agent-standardization apparatus, the substrate architecture is the same shape; the difference is where the authority chain terminates, and every other apparent difference is downstream of that root.*

That sentence was produced after seven primary-read passes and stress-testing at three scales (intra-Chinese CAC/TC260 vs MIIT, intra-regulation Order No. 9 → 15 → 12, intra-branch generative vs personalization/ranking/filtering/scheduling). It has not been refuted. §II.20 is that sentence restated as an invariant rather than an observation.

The three-turn crystallization arc — operator selecting Candidate 3 sequence 3 → 2 → 1, then observing "intent CAN have a receipt — except it has to actually come into focus first," then confirming "explicit shaping is what I'm reaching for" — is the substrate's own crystallization moment around the shape of what this amendment IS. That arc is preserved as historical context in the INTENT-CRYSTALLIZATION-PRIMITIVE-2026-08 doc's §11; readers of this amendment should read that arc before proceeding to disconfirmation.
