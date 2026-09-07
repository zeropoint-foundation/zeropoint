# Trust-Root Locus — Lens Declaration

**Lens declaration — not a Tier-2 canonical elaboration.** A first-class lens instance under `LENS-DISCIPLINE-2026-07.md`, which is where the primitive itself is canonically specified (elaborating `KEEL-2026-07.md` §II.17, §III.19, §III.22 and Part V). This document elaborates no KEEL claim of its own: per the corpus index's *Design intent / opportunity mapping* rule it is an **outside-in attention lens for downstream spec work**, sitting beside `AI-LANDSCAPE-SIGNAL-2026-07.md` rather than beside `OFFICER-LENS-DECLARATIONS-2026-07.md`, which is inside-out. It nominates; it never canonizes. Canonical claims live in KEEL.

**Established 2026-08-14** by splitting `lens:declared:ai_landscape` (E12 from `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Signal 5"). Direction: **outside-in**.

---

## 1. Why this is a separate lens

The `ai_landscape` lens was declared 2026-07-21 around inference economics, model tiers, provider concentration and capability distribution. Its transformation question asks whether a substrate direction *remains load-bearing* under multi-provider disruption, cost inversion and attack-surface expansion. That question is about **survival under market pressure**.

Through 2026-08 the same feed began returning a different class of item: IETF drafts specifying delegation attenuation, vendor programmes signing capability artifacts, authorization languages enforcing policy with an audit trail from clause to control. These are not market dynamics. They are the industry building the mechanisms this substrate is built on — and rooting every one of them in an institution rather than in the principal.

Asking that class of item the `ai_landscape` question produces the wrong answer. "Does this direction remain load-bearing?" invites *yes, and look, they agree with us* — which is how a requirements document that diverges from ZeroPoint on the sovereignty question nearly entered the corpus as convergence (see `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Signal 5", and the rule-6 caution in the 2026-08-14 sweep entry). The question this class of item needs is different, and a lens that asks the wrong question of an item is worse than no lens, because it produces a confident reading.

Two subjects, two lenses. The split is the correction.

## 2. Formal lens declaration

- **`lens_id`**: `trust_root_locus`
- **`focus`**: where trust is rooted, at each layer of an agentic stack, as external standards bodies and vendor programmes converge on mechanisms ZeroPoint already implements
- **`dimensions`**: trust-root locus (operator / institutional / vendor); delegation-vocabulary convergence; capability-artifact signing and admission; offline verification and revocation staleness; standards-venue trajectory (individual draft → working-group adoption → RFC, or expiry); external legibility — whether a stranger could score ZeroPoint against this vocabulary; differentiation under convergence
- **`keyword_composition`**: [delegation, attenuation, narrowing, scope reduction, trust root, root of trust, trust anchor, capability admission, admission ceremony, signed artifact, artifact signing, attestation, skill card, provenance record, relying party, revocation, offline verification, staleness, principal, sovereign identity, agent identity, standards venue, Internet-Draft, working group, specification, conformance, interoperability, vendor certificate, registry, catalog]
- **`transformation_question`**: *"the industry is building this mechanism — where does it root it, and does that leave the substrate's position differentiated, merely legible, or duplicated?"*
- **`cross_references`**: `SUBSTRATE-FORM-2026-07.md` §"Trust-chain reach is stated per layer" · `EXTENSION-SURFACE-2026-07.md` · `QUARANTINE-PLANE-2026-07.md` · `SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` §3 · `CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md` · `MEDIA-PROVENANCE-INTEROP-2026-07.md` · `LENS-DISCIPLINE-2026-07.md` · `SIGNAL-INGESTION-PLANE-2026-08.md` · `AI-LANDSCAPE-SIGNAL-2026-07.md`

**The three outcomes the transformation question sorts into**, which is the whole reason for asking it in this shape:

- **Differentiated** — the mechanism converges and the root does not. Record the divergence, not the agreement. This is the common case so far.
- **Legible** — an external vocabulary now exists against which ZeroPoint can be scored by someone who has never heard of it. Worth more than an internal falsifier; adopt the vocabulary, do not adopt the position. `SUBSTRATE-CONFORMANCE-CONTRACT` §3's R1/R3/R7/R8 note is the first instance.
- **Duplicated** — someone has built the same thing on the same root. Not yet observed. If it is ever observed, it is the most important finding this lens can produce and it should be escalated rather than logged.

## 3. Composition and boundary with `ai_landscape`

Declared: **`lens:composed:ai_landscape:trust_root_locus`**. The two share sources (the same sweep feeds both), share a source discipline, and will regularly see the same document. They are composed, not conflicting: no transformation either prescribes contradicts the other.

The boundary rule, so that items are not silently claimed twice or dropped between them:

| Item is about | Lens |
|---|---|
| Inference economics, model tiers, provider concentration, capability distribution, cost/latency, disruption risk | `ai_landscape` |
| Mechanism and where it roots — delegation, admission, attestation, verification, revocation, identity | `trust_root_locus` |
| Both (a vendor programme that is simultaneously a market move and a trust-root claim) | `trust_root_locus`, cross-referencing the market reading |

The last row is deliberate. When an item is genuinely both, the root question is the one more easily lost, because the market reading is the easier and more familiar one to write.

## 4. Standing finding this lens inherits

Carried forward from three sweeps (2026-08-13, -14) so the lens starts with a stated prior rather than a blank:

> Across `draft-reece-wimse-cross-org-delegation`, `draft-niyikiza-oauth-attenuating-agent-tokens`, `draft-liu-oauth-chain-delegation`, `draft-mcguinness-oauth-actor-profile`, the AIP drafts and OIDC-A, the same three properties are repeatedly specified — narrowing a relying party can verify from the credential alone, a principal binding intermediaries cannot alter, and audit that composes across parties. **Not one roots the chain in the human principal's own key.** The root is always the organisation's anchor, and the principal is a claim carried inside it. The same shape appears one layer up, where capability artifacts are signed against a vendor certificate and catalogued by that vendor, and one layer sideways, where policy-to-enforcement languages enforce policy authored by whoever operates the platform.

**The falsifier, stated so it is recognised if it arrives:** a draft, specification or shipped programme that roots the chain in the principal's own key. That single observation would move this lens's standing finding from *differentiated* to *duplicated* and is the thing worth watching for above all else. Three sweeps have seen none.

Per `SUBSTRATE-FORM` §"Trust-chain reach is stated per layer", the layers to score independently are **boot**, **capability admission**, and **delegation verification**. An item that settles one says nothing about the other two.

## 5. Invocation, silence, and receipts

Standard per `LENS-DISCIPLINE` §2. A work context matching the keyword composition emits `lens:applied:trust_root_locus:<invocation_id>`; the declaration anchors as `lens:declared:trust_root_locus`; the composition edge above anchors as `lens:composed:ai_landscape:trust_root_locus`.

Silence semantics differ from `ai_landscape` and are worth stating, because the two lenses fail differently. Silence on `ai_landscape` over a long window means market pressure abated or the substrate stopped attending to it. **Silence on this lens most likely means the sweep stopped reading standards venues** — the class of source that produces its items is narrow, slow, and easy to skip, and two of the three items that motivated this declaration were May and June publications found only by going to a datatracker and a vendor engineering blog and reading. A quiet quarter here should trigger a deliberate backfill pass over IETF, W3C, C2PA/CAWG, OpenID Foundation, DIF and NIST before it is read as the convergence having stopped.

## 6. Source discipline

Inherited unchanged from `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Source discipline", with one addition specific to this lens: **standards-venue documents carry their own standing on their face and it must be recorded.** An individual Internet-Draft is one author's submission and is not a working-group product; a working-group draft is not an RFC; an RFC is not deployment. The 2026-08-14 sweep recorded `draft-reece-wimse-cross-org-delegation` as an individual draft with no formal standing, which is why its requirement set entered the corpus as a *scoring vocabulary* rather than as a standard the substrate must meet. Any later item that omits this is mis-recorded.

## 7. What this lens does not do

- It does not adopt external positions. Adopting a vocabulary to be scored against is not adopting the root that vocabulary assumes.
- It does not make ZeroPoint chase mechanism parity. The mechanisms are being built well by organisations with more engineers; the substrate's position is the root, not the mechanism.
- It does not produce canon. Like `ai_landscape`, items land as briefs that *nominate* edits; edits land through their own review.
