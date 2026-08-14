# Proposed Edits — AI Landscape Signal (2026-07)

Companion to `AI-LANDSCAPE-SIGNAL-2026-07.md`. Round one (2026-07-21): five additive edit blocks, one per affected Tier-2 doc. Round two (2026-08-14, at the end of this file): four more, from Signal 5. Each is additive (append/insert; no existing prose rewritten) and cites the signal brief so the reasoning trail is walkable.

**Status (2026-07-21):**

| Edit | Target | Status |
|---|---|---|
| E1 | INFERENCE-ROUTING-DISCIPLINE | **APPLIED (2026-07-22)** — data-backed by the APOLLO benchmark; measured note appended to the doc |
| E2 | DEPENDENCY-POSTURE | **APPLIED (2026-07-22)** — data-backed by the APOLLO benchmark; measured note appended (hedge → measured baseline) |
| E3 | SUBSTRATE-HARDENING-CEREMONY | **APPLIED** — additive external-signal note appended |
| E4 | SOVEREIGN-KINSHIP-PRIMITIVES (+ DEPENDENT-SOVEREIGNTY xref) | **APPLIED** — scenario note appended; the `kinship:challenge:*` primitive-vs-composition question remains an open design decision |
| E5 | CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS | **APPLIED** — additive external-signal note appended |

The blocks below are retained as the authored source of the applied notes and the held nominations.

Convention followed: the corpus already carries dated inline motivations ("Amended 2026-07-18 following SLM failure-mode analysis"; "Motivated 2026-07-18 by Nikon…"). These match that pattern with a 2026-07-21 external-signal citation.

---

## E1 — `docs/design/INFERENCE-ROUTING-DISCIPLINE-2026-07.md`

**Where:** end of the `## Framing` section (after the three-properties list), or as a note under `### Routing policy: the precedent bright-line`.

**Insert:**

> **External-signal note (2026-07-21).** The Kimi K3 open-weights release is a market data point on the *local-frontier floor* the substrate has been treating as empirically unknown (KEEL glossary, *inference-sourcing*). Reaching near-frontier capability with an open model now means a large, expensive-to-serve model (~64 accelerator cores cited for top performance; ~$15/M output tokens; lower token-efficiency than frontier proprietary) — a corporate footprint, not a home one. This reinforces the precedent→SLM / novelty→LLM bright-line as the *economic* answer, not only the capability answer: the substrate does not attempt frontier-class general reasoning locally: it runs stable, precedent-shaped work on cheap local SLMs and reserves rally/cloud budget for genuine novelty. The "cheap efficient open model at the frontier" assumption is false; the discipline already assumes it. See `AI-LANDSCAPE-SIGNAL-2026-07.md` §1.

---

## E2 — `docs/DEPENDENCY-POSTURE.md`

**Where:** Tier 3 → "LLM API providers — Cognition layer", appended under the existing **Gap** / **Status** lines.

**Insert:**

> **External-signal note (2026-07-21).** Market commentary around the Kimi K3 release argues the baseline consumer/enterprise posture is now "hold at least one model plus a backup, and assume no single provider is load-bearing." That reframes the local-inference-backend item below from *strategic hedge* to *baseline table stakes*: a substrate whose cognition layer can be disrupted by one provider's pricing, policy, acquisition, or a distribution restriction is structurally fragile in exactly the way the market is now pricing in. Recommend elevating the local-inference-backend priority accordingly, and treating the local/rallied/cloud multi-source axis (SUBSTRATE-FORM inference-sourcing) as the operational expression of *there is no center*. See `AI-LANDSCAPE-SIGNAL-2026-07.md` §2.

**Optional companion:** add a one-line Review-Cadence trigger — "when an external market signal materially changes a dependency's risk framing (e.g., inference-provider disruption becomes baseline expectation)."

---

## E3 — `docs/design/SUBSTRATE-HARDENING-CEREMONY-2026-07.md`

**Where:** near the framing of "hardening is ongoing state maintenance, not one-time badge."

**Insert:**

> **Threat-environment note (2026-07-21).** External signal (Kimi K3 open-weights release; see `AI-LANDSCAPE-SIGNAL-2026-07.md` §3) indicates offensive capability is commoditizing: capable, lower-guardrail open models usable for cloning, exploit assistance, and attack tooling at low cost through H2 2026. This does not change the hardening model — it confirms its premise. Two implications for cadence: (1) the attacker's access to a strong model is now as cheap as the defender's, so the interval between adversarial hardening passes should be treated as a live parameter, not a formality; (2) SECURITY-SIGNAL-CHANNEL timeliness matters more as the population of capable adversaries grows. Consistent with *detectability over invulnerability* — the substrate does not bet on preventing a well-resourced attacker, it bets on making the residual surface visibly measurable.

---

## E4 — `docs/design/SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md`  ⚠ decision, not a paste

**Where:** as a new canonical scenario under the coordination scopes, cross-referenced from `DEPENDENT-SOVEREIGNTY-2026-07.md`.

**The observation:** the "family safe-word against voice/likeness clones" that the outside world reaches for is the low-tech shadow of a Genesis-rooted challenge between kin — a shared secret a clone cannot hold because it lacks the *key*, not because it sounds wrong. The dementia-wire-fraud case ("grandpa, it's me, wire the money") maps onto DEPENDENT-SOVEREIGNTY's already-named elderly-cognitive-decline persona plus kinship safety-check scopes.

**Proposed scenario text (additive):**

> **Verified-kin challenge (anti-impersonation).** A canonical coordination scenario: kin verify a purported contact against likeness/voice impersonation via a Genesis-rooted challenge rather than recognition. The defended case is deepfake-enabled social engineering — a cloned voice or video requesting an urgent, irreversible action (classically, wire fraud targeting a cognitively-vulnerable dependent). The challenge is narrow, mutual, and purposeful: it answers "is this really my kin?" and nothing more. It is **coordination, not oversight** — it must not compose into a kinship-graph, copresence-history, or life-review surface, and it produces no retained record of *who challenged whom* beyond the minimum. Composes with DEPENDENT-SOVEREIGNTY guardian scopes (a guardian may hold challenge capability for a dependent who cannot reliably self-verify).

**Decision flagged (do not paste blindly):** does this warrant a first-class `kinship:challenge:*` primitive, or do the existing `safety_check` + `copresence` scopes + a Genesis-rooted challenge already cover it as a composition? Recommend the latter unless a concrete affordance (offline challenge, dependent-held challenge token, guardian-proxied challenge) needs its own receipt schema. See `AI-LANDSCAPE-SIGNAL-2026-07.md` §4. This is the one signal dimension that may be additive rather than confirmatory — worth a deliberate design pass.

---

## E5 — `docs/design/CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md`

**Where:** among the edge-cases / foreseeable-stressors framing.

**Insert:**

> **External-signal note (2026-07-21).** Market commentary (see `AI-LANDSCAPE-SIGNAL-2026-07.md` §5) anticipates governments (US and China) restricting model distribution and a fragmenting, multi-provider landscape. This is a foreseeable stressor the substrate's posture already answers rather than a new requirement: trust anchored to a vendor or jurisdiction is fragile under distribution restriction; trust anchored to the operator's Genesis root is not. The substrate composes with lawful process while defeating silent/unaccountable control, and it depends on no single model's continued availability (multi-source inference is the operational expression; per-operator trust root the structural one). No structural change implied — noted so the reasoning trail records that the stressor was anticipated.

---

## Summary of nominated actions

| # | Doc | Type | Weight |
|---|-----|------|--------|
| E1 | INFERENCE-ROUTING-DISCIPLINE | Additive note | Confirms + adds data |
| E2 | DEPENDENCY-POSTURE | Additive note + cadence trigger | Raises priority (hedge → baseline) |
| E3 | SUBSTRATE-HARDENING-CEREMONY | Additive note | Confirms premise, sharpens cadence |
| E4 | SOVEREIGN-KINSHIP-PRIMITIVES (+ DEPENDENT-SOVEREIGNTY xref) | New scenario **+ design decision** | Possibly additive primitive |
| E5 | CRYPTO-SOVEREIGNTY-AND-LEGAL-PROCESS | Additive note | Confirms posture |

Plus two candidate CLAUDE.md heuristics (staged, pending N-instances test) — see brief.

---

# Second nomination round — Signal 5 (2026-08-14)

Companion to `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Signal 5". Four blocks, same
discipline: additive, dated, each citing the brief so the trail is walkable.

**Status (2026-08-14):**

| Edit | Target | Status |
|---|---|---|
| E6 | DEPENDENCY-POSTURE (Anthropic-not-signed / vendor-substrate separation) | **NOMINATED, HELD** in the brief since 2026-07-31; never authored as a block here |
| E7 | INFERENCE-ROUTING-DISCIPLINE (guardrails-cut-against-operator) | **NOMINATED, HELD** in the brief since 2026-07-31; never authored as a block here |
| E8 | SUBSTRATE-FORM | **APPLIED (2026-08-14)** — refinement taken, not a third axis: §"Trust-chain reach is stated per layer" added, Form Disclosure completed in reach, one open position and a KEEL Part XV note added |
| E9 | EXTENSION-SURFACE (+ QUARANTINE-PLANE xref) | **APPLIED (2026-08-14)** — 9a as specified (review-surface bullet, evidence-not-authority block, `quarantine:attestation:*` third signature state in QP Step 2, review bullet in QP Step 3). **9b and 9c landed as open positions, not as spec** — both are unresolved design questions and writing them into the audit mechanism would assert a decision nobody has taken |
| E10 | SUBSTRATE-CONFORMANCE-CONTRACT | **APPLIED (2026-08-14)** — §3 note after Claim 4, R7 named as the open one, hard-wrapped to that document's line style |
| E11 | `CLAUDE.md` heuristic promotion | **HELD (operator, 2026-08-14)** — two instances is not the bar; revisit on a third. The instance count is recorded in the brief so the staged heuristic is not mistaken for a forgotten one |
| E12 | This brief's own lens declaration | **APPLIED (2026-08-14) as a split, per operator** — `TRUST-ROOT-LOCUS-LENS-2026-08.md` declares `lens:declared:trust_root_locus`; `ai_landscape` is narrowed rather than widened, with `lens:composed:` and a boundary rule |

E6 and E7 are listed so their held state is visible in one place rather than
only in the brief's closing paragraph. They are unchanged and unauthored; this
round does not advance them.

---

## E8 — `docs/design/SUBSTRATE-FORM-2026-07.md`

**Where:** §"Two axes: sovereignty and compute capacity", appended after the
two-axes statement and before the three inference sources. Plus one sentence in
§"Form Disclosure (invariant)".

**Insert (§Two axes):**

> **External-signal note (2026-08-14).** Form as specified here roots
> sovereignty in one chain — firmware → boot → substrate. Two further roots have
> since become observable in the industry, and the substrate has positions on
> both without expressing either in Form terms. **The capability-admission root**:
> NVIDIA-Verified Agent Skills are signed against an NVIDIA certificate and
> catalogued by NVIDIA, so an operator can neither admit what NVIDIA has not
> blessed nor decline what it has. **The delegation-verification root**: the
> IETF WIMSE cross-organisation delegation problem statement roots verification
> in "another organization's trust anchor," binding the principal as a claim
> carried inside an institutional credential rather than as the root itself.
> Both are the Companion-Form trust posture arriving at layers above the OS.
>
> The consequence for this document is that **sovereignty is turning out to be a
> per-layer property, and Form currently names only the lowest layer.** A
> Sovereign-Form operator admitting only vendor-signed capabilities has an
> operator-rooted boot chain above which the capability layer is vendor-rooted;
> nothing in the substrate today makes that visible, and Form Disclosure is
> silent on Sovereign Form by design. See `AI-LANDSCAPE-SIGNAL-2026-07.md`
> §"Signal 5".

**Insert (§Form Disclosure), appended after the Sovereign-Form silence rule:**

> Silence on Sovereign Form covers the *boot* trust chain, which is what this
> document's Form definition names. It does not cover roots above it. If the
> per-layer question in §"Two axes" resolves toward a layered statement, the
> Disclosure invariant extends with it — a substrate whose boot chain is
> operator-rooted and whose capability admission is vendor-rooted is
> Form-honest only if it says so.

**Decision — RESOLVED 2026-08-14 (operator): refine, do not add an axis.** Applied as written below plus three things the block did not anticipate: a sibling `### Cognitive capacity is sourced separately` heading, because inserting a subsection mid-section orphaned the compute material under the new one; a per-layer canonical-position table naming where each root is already specified; and an open position on *detecting* divergence, since the Disclosure amendment creates an obligation the substrate has no derived state to satisfy. The original question is retained below as authored.

**Decision as flagged (do not paste blindly):** is the per-layer root a *third
axis* alongside sovereignty and compute capacity, a *refinement of the first*
(Form reach stated per layer rather than as one chain), or a matter for
`EXTENSION-SURFACE` alone with Form left as-is? Recommend the second — a Form
that names one root while three exist is under-specified rather than wrong, and
refinement costs less than a new axis. This is the one place in this round that
touches a Layer A invariant's surface (Form Disclosure), so it wants a
deliberate pass rather than an append.

---

## E9 — `docs/design/EXTENSION-SURFACE-2026-07.md` (+ `QUARANTINE-PLANE-2026-07.md` xref) ⚠ three parts; 9b and 9c are decisions

### 9a — third-party attestation as evidence, not authority

**Where:** §"Delegation semantics" → "Operator review surface", appended to the
reviewed-items list; cross-referenced from `QUARANTINE-PLANE` §"The admission
ceremony" Step 2/Step 3.

**Insert:**

> **External-signal note (2026-08-14).** The distribution model already states
> that registries are advisory only and that the substrate trusts the individual
> extension signature and author, not the index. NVIDIA-Verified Agent Skills is
> the first concrete artifact that tests what "advisory" means mechanically:
> each skill ships a detached signature over the whole directory, verifiable
> against a vendor root, plus a *skill card* — a machine-readable trust record
> naming ownership, licence, dependencies, known limitations, risks and
> mitigations, loaded by the consuming agent so that no manual per-install audit
> is required.
>
> Under the ceremony as written, such an artifact is **unsigned**: QUARANTINE-PLANE
> Step 2 verifies signatures "against operator-trusted signers (Genesis-derivable)",
> and a vendor root is not Genesis-derivable. The check is binary, and a
> verifiable signature by a non-Genesis party has no third state — it is
> discarded rather than recorded. That is a loss of evidence, not a defence.
>
> The shape that keeps the discipline: a third-party attestation is **admitted
> as evidence and never as authority**. It appears in the operator review
> surface alongside the author key and prior-delegation history; it is
> chain-anchored so that a later compromise of the attesting party is traceable
> to everything it vouched for; and it is structurally incapable of advancing an
> admission by itself. Concretely, a `quarantine:attestation:<surface>:<hash>`
> receipt carrying attesting-party identity, signature verification result, the
> attestation's own claims, and an explicit `authority: none` marker — reviewed
> by the operator, never consumed by the gate.

**Composition constraint to state with it:** a third-party attestation must not
become a precedent source. `QUARANTINE-PLANE` §Open positions carries
"precedent-based auto-admission scope" (admitting from signer X after operator
has admitted from X before), and *act on precedent, escalate on novelty*
requires that precedent be built from **operator signatures**. Precedent built
from a vendor's signatures is the vendor's trust root wearing the operator's
clothes — the exact substitution `draft-reece-wimse-cross-org-delegation` §7
names as the high-value attack target.

### 9b — declared purpose vs requested scope: an advisory pass ⚠ decision

**Where:** §"Capability declaration language" → "Audit mechanism", appended
after the five structural checks.

**Insert (if the decision below goes that way):**

> **External-signal note (2026-08-14).** NVIDIA's pre-publication scanner checks,
> among conventional software risk, "mismatches between a skill's declared
> purpose, requested access, and bundled behavior." The audit above is
> deliberately structural — WASM imports versus manifest — and catches a
> declaration that lies about *what the code imports*. It cannot catch a
> declaration that is structurally honest and semantically false: a capability
> whose `justification` string describes one purpose while the requested scope
> serves another. The substrate already collects the raw material — every
> capability carries an operator-readable justification — and **nothing reads
> them**. A pre-admission pass comparing justification text against requested
> scope is cheap, is natural officer work, and composes with the semantic-sanity
> step QUARANTINE-PLANE Step 2 already names.

**Decision flagged (do not paste blindly):** the audit mechanism's stated virtue
is that it is *structural, not policy-based* — extensions physically cannot
import undeclared host functions, so the check cannot be argued with. A
semantic comparison is policy-based and fallible, and wiring it into admission
would convert a structural gate into a judged one. Recommend: **advisory input
to the operator ceremony, never a gate** — it produces a finding the operator
reads, at Info severity per the coordination discipline, and an admission is
never blocked by it. If that constraint cannot be held, do not build it. Note
also QUARANTINE-PLANE §Open positions "verification cost bounds": semantic
analysis is the expensive class, and a justification-versus-scope pass is an
inference call per capability per admission.

### 9c — instruction-shaped artifacts carrying authority ⚠ open, no paste proposed

**The gap.** The industry's capability unit at the layer NVIDIA is signing is an
*instruction bundle*, not a binary. QUARANTINE-PLANE's six admission surfaces do
have a home for it — "canonical spec artifacts" explicitly covers prompts,
model dossiers and policy modules arriving as artifacts — but that surface's
verification schema is *schema conformance to a declared trait interface and
cross-reference validation against the canonical corpus*, which assumes a Layer
B data record. An instruction bundle that carries authority is neither a data
record nor a binary: there are no imports to diff against a manifest, and
conformance to a schema says nothing about what the instructions ask the
cognition layer to do.

Per `HARNESS-SEAM` §2.2, skill definitions are **outer content**. The substrate
has an admission ceremony for inner-shaped artifacts and crossing-observability
for outer configuration, and no ceremony for outer instruction artifacts that
carry authority. `FOOTPRINT-AUDIT-2026-04` logged the same hole from the other
direction under LLM03 / ASI04 — "no signature verification on skill packages,
no SBOM" — which is now a dated gap with an external instantiation rather than
an internal note.

**Naming note, so a later reader is not confused.** `zp-skills` is scheduled for
deletion in the W5 work (`HARNESS-SEAM` §6.1.1; `LEGACY-ACCOUNTING` §3.3.1 — a
bidirectional-substring matcher with exactly one consumer, agent-framework
residue). That deletion is right and unaffected by any of the above. It happens
to free the name at the moment the industry fixes its meaning: if an
admitted-instruction-artifact primitive is later specified, it is **not** a
reversal of the deletion and should not inherit the name.

**No edit proposed.** Recorded as an open position for `EXTENSION-SURFACE` and
`QUARANTINE-PLANE` rather than an insert, because the answer is a design pass,
not a note.

---

## E10 — `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`

**Where:** §3, "The four claims", appended after the four claim/falsifier
statements.

**Insert:**

> **External falsifier vocabulary (2026-08-14).** `draft-reece-wimse-cross-org-delegation`
> (IETF individual Internet-Draft, -00 published 22 June 2026; **not** a
> working-group product and carrying no standards standing) enumerates nine
> requirements for cross-organisational agent delegation and explicitly declines
> to specify a solution. Four of them are this contract's discipline written by
> someone with no knowledge of ZeroPoint, which makes them worth more than an
> internally-authored falsifier:
>
> - **R1** — a relying party can verify *from the conveyed authority alone* that
>   no hop exceeds its predecessor. Mechanism here: `DelegationChain::verify()`
>   walks parent-link, depth increment, depth ceiling, grantor-equals-parent's-grantee,
>   `parent.capability.contains(child.capability)`, and lease non-escalation.
>   ZP passes on its face. One subtlety worth carrying rather than glossing: ZP
>   verifies with the **whole chain in hand**, where R1 asks what a relying party
>   can verify **from the credential it was handed**. Same property, different
>   possession assumption — and the difference is exactly what an offline
>   third-party verifier would hit first.
> - **R3** — an authorization decision without a synchronous call to the
>   originating organization. ZP is structurally stronger: there is no
>   originating organization.
> - **R7** — revocation whose authenticity is verifiable offline and **whose
>   staleness is bounded**, so a relying party can fail safe. Revocation here is
>   chain-anchored and offline-verifiable; *bounded staleness under partition* is
>   not specified anywhere the corpus currently reaches. **Treat R7 as the open
>   one** — it is the cheapest genuine gap this signal produced.
> - **R8** — each participant's record resistant to undetectable alteration, and
>   the records composing into an end-to-end account of an action's provenance.
>   This is Claim 2, whose status is "mechanism exists; not yet load-tested
>   against adversarial peers." R8 supplies the load test a vocabulary that did
>   not originate here.
>
> **Where it diverges, and why that matters more than the agreement.** R2 roots
> verification in another organization's trust anchor; the principal is bound but
> not sovereign. The draft's §7 names substitution of a relying party's trust
> root as the attack a solution must prevent — while rooting every chain in an
> institution. That is the Sovereign/Companion axis of `SUBSTRATE-FORM`, arriving
> at the delegation layer. Recording the convergence without recording the
> divergence would be the misreading; the mechanisms are converging and the root
> question is untouched. See `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Signal 5".

---

## E11 — `CLAUDE.md` — promotion of a staged heuristic ⚠ threshold call, not a paste

**The candidate,** staged in the brief since 2026-07-21 and never promoted:

> *"A shared secret a clone cannot hold is the consumer name for a key."* When
> the outside world reaches for a low-tech trust patch — family safe-words,
> callback verification, code phrases — it is groping toward what the substrate
> provides structurally: a Genesis-rooted challenge. Read those patches as unmet
> demand the substrate already satisfies, and name the scenario explicitly.
> Connects to *identity is a key, not a location*, `SOVEREIGN-KINSHIP-PRIMITIVES`,
> `DEPENDENT-SOVEREIGNTY`.

**Second instance (2026-08-14).** A 500-character consumer short (Nate B Jones,
`bC2VZlkvWXQ`, transcript read in full) whose entire content is one piece of
advice: agree a family password, "if you use that word, it's really you," so a
cloned voice making a ransom demand fails a check it cannot guess. Independent
source, independent audience — consumer rather than founder — and the same
shape as the instance that motivated E4.

**The call:** the corpus requires N distinct instances before canonization per
*verify before commit*, and does not fix N. Two independent instances from
unrelated sources is the usual bar elsewhere in `CLAUDE.md`. Recommend promoting
to a workflow heuristic with both instances cited. If the standing bar is three,
this stages one instance short and the entry should say so rather than sit
silently — a staged heuristic with no instance count is indistinguishable from a
forgotten one.

---

## Summary of nominated actions — round two

| # | Doc | Type | Weight |
|---|-----|------|--------|
| E8 | SUBSTRATE-FORM | **Applied** — refinement of the first axis | Completed a Layer A invariant's reach |
| E9a | EXTENSION-SURFACE (+ QUARANTINE-PLANE xref) | **Applied** | Closed an evidence loss |
| E9b | EXTENSION-SURFACE audit mechanism | **Applied as an open position** | Structural vs judged admission, unresolved |
| E9c | EXTENSION-SURFACE / QUARANTINE-PLANE | **Applied as open positions in both** | Design pass still owed |
| E10 | SUBSTRATE-CONFORMANCE-CONTRACT | **Applied** | External falsifiers; R7 named as open |
| E11 | `CLAUDE.md` | **Held** — instance count recorded | Revisit on a third instance |
| E12 | AI-LANDSCAPE-SIGNAL lens declaration | **Applied as a split** | New lens takes the subject the old one read wrongly |

Everything above is additive or a flagged decision. Nothing in this round amends
KEEL, changes a claim's substance, or adopts a dependency.

---

## E12 — `docs/design/AI-LANDSCAPE-SIGNAL-2026-07.md` §"Formal lens declaration" ⚠ amends a lens declaration, not prose

**Surfaced during the authoring of round two, not by the sweep.** Recorded
because the alternative is that it is noticed again in three runs' time.

**The observation.** The `ai_landscape` lens's `keyword_composition` was written
in 2026-07 around inference economics, model tiers, provider disruption and
identity attack surface. Signal 5 is about **delegation attenuation, capability
admission and trust roots**, and not one of those words is in the composition.
Per `LENS-DISCIPLINE-2026-07`, the composition *is* the attention surface — the
lens is invited when one of its keywords appears in a design conversation, spec
draft or task description. As written, a future conversation about attenuated
tokens, signed capability artifacts or an organisation's trust anchor will not
invite this lens, and the silence will be indistinguishable from the pressure
having abated.

**Proposed additions to `keyword_composition`:** delegation, attenuation,
narrowing, trust root, trust anchor, capability admission, signed artifact,
attestation, relying party, revocation, offline verification, standards venue,
Internet-Draft.

**Proposed additions to `dimensions`:** delegation-vocabulary convergence,
capability-artifact signing, trust-root locus (institutional vs operator),
offline verification and revocation staleness.

**Why this is not a paste.** Changing the composition changes what invokes the
lens, and once anchored the declaration is a `lens:declared:ai_landscape`
receipt — an amendment is a new declaration superseding the old, not an edit.
Two questions for the review: (1) does the trust-root material belong in this
lens at all, or does it want its own declaration with a `lens:composed:` edge to
`ai_landscape` — the composition is drifting toward two subjects, market
dynamics and standards convergence, which is the shape that usually argues for a
split; (2) if it stays, the transformation question should widen with it — the
current one asks about disruption, cost inversion and attack surface, and asks
nothing about whether a substrate direction remains *differentiated* as the
industry builds the same mechanism on a different root, which is precisely what
Signal 5 tested.

Recommend the split, on the grounds that the second question is a different
question and answering it through a market-dynamics lens is what nearly caused
this round to be recorded as convergence.
